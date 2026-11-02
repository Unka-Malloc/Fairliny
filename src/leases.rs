//! The credential custody port: leases in, a4mp `CredentialResolver` out.
//!
//! Custody — the system keyring, persistence, owner authorization — belongs
//! to the host. Fairliny accepts a `CredentialHandoff` over a process-local
//! channel (an inherited file descriptor is the designed-for carrier),
//! keeps it in a process-bound [`CredentialSlot`], and answers a4mp's
//! `CredentialResolver` from it: every resolution consults the custody
//! epoch, so an owner-initiated rotation fails the very next credential
//! read rather than expiring in a cache window.
//!
//! Secret bytes never leave this module except through a4mp's redacted
//! `Secret`/`Credential` boundary types. Errors carry the lease contract's
//! refusal codes and nothing else — no credential ids, no byte counts,
//! no material.

use std::fmt;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use a4mp::{AuthKind, Credential, CredentialResolver, CredentialScope, Secret};
use credential_lease::{
    CredentialHandoff, CredentialKind, CredentialSlot, LeaseEpochSource,
    handoff::MAX_HANDOFF_DOC_BYTES,
};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// The credential kinds custody may lease to this gateway.
///
/// One kind per a4mp mechanism a provider handoff can carry — a static
/// API key or bearer material (OAuth-issued or provider-granted). Cloud
/// identity and external-client access stay with the host's own custody;
/// they are not leased kinds here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProviderCredential {
    /// Static provider API key.
    ApiKey,
    /// Bearer material — OAuth-issued or provider-granted.
    Bearer,
}

impl CredentialKind for ProviderCredential {
    /// The schema every provider-credential handoff pins: documents minted
    /// for another family can never parse as this one.
    const HANDOFF_SCHEMA: &'static str = "fairliny.provider-credentials.handoff.v1";

    fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api-key",
            Self::Bearer => "bearer",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "api-key" => Some(Self::ApiKey),
            "bearer" => Some(Self::Bearer),
            _ => None,
        }
    }
}

/// The epoch source a custody owner drives through a file.
///
/// The file holds the active epoch; the owner rotates it to revoke every
/// outstanding lease — the next resolution re-reads the file, so there is
/// no cached authorization window. A missing or empty file means no epoch
/// is active and every lease fails closed.
#[derive(Clone, Debug)]
pub struct FileEpochSource {
    path: PathBuf,
}

impl FileEpochSource {
    /// Watch the epoch document at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl LeaseEpochSource for FileEpochSource {
    fn active_epoch(&self) -> anyhow::Result<Option<String>> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => {
                let epoch = text.trim();
                Ok((!epoch.is_empty()).then(|| epoch.to_owned()))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

/// An epoch source pinned to one epoch forever — the degenerate custody
/// answer used when no live revocation channel exists. Resolution works;
/// revocation cannot arrive. Hosts with a real channel use
/// `install_handoff` with their own source instead.
struct StaticEpoch(String);

impl LeaseEpochSource for StaticEpoch {
    fn active_epoch(&self) -> anyhow::Result<Option<String>> {
        Ok(Some(self.0.clone()))
    }
}

/// The gateway's custody port: the process-local lease behind every
/// credential resolution.
pub struct Leases {
    slot: CredentialSlot<ProviderCredential>,
}

impl Leases {
    /// A custody port with no lease installed — resolutions fail closed
    /// with `credential_lease_unavailable` until a handoff lands.
    pub fn disconnected() -> Self {
        Self {
            slot: CredentialSlot::disconnected(),
        }
    }

    /// A port over an already-built slot — the shape a host uses when it
    /// owns the lease lifecycle itself.
    pub fn over_slot(slot: CredentialSlot<ProviderCredential>) -> Self {
        Self { slot }
    }

    /// Read a handoff document from a process-local channel, bounded by the
    /// contract's maximum so an oversized input is refused before parsing.
    /// The document is secret-bearing — it embeds every credential in the
    /// clear — so the buffer zeroizes on drop like `HandoffDocument`.
    pub fn read_handoff(channel: impl Read) -> Result<Zeroizing<Vec<u8>>> {
        let mut document = Zeroizing::new(Vec::new());
        channel
            .take(MAX_HANDOFF_DOC_BYTES as u64 + 1)
            .read_to_end(&mut document)
            .map_err(|error| Error::Credential(format!("handoff channel: {error}")))?;
        if document.len() > MAX_HANDOFF_DOC_BYTES {
            return Err(Error::Credential(
                "credential_lease_handoff_invalid".to_owned(),
            ));
        }
        Ok(document)
    }

    /// Install a serialized handoff document, rebuilding the lease under
    /// the supplied epoch source in one atomic swap. Parsing fails closed:
    /// a truncated or tampered document never becomes a partial lease.
    pub fn install_handoff(
        &self,
        document: &[u8],
        epoch_source: Arc<dyn LeaseEpochSource>,
    ) -> Result<()> {
        let handoff = CredentialHandoff::<ProviderCredential>::from_json(document)
            .map_err(|error| Error::Credential(error.to_string()))?;
        self.slot
            .install_handoff(handoff, epoch_source)
            .map_err(|error| Error::Credential(error.to_string()))
    }

    /// Install a handoff with the epoch source pinned to the document's own
    /// epoch — the degenerate mode for callers without a live epoch channel.
    /// Resolution works; revocation has no way to arrive.
    pub fn install_handoff_self_epoch(&self, document: &[u8]) -> Result<()> {
        let handoff = CredentialHandoff::<ProviderCredential>::from_json(document)
            .map_err(|error| Error::Credential(error.to_string()))?;
        let epoch = handoff.epoch().to_owned();
        self.slot
            .install_handoff(handoff, Arc::new(StaticEpoch(epoch)))
            .map_err(|error| Error::Credential(error.to_string()))
    }

    /// The slot behind the port, for hosts that drive the lease lifecycle
    /// (hot-apply a new handoff, clear on lock).
    pub fn slot(&self) -> &CredentialSlot<ProviderCredential> {
        &self.slot
    }
}

impl fmt::Debug for Leases {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Leases")
            .field("slot", &self.slot)
            .finish()
    }
}

/// The leased kind an a4mp auth mechanism resolves, or `None` when the
/// mechanism cannot come from a provider-credential handoff — cloud
/// identity and external-client access belong to the host's own custody.
fn leased_kind(auth: &AuthKind) -> Option<ProviderCredential> {
    match auth {
        AuthKind::ApiKey => Some(ProviderCredential::ApiKey),
        AuthKind::Bearer => Some(ProviderCredential::Bearer),
        _ => None,
    }
}

#[async_trait::async_trait]
impl CredentialResolver for Leases {
    /// Resolve request-time material for the adapter's scope. Resolution
    /// goes through the slot on every call: the lease's own expiry and the
    /// custody epoch are consulted each time, so a revoked lease fails the
    /// very next forward rather than finishing one more request.
    async fn resolve(
        &self,
        scope: CredentialScope<'_>,
    ) -> std::result::Result<Credential, a4mp::Error> {
        let invalid = |error: &dyn fmt::Display| a4mp::Error::Credential(error.to_string());
        if matches!(scope.auth, AuthKind::None) {
            return Ok(Credential::None);
        }
        let Some(kind) = leased_kind(scope.auth) else {
            return Err(a4mp::Error::Credential(
                "credential_lease_kind_not_leased".to_owned(),
            ));
        };
        let secret = self.slot.resolve(kind).map_err(|e| invalid(&e))?;
        let utf8 = secret.expose_utf8().map_err(|e| invalid(&e))?;
        let token = Secret::new(utf8);
        Ok(match kind {
            ProviderCredential::ApiKey => Credential::ApiKey(token),
            ProviderCredential::Bearer => Credential::Bearer {
                token,
                expires_at: None,
            },
        })
    }
}
