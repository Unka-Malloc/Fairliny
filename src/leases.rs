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
//! One lease may carry credentials for several vendors, so resolution is
//! scoped: the host authorizes named *credential scopes* — sets of
//! `credentialId`s from the handoff — and the router registers each
//! authenticated route's bound surface against the scope it declared. A
//! surface then resolves only the credentials its host authorized for it;
//! a scope holding none fails closed rather than borrowing another
//! vendor's key.
//!
//! Secret bytes never leave this module except through a4mp's redacted
//! `Secret`/`Credential` boundary types. Errors carry the lease contract's
//! refusal codes and nothing else — no credential ids, no byte counts,
//! no material.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use a4mp::{AuthKind, Credential, CredentialResolver, CredentialScope, Secret, ServiceTarget};
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

impl ProviderCredential {
    /// The leased kind an a4mp auth mechanism resolves, or `None` when
    /// the mechanism cannot come from a provider-credential handoff —
    /// cloud identity and external-client access belong to the host's
    /// own custody. This is the same table [`Leases`] resolves with, so
    /// a route can refuse an unanswerable mechanism at declaration
    /// rather than at first forward.
    pub fn for_auth(auth: &AuthKind) -> Option<Self> {
        match auth {
            AuthKind::ApiKey => Some(Self::ApiKey),
            AuthKind::Bearer => Some(Self::Bearer),
            _ => None,
        }
    }
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

/// A credential-scope name never exceeds the handoff contract's own
/// schema bound — a longer name is a document bug, not a scope.
const MAX_SCOPE_NAME_BYTES: usize = credential_lease::handoff::MAX_HANDOFF_SCHEMA_BYTES;

/// Take a scope-table lock whether or not it is poisoned. Every guarded
/// table changes only through single, non-panicking operations, so a
/// poisoned lock's contents are still consistent.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
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
    /// The slot unscoped resolutions answer from: host-bound adapters and
    /// programmatic routes that declare no credential scope.
    slot: CredentialSlot<ProviderCredential>,
    /// The document the current lease was built from, kept so credential
    /// scopes declared after the install still materialize their slots —
    /// and zeroized on drop like the buffer it was read into.
    handoff: Mutex<Option<Zeroizing<Vec<u8>>>>,
    /// The epoch source every installed slot shares.
    epoch_source: Mutex<Option<Arc<dyn LeaseEpochSource>>>,
    /// Scope name → the credential ids the host authorized for it.
    authorizations: Mutex<BTreeMap<String, BTreeSet<String>>>,
    /// Scope name → the slot holding only that scope's credentials.
    scopes: Mutex<BTreeMap<String, CredentialSlot<ProviderCredential>>>,
    /// Bound surface key → scope name. The router registers each scoped
    /// route's surface at declaration; resolution dispatches on it.
    target_scopes: Mutex<BTreeMap<String, String>>,
}

impl Leases {
    /// A custody port with no lease installed — resolutions fail closed
    /// with `credential_lease_unavailable` until a handoff lands.
    pub fn disconnected() -> Self {
        Self {
            slot: CredentialSlot::disconnected(),
            handoff: Mutex::new(None),
            epoch_source: Mutex::new(None),
            authorizations: Mutex::new(BTreeMap::new()),
            scopes: Mutex::new(BTreeMap::new()),
            target_scopes: Mutex::new(BTreeMap::new()),
        }
    }

    /// A port over an already-built slot — the shape a host uses when it
    /// owns the lease lifecycle itself. No handoff document is retained,
    /// so credential scopes cannot materialize and scoped surfaces fail
    /// closed; hosts wanting scopes install a document instead.
    pub fn over_slot(slot: CredentialSlot<ProviderCredential>) -> Self {
        Self {
            slot,
            ..Self::disconnected()
        }
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
    /// Authorized credential scopes re-materialize from the new document
    /// against the same epoch source.
    pub fn install_handoff(
        &self,
        document: &[u8],
        epoch_source: Arc<dyn LeaseEpochSource>,
    ) -> Result<()> {
        let handoff = CredentialHandoff::<ProviderCredential>::from_json(document)
            .map_err(|error| Error::Credential(error.to_string()))?;
        self.slot
            .install_handoff(handoff, epoch_source.clone())
            .map_err(|error| Error::Credential(error.to_string()))?;
        *lock(&self.handoff) = Some(Zeroizing::new(document.to_vec()));
        *lock(&self.epoch_source) = Some(epoch_source);
        self.materialize_scopes()
    }

    /// Install a handoff with the epoch source pinned to the document's own
    /// epoch — the degenerate mode for callers without a live epoch channel.
    /// Resolution works; revocation has no way to arrive.
    pub fn install_handoff_self_epoch(&self, document: &[u8]) -> Result<()> {
        let handoff = CredentialHandoff::<ProviderCredential>::from_json(document)
            .map_err(|error| Error::Credential(error.to_string()))?;
        let epoch = handoff.epoch().to_owned();
        let epoch_source: Arc<dyn LeaseEpochSource> = Arc::new(StaticEpoch(epoch));
        self.slot
            .install_handoff(handoff, epoch_source.clone())
            .map_err(|error| Error::Credential(error.to_string()))?;
        *lock(&self.handoff) = Some(Zeroizing::new(document.to_vec()));
        *lock(&self.epoch_source) = Some(epoch_source);
        self.materialize_scopes()
    }

    /// Authorize `scope` to resolve the named credential ids — the
    /// host-authorized binding a route's `credentialScope` declares.
    ///
    /// Ids follow the handoff contract: canonical UUIDs, non-empty. An
    /// id the handoff does not carry leaves the scope without that
    /// credential — resolution fails closed rather than borrowing
    /// another scope's. Authorizing is idempotent and may run before or
    /// after [`Self::install_handoff`]; the scope's slot materializes
    /// whenever both sides have arrived.
    pub fn authorize_scope(
        &self,
        scope: &str,
        credential_ids: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<()> {
        let invalid = || Error::Credential("credential_scope_invalid".to_owned());
        if scope.is_empty() || scope.len() > MAX_SCOPE_NAME_BYTES {
            return Err(invalid());
        }
        let ids: BTreeSet<String> = credential_ids
            .into_iter()
            .map(|id| {
                let id = id.as_ref();
                uuid::Uuid::parse_str(id)
                    .ok()
                    .filter(|parsed| parsed.to_string() == id)
                    .map(|_| id.to_owned())
                    .ok_or_else(invalid)
            })
            .collect::<Result<_>>()?;
        if ids.is_empty() {
            return Err(invalid());
        }
        lock(&self.authorizations).insert(scope.to_owned(), ids.clone());
        self.materialize_scope(scope, &ids)
    }

    /// The `credentialScopes` member of a routes document:
    /// `{"credentialScopes": {"<scope>": ["<credentialId>", ...]}}` —
    /// the host-authorized table every route's `credentialScope` names.
    /// An absent member authorizes nothing; a malformed one refuses.
    pub fn authorize_scopes(&self, document: &serde_json::Value) -> Result<()> {
        let Some(scopes) = document.get("credentialScopes") else {
            return Ok(());
        };
        let invalid = || Error::Credential("credential_scope_invalid".to_owned());
        for (scope, ids) in scopes.as_object().ok_or_else(invalid)? {
            let ids = ids.as_array().ok_or_else(invalid)?;
            self.authorize_scope(scope, ids.iter().map(|id| id.as_str().unwrap_or("")))?;
        }
        Ok(())
    }

    /// Bind `target` to the credential scope its route declared. The
    /// router registers each scoped route's bound surface at
    /// declaration, so resolution dispatches on the surface a request
    /// actually forwards to — never on the auth mechanism alone. The
    /// scope must be one the host authorized — a misspelled or
    /// unauthorized name refuses at declaration, not at first request —
    /// and a surface already bound to a different scope refuses rather
    /// than silently re-pointing a vendor's credential.
    pub fn register_target_scope(&self, target: &ServiceTarget, scope: &str) -> Result<()> {
        if !lock(&self.authorizations).contains_key(scope) {
            return Err(Error::Credential(
                "credential_scope_unauthorized".to_owned(),
            ));
        }
        match lock(&self.target_scopes).entry(target_key(target)) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(scope.to_owned());
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(entry) => {
                if entry.get() == scope {
                    Ok(())
                } else {
                    Err(Error::Credential("credential_scope_conflict".to_owned()))
                }
            }
        }
    }

    /// The slot behind the port, for hosts that drive the lease lifecycle
    /// (hot-apply a new handoff, clear on lock).
    pub fn slot(&self) -> &CredentialSlot<ProviderCredential> {
        &self.slot
    }

    /// (Re)build every authorized scope's slot from the retained
    /// document — a no-op before the first install.
    fn materialize_scopes(&self) -> Result<()> {
        for (scope, ids) in lock(&self.authorizations).iter() {
            self.materialize_scope(scope, ids)?;
        }
        Ok(())
    }

    /// Rebuild one scope's slot from the retained document: the
    /// authorized ids and nothing else. A scope the document carries no
    /// credential for installs an empty lease — every resolution fails
    /// closed instead of falling back to the unscoped slot. No-op until
    /// a handoff and its epoch source have both been installed.
    fn materialize_scope(&self, scope: &str, ids: &BTreeSet<String>) -> Result<()> {
        let (Some(document), Some(epoch_source)) = (
            lock(&self.handoff).clone(),
            lock(&self.epoch_source).clone(),
        ) else {
            return Ok(());
        };
        let mut handoff = CredentialHandoff::<ProviderCredential>::from_json(&document)
            .map_err(|error| Error::Credential(error.to_string()))?;
        handoff.retain_credential_ids(ids);
        let slot = CredentialSlot::disconnected();
        slot.install_handoff(handoff, epoch_source)
            .map_err(|error| Error::Credential(error.to_string()))?;
        lock(&self.scopes).insert(scope.to_owned(), slot);
        Ok(())
    }
}

impl fmt::Debug for Leases {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Leases")
            .field("slot", &self.slot)
            .field("scope_count", &lock(&self.scopes).len())
            .finish()
    }
}

/// The key a bound surface registers and resolves under: provider id,
/// protocol family and base URL — the surface's identity, not the
/// outward model name. Two outward names bound to the same surface share
/// its credential scope.
fn target_key(target: &ServiceTarget) -> String {
    format!(
        "{}\u{1f}{:?}\u{1f}{}\u{1f}{:?}",
        target.provider.as_str(),
        target.protocol,
        target.base_url,
        target.region
    )
}

#[async_trait::async_trait]
impl CredentialResolver for Leases {
    /// Resolve request-time material for the adapter's scope. Resolution
    /// goes through the slot on every call: the lease's own expiry and the
    /// custody epoch are consulted each time, so a revoked lease fails the
    /// very next forward rather than finishing one more request.
    ///
    /// A surface the router registered against a credential scope
    /// resolves only from that scope's slot — the credentials the host
    /// authorized for it — and fails closed when the scope holds none.
    /// Unregistered surfaces answer from the unscoped slot.
    async fn resolve(
        &self,
        scope: CredentialScope<'_>,
    ) -> std::result::Result<Credential, a4mp::Error> {
        let invalid = |error: &dyn fmt::Display| a4mp::Error::Credential(error.to_string());
        if matches!(scope.auth, AuthKind::None) {
            return Ok(Credential::None);
        }
        let Some(kind) = ProviderCredential::for_auth(scope.auth) else {
            return Err(a4mp::Error::Credential(
                "credential_lease_kind_not_leased".to_owned(),
            ));
        };
        let scoped = lock(&self.target_scopes)
            .get(&target_key(scope.target))
            .cloned();
        let secret = match scoped {
            Some(name) => match lock(&self.scopes).get(&name) {
                Some(slot) => slot.resolve(kind).map_err(|e| invalid(&e))?,
                None => {
                    return Err(a4mp::Error::Credential(
                        "credential_lease_unavailable".to_owned(),
                    ));
                }
            },
            None => self.slot.resolve(kind).map_err(|e| invalid(&e))?,
        };
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
