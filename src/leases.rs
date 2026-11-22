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

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::fmt;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use a4mp::{AuthKind, Credential, CredentialResolver, CredentialScope, Secret, ServiceTarget};
use credential_lease::{
    CredentialHandoff, CredentialKind, CredentialLease, CredentialSlot, LeaseEpochSource,
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

/// Everything one installed handoff produced — the lease state that
/// installs, replacements and lock-down swap as a single consistent
/// piece, so a resolution never observes a new document beside an old
/// epoch source or yesterday's scoped slots.
struct LeaseState {
    /// The document the installed leases were built from, kept so
    /// credential scopes authorized after the install still materialize
    /// their slots — and zeroized on drop like the buffer it was read
    /// into.
    document: Option<Zeroizing<Vec<u8>>>,
    /// The epoch source every installed slot shares.
    epoch_source: Option<Arc<dyn LeaseEpochSource>>,
    /// When the installed lease stops answering, fixed at install time.
    /// A scope materialized later mints only the remaining duration —
    /// authorizing can never restart the expiry the install set.
    expires_at: Instant,
    /// The slot unscoped resolutions answer from: host-bound adapters
    /// and programmatic routes that declare no credential scope.
    unscoped: CredentialSlot<ProviderCredential>,
    /// Scope name → the slot holding only that scope's credentials.
    scoped: BTreeMap<String, CredentialSlot<ProviderCredential>>,
}

impl LeaseState {
    /// An empty state: no document, no epoch source and every resolution
    /// failing closed.
    fn disconnected() -> Self {
        Self {
            document: None,
            epoch_source: None,
            expires_at: Instant::now(),
            unscoped: CredentialSlot::disconnected(),
            scoped: BTreeMap::new(),
        }
    }
}

/// The gateway's custody port: the process-local lease behind every
/// credential resolution.
pub struct Leases {
    /// The whole installed-lease state, replaced under one lock on every
    /// install, replacement or clear.
    state: Mutex<LeaseState>,
    /// Scope name → the credential ids the host authorized for it.
    authorizations: Mutex<BTreeMap<String, BTreeSet<String>>>,
    /// Bound surface key → scope name. The router publishes each scoped
    /// route's surface at declaration; resolution dispatches on it.
    target_scopes: Mutex<BTreeMap<String, String>>,
}

impl Leases {
    /// A custody port with no lease installed — resolutions fail closed
    /// with `credential_lease_unavailable` until a handoff lands.
    pub fn disconnected() -> Self {
        Self {
            state: Mutex::new(LeaseState::disconnected()),
            authorizations: Mutex::new(BTreeMap::new()),
            target_scopes: Mutex::new(BTreeMap::new()),
        }
    }

    /// A port over an already-minted lease — the shape a host uses when
    /// it owns the lease lifecycle itself. No handoff document is
    /// retained, so credential scopes cannot materialize and scoped
    /// surfaces fail closed; hosts wanting scopes install a document
    /// instead.
    pub fn over_lease(lease: CredentialLease<ProviderCredential>) -> Self {
        let port = Self::disconnected();
        port.install_lease(lease);
        port
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

    /// Install a serialized handoff document, publishing the whole lease
    /// state in one swap: the rebuilt unscoped slot, the retained
    /// document, its epoch source and every authorized scope's
    /// re-materialized slot. The state lock is held across the build so
    /// a scope authorized mid-install materializes against the new
    /// document rather than dying with the old state; a build that
    /// fails still leaves the running lease untouched and a concurrent
    /// resolution can never observe the new document beside the old
    /// epoch source.
    pub fn install_handoff(
        &self,
        document: &[u8],
        epoch_source: Arc<dyn LeaseEpochSource>,
    ) -> Result<()> {
        let mut state = lock(&self.state);
        *state = self.build_state(document, epoch_source)?;
        Ok(())
    }

    /// Install a handoff with the epoch source pinned to the document's own
    /// epoch — the degenerate mode for callers without a live epoch channel.
    /// Resolution works; revocation has no way to arrive.
    pub fn install_handoff_self_epoch(&self, document: &[u8]) -> Result<()> {
        let handoff = CredentialHandoff::<ProviderCredential>::from_json(document)
            .map_err(|error| Error::Credential(error.to_string()))?;
        let epoch_source: Arc<dyn LeaseEpochSource> =
            Arc::new(StaticEpoch(handoff.epoch().to_owned()));
        self.install_handoff(document, epoch_source)
    }

    /// Install an already-minted lease — the host-driven replacement for
    /// the handoff path. The swap covers the whole state: the retained
    /// document and every scoped slot die with the previous lease, so a
    /// scoped surface fails closed rather than resolving credentials the
    /// new lease never granted. No document is retained, so scopes
    /// cannot re-materialize until the next document install.
    pub fn install_lease(&self, lease: CredentialLease<ProviderCredential>) {
        let mut state = LeaseState::disconnected();
        state.unscoped = CredentialSlot::new(lease);
        *lock(&self.state) = state;
    }

    /// Drop the installed lease state — the lock-down answer for a host
    /// revoking in place. One swap retires the unscoped slot, every
    /// scoped slot, the retained document and the epoch source: the very
    /// next resolution on any surface fails closed. Authorizations and
    /// surface bindings stay — they are declarations, not credentials.
    pub fn clear(&self) {
        *lock(&self.state) = LeaseState::disconnected();
    }

    /// Build the complete [`LeaseState`] one document installs —
    /// unscoped slot, retained document, epoch source and every
    /// authorized scope's slot — without touching the published state,
    /// so a failure anywhere leaves the running lease untouched. Runs
    /// with the state lock held: a scope materializing against the old
    /// state can never be discarded by a swap it raced.
    fn build_state(
        &self,
        document: &[u8],
        epoch_source: Arc<dyn LeaseEpochSource>,
    ) -> Result<LeaseState> {
        let handoff = CredentialHandoff::<ProviderCredential>::from_json(document)
            .map_err(|error| Error::Credential(error.to_string()))?;
        let duration = handoff.lease_duration();
        let unscoped = CredentialSlot::disconnected();
        unscoped
            .install_handoff(handoff, epoch_source.clone())
            .map_err(|error| Error::Credential(error.to_string()))?;
        let expires_at = Instant::now()
            .checked_add(duration)
            .ok_or_else(|| Error::Credential("credential_lease_expiry_invalid".to_owned()))?;
        let mut scoped = BTreeMap::new();
        for (scope, ids) in lock(&self.authorizations).iter() {
            scoped.insert(
                scope.clone(),
                scoped_slot(document, ids, duration, epoch_source.clone())?,
            );
        }
        Ok(LeaseState {
            document: Some(Zeroizing::new(document.to_vec())),
            epoch_source: Some(epoch_source),
            expires_at,
            unscoped,
            scoped,
        })
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

    /// Whether `scope` is one the host authorized — the read-only check
    /// a router runs before committing a scoped route, so a misspelled
    /// or unauthorized name refuses at declaration, not at first
    /// request.
    pub fn scope_authorized(&self, scope: &str) -> bool {
        lock(&self.authorizations).contains_key(scope)
    }

    /// Publish the whole bound-surface table in one swap: every live
    /// scoped route's surface → the scope it declared. The table is
    /// validated before it lands — a scope the host did not authorize,
    /// or two surfaces pointing at different scopes for one key, refuses
    /// the whole publish — and the swap is total, so a route that
    /// stopped declaring a scope releases its old binding instead of
    /// leaving it behind for the next surface that reuses the target.
    pub fn replace_target_scopes<'a>(
        &self,
        bindings: impl IntoIterator<Item = (&'a ServiceTarget, &'a str)>,
    ) -> Result<()> {
        let mut table = BTreeMap::new();
        {
            let authorizations = lock(&self.authorizations);
            for (target, scope) in bindings {
                if !authorizations.contains_key(scope) {
                    return Err(Error::Credential(
                        "credential_scope_unauthorized".to_owned(),
                    ));
                }
                match table.entry(target_key(target)) {
                    Entry::Vacant(entry) => {
                        entry.insert(scope.to_owned());
                    }
                    Entry::Occupied(entry) => {
                        if *entry.get() != scope {
                            return Err(Error::Credential("credential_scope_conflict".to_owned()));
                        }
                    }
                }
            }
        }
        *lock(&self.target_scopes) = table;
        Ok(())
    }

    /// Rebuild one scope's slot inside the published state, minting only
    /// the duration the installed lease has left — the expiry fixed at
    /// install is never extended, so re-authorizing cannot restore
    /// access past it. A scope the document carries no credential for
    /// installs an empty lease — every resolution fails closed instead
    /// of falling back to the unscoped slot. No-op until a handoff and
    /// its epoch source have both been installed.
    fn materialize_scope(&self, scope: &str, ids: &BTreeSet<String>) -> Result<()> {
        let mut state = lock(&self.state);
        let (Some(document), Some(epoch_source)) =
            (state.document.clone(), state.epoch_source.clone())
        else {
            return Ok(());
        };
        let remaining = state.expires_at.saturating_duration_since(Instant::now());
        state.scoped.insert(
            scope.to_owned(),
            scoped_slot(&document, ids, remaining, epoch_source)?,
        );
        Ok(())
    }
}

/// Build one scope's slot from a retained document: its authorized ids
/// and nothing else, under the same epoch source, living at most
/// `duration` — the install's remaining lifetime when a scope
/// materializes late. Below the contract's one-second minimum no lease
/// can mint: the install's own expiry has effectively arrived, so the
/// scope stays disconnected and resolves unavailable.
fn scoped_slot(
    document: &[u8],
    ids: &BTreeSet<String>,
    duration: std::time::Duration,
    epoch_source: Arc<dyn LeaseEpochSource>,
) -> Result<CredentialSlot<ProviderCredential>> {
    let slot = CredentialSlot::disconnected();
    if duration.as_secs() >= 1 {
        let mut handoff = CredentialHandoff::<ProviderCredential>::from_json(document)
            .map_err(|error| Error::Credential(error.to_string()))?;
        handoff.retain_credential_ids(ids);
        slot.install_handoff(handoff, epoch_source)
            .map_err(|error| Error::Credential(error.to_string()))?;
    }
    Ok(slot)
}

impl fmt::Debug for Leases {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = lock(&self.state);
        formatter
            .debug_struct("Leases")
            .field("unscoped", &state.unscoped)
            .field("scope_count", &state.scoped.len())
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
        let state = lock(&self.state);
        let secret = match scoped {
            Some(name) => match state.scoped.get(&name) {
                Some(slot) => slot.resolve(kind).map_err(|e| invalid(&e))?,
                None => {
                    return Err(a4mp::Error::Credential(
                        "credential_lease_unavailable".to_owned(),
                    ));
                }
            },
            None => state.unscoped.resolve(kind).map_err(|e| invalid(&e))?,
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
