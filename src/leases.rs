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
//! vendor's key. Routers sharing this port publish their bindings under
//! their own [`ScopeOwner`] — one router's whole-table publish retires
//! only its own slice, never another router's live bindings — and a
//! dropped router's slice retires with it, tombstoned so the adapters
//! it detached fail closed while a replacement can bind the freed
//! surfaces.
//!
//! Secret bytes never leave this module except through a4mp's redacted
//! `Secret`/`Credential` boundary types. Errors carry the lease contract's
//! refusal codes and nothing else — no credential ids, no byte counts,
//! no material.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::fmt;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// An epoch source that stops answering at a fixed instant. Every scoped
/// slot is minted against the install's own expiry, so a scope authorized
/// late materializes a lease that still dies at the deadline the install
/// fixed — past it the epoch read reports no active epoch and the lease
/// contract's revocation check fails the very next resolution, whatever
/// duration the minted document happened to carry.
struct DeadlineEpoch {
    inner: Arc<dyn LeaseEpochSource>,
    deadline: Instant,
}

impl LeaseEpochSource for DeadlineEpoch {
    fn active_epoch(&self) -> anyhow::Result<Option<String>> {
        if Instant::now() >= self.deadline {
            return Ok(None);
        }
        self.inner.active_epoch()
    }
}

/// One scope-binding owner's identity. Every router publishing surface
/// bindings holds a fresh owner, so its whole-table publish replaces only
/// its own slice — a second router over the same lease port can never
/// erase the bindings a still-live route elsewhere needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScopeOwner(u64);

impl ScopeOwner {
    /// A process-unique owner identity.
    pub fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

impl Default for ScopeOwner {
    fn default() -> Self {
        Self::new()
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

/// One live surface binding: the scope it resolves under and the
/// generation identifying *this* binding. A republish that keeps the
/// surface, mechanism and scope carries the generation forward; a
/// retirement, a mechanism swap or a scope change mints a fresh one,
/// so a resolver pinned to the earlier binding can never ride its
/// replacement — a retained adapter bound under the old mechanism fails
/// closed even while the surface's new mechanism resolves.
#[derive(Clone)]
struct LiveBinding {
    scope: String,
    generation: u64,
}

/// The identity a surface binding registers and resolves under: the
/// bound surface's key plus the leased mechanism the route declared.
/// Mechanisms are tracked separately — replacing an `api-key` route
/// with a `bearer` one on the same surface and scope is a different
/// binding, so the retired mechanism's generation dies with the last
/// route that used it while the surface's other mechanism binds fresh.
type BindingKey = (String, ProviderCredential);

/// The composite key a bound surface-and-mechanism pair registers
/// under. Two outward names bound to the same surface and mechanism
/// share its credential scope; a different mechanism on the same
/// surface is its own binding.
fn binding_key(target: &ServiceTarget, kind: ProviderCredential) -> BindingKey {
    (target_key(target), kind)
}

/// The gateway's custody port: the process-local lease behind every
/// credential resolution.
pub struct Leases {
    /// The whole installed-lease state, replaced under one lock on every
    /// install, replacement or clear.
    state: Mutex<LeaseState>,
    /// Scope name → the credential ids the host authorized for it.
    authorizations: Mutex<BTreeMap<String, BTreeSet<String>>>,
    /// Binding owner → (bound surface+mechanism key → the live binding,
    /// or a retired marker). Each router publishes its scoped routes'
    /// surfaces under its own [`ScopeOwner`], so its publish retires its
    /// slice and nothing else; a surface an owner's republish drops keeps
    /// a tombstone, so an adapter detached by that republish fails closed
    /// rather than slipping back to the unscoped slot. Resolution
    /// dispatches on the live bindings every owner's table names.
    target_scopes: Mutex<BTreeMap<ScopeOwner, BTreeMap<BindingKey, Option<LiveBinding>>>>,
    /// The binding-generation counter: every newly established surface
    /// binding takes the next value, so a resolver can pin the exact
    /// binding it was minted for — a retired-and-republished binding is
    /// never the one it was, even when surface and scope read the same.
    generations: AtomicU64,
}

impl Leases {
    /// A custody port with no lease installed — resolutions fail closed
    /// with `credential_lease_unavailable` until a handoff lands.
    pub fn disconnected() -> Self {
        Self {
            state: Mutex::new(LeaseState::disconnected()),
            authorizations: Mutex::new(BTreeMap::new()),
            target_scopes: Mutex::new(BTreeMap::new()),
            generations: AtomicU64::new(1),
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
        state.expires_at = Instant::now()
            .checked_add(lease.lease_duration())
            .unwrap_or_else(Instant::now);
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
                scoped_slot(document, ids, expires_at, epoch_source.clone())?,
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
        let ids = validate_scope(scope, credential_ids)?;
        self.commit_authorizations([(scope.to_owned(), ids)])
    }

    /// Publish a fully validated authorization table in one commit: every
    /// scope's slot materializes under the single state lock first — a
    /// minting failure anywhere aborts before anything lands — then the
    /// recorded ids and their slots publish together, so a rejected table
    /// can never leave a prefix of its entries changing which credentials
    /// live routes resolve.
    fn commit_authorizations(
        &self,
        table: impl IntoIterator<Item = (String, BTreeSet<String>)>,
    ) -> Result<()> {
        let table: Vec<_> = table.into_iter().collect();
        let mut state = lock(&self.state);
        let mut slots = BTreeMap::new();
        if let (Some(document), Some(epoch_source)) = (&state.document, &state.epoch_source) {
            for (scope, ids) in &table {
                slots.insert(
                    scope.clone(),
                    scoped_slot(document, ids, state.expires_at, epoch_source.clone())?,
                );
            }
        }
        let mut authorizations = lock(&self.authorizations);
        for (scope, ids) in table {
            authorizations.insert(scope.clone(), ids);
            if let Some(slot) = slots.remove(&scope) {
                state.scoped.insert(scope, slot);
            }
        }
        Ok(())
    }

    /// The `credentialScopes` member of a routes document:
    /// `{"credentialScopes": {"<scope>": ["<credentialId>", ...]}}` —
    /// the host-authorized table every route's `credentialScope` names.
    /// An absent member authorizes nothing; a malformed one refuses —
    /// and a document that is not a JSON object is malformed, never an
    /// empty table. The whole table validates and stages before any of
    /// it publishes, so a malformed later entry cannot leave earlier
    /// entries already changing which credentials live routes resolve.
    pub fn authorize_scopes(&self, document: &serde_json::Value) -> Result<()> {
        if !document.is_object() {
            return Err(Error::Credential("credential_scope_invalid".to_owned()));
        }
        let Some(scopes) = document.get("credentialScopes") else {
            return Ok(());
        };
        let invalid = || Error::Credential("credential_scope_invalid".to_owned());
        let mut table = Vec::new();
        for (scope, ids) in scopes.as_object().ok_or_else(invalid)? {
            let ids = ids.as_array().ok_or_else(invalid)?;
            table.push((
                scope.clone(),
                validate_scope(scope, ids.iter().map(|id| id.as_str().unwrap_or("")))?,
            ));
        }
        self.commit_authorizations(table)
    }

    /// Whether `scope` is one the host authorized — the read-only check
    /// a router runs before committing a scoped route, so a misspelled
    /// or unauthorized name refuses at declaration, not at first
    /// request.
    pub fn scope_authorized(&self, scope: &str) -> bool {
        lock(&self.authorizations).contains_key(scope)
    }

    /// Publish the whole bound-surface table for `owner` in one swap:
    /// every live scoped route's surface and leased mechanism → the
    /// scope it declared. The table is validated before it lands — a
    /// scope the host did not authorize, or two bindings pointing at
    /// different scopes for one key, refuses the whole publish — and
    /// the swap covers only the owner's own slice, so a route that
    /// stopped declaring a scope retires its old binding while a
    /// binding another router still needs is never touched. A retired
    /// binding keeps a tombstone rather than disappearing: an adapter
    /// detached by the republish — already bound against the retired
    /// surface — fails closed on its next resolve instead of falling
    /// back to the unscoped slot, until a live binding reclaims the
    /// surface. A surface and mechanism another owner already bound to
    /// a different scope refuses the whole publish too: resolution
    /// could never tell the two declarations apart, so the conflict
    /// dies at declaration.
    pub fn replace_target_scopes<'a>(
        &self,
        owner: ScopeOwner,
        bindings: impl IntoIterator<Item = (&'a ServiceTarget, &'a str, ProviderCredential)>,
    ) -> Result<()> {
        let mut table = BTreeMap::new();
        {
            let authorizations = lock(&self.authorizations);
            for (target, scope, kind) in bindings {
                if !authorizations.contains_key(scope) {
                    return Err(Error::Credential(
                        "credential_scope_unauthorized".to_owned(),
                    ));
                }
                match table.entry(binding_key(target, kind)) {
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
        let mut live = lock(&self.target_scopes);
        for (key, scope) in &table {
            if live.iter().any(|(other, existing)| {
                *other != owner
                    && existing
                        .get(key)
                        .and_then(Option::as_ref)
                        .is_some_and(|bound| bound.scope != *scope)
            }) {
                return Err(Error::Credential("credential_scope_conflict".to_owned()));
            }
        }
        // The swap covers the owner's whole slice: a binding absent from
        // the new table keeps a tombstone, a binding kept on the same
        // scope keeps its generation — the publish changed nothing it
        // stands for — and a new, tombstoned, rescoped or re-mechanismed
        // binding mints a fresh generation, so a resolver pinned to the
        // earlier binding fails the next resolution even when the same
        // surface-and-scope pair came back under another mechanism.
        let slice = live.entry(owner).or_default();
        let previous = std::mem::take(slice);
        for (key, scope) in table {
            let generation = match previous.get(&key) {
                Some(Some(old)) if old.scope == scope => old.generation,
                _ => self.generations.fetch_add(1, Ordering::Relaxed),
            };
            slice.insert(key, Some(LiveBinding { scope, generation }));
        }
        for key in previous.into_keys() {
            slice.entry(key).or_insert(None);
        }
        Ok(())
    }
}

/// The pure half of authorization — name and id validation with no
/// state touched — so [`Leases::authorize_scopes`] can stage a whole
/// table before publishing any of it.
fn validate_scope(
    scope: &str,
    credential_ids: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<BTreeSet<String>> {
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
    Ok(ids)
}

/// Build one scope's slot from a retained document: its authorized ids
/// and nothing else, under the install's epoch source wrapped in
/// [`DeadlineEpoch`] so the minted lease dies at `deadline` — the
/// install's own expiry — however much duration the document itself
/// still claims. Any positive remaining duration mints: the document's
/// own duration satisfies the contract's whole-second minimum and the
/// deadline wrapper holds the absolute end, so a scope authorized with
/// less than a second left still resolves until the install expires.
/// Only a deadline already reached leaves the slot disconnected.
fn scoped_slot(
    document: &[u8],
    ids: &BTreeSet<String>,
    deadline: Instant,
    epoch_source: Arc<dyn LeaseEpochSource>,
) -> Result<CredentialSlot<ProviderCredential>> {
    let slot = CredentialSlot::disconnected();
    let remaining = deadline.saturating_duration_since(Instant::now());
    if !remaining.is_zero() {
        let mut handoff = CredentialHandoff::<ProviderCredential>::from_json(document)
            .map_err(|error| Error::Credential(error.to_string()))?;
        handoff.retain_credential_ids(ids);
        let epoch_source: Arc<dyn LeaseEpochSource> = Arc::new(DeadlineEpoch {
            inner: epoch_source,
            deadline,
        });
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
pub(crate) fn target_key(target: &ServiceTarget) -> String {
    format!(
        "{}\u{1f}{:?}\u{1f}{}\u{1f}{:?}",
        target.provider.as_str(),
        target.protocol,
        target.base_url,
        target.region
    )
}

/// A credential resolver pinned to the exact binding an adapter's
/// surface was declared under — its publishing owner's table entry, at
/// one generation, for one surface and one leased mechanism.
///
/// The router binds a scoped route's adapter with this resolver instead
/// of the bare port: the adapter resolves only while the binding it was
/// declared under is still live — same owner, same surface, same scope,
/// same generation. A sibling owner publishing the same surface-to-scope
/// binding is a different binding, and so is the same surface and scope
/// republished after a retirement: an adapter whose own binding retired
/// or rebound fails closed even while another binding keeps resolving,
/// so a detached adapter can never ride a binding it was not declared
/// under.
pub struct ScopedResolver {
    leases: Arc<Leases>,
    owner: ScopeOwner,
    scope: String,
    target: String,
    kind: Option<ProviderCredential>,
    generation: u64,
}

impl ScopedResolver {
    /// Pin resolutions to the binding `owner` holds for `target` under
    /// `scope` — capturing its generation now, so a retirement followed
    /// by an identical republish is still a different binding and
    /// answers nothing here. `auth` pins the declared mechanism: a
    /// resolution naming another surface in the same owner's slice or
    /// another mechanism is outside the declared binding and refuses.
    /// When no live binding covers `target` at construction, the pin
    /// takes the never-minted generation `0` — every credential-bearing
    /// resolution then fails `credential_scope_retired`.
    pub fn new(
        leases: Arc<Leases>,
        owner: ScopeOwner,
        scope: impl Into<String>,
        target: &ServiceTarget,
        auth: &AuthKind,
    ) -> Self {
        let target = target_key(target);
        let kind = ProviderCredential::for_auth(auth);
        let generation = kind
            .and_then(|kind| leases.binding_generation(owner, &(target.clone(), kind)))
            .unwrap_or(0);
        Self {
            leases,
            owner,
            scope: scope.into(),
            target,
            kind,
            generation,
        }
    }
}

#[async_trait::async_trait]
impl CredentialResolver for ScopedResolver {
    async fn resolve(
        &self,
        scope: CredentialScope<'_>,
    ) -> std::result::Result<Credential, a4mp::Error> {
        self.leases.resolve_pinned(
            self.owner,
            &self.scope,
            &self.target,
            self.kind,
            self.generation,
            scope,
        )
    }
}

impl Leases {
    /// The live scope one surface's bindings name across every owner's
    /// table for the requested mechanism: `None` when no live binding
    /// claims it, `Some(scope)` when exactly one does. A tombstoned
    /// binding with no live claim refuses `credential_scope_retired`
    /// rather than falling back to the unscoped slot, and two owners
    /// naming different scopes refuse `credential_scope_conflict` —
    /// resolution could never tell them apart.
    fn bound_scope(
        &self,
        target: &ServiceTarget,
        kind: ProviderCredential,
    ) -> std::result::Result<Option<String>, a4mp::Error> {
        let tables = lock(&self.target_scopes);
        let key = binding_key(target, kind);
        let mut found = BTreeSet::new();
        let mut retired = false;
        for table in tables.values() {
            match table.get(&key) {
                Some(Some(binding)) => {
                    found.insert(binding.scope.clone());
                }
                Some(None) => retired = true,
                None => {}
            }
        }
        match found.len() {
            0 if retired => Err(a4mp::Error::Credential(
                "credential_scope_retired".to_owned(),
            )),
            0 => Ok(None),
            1 => Ok(found.pop_first()),
            _ => Err(a4mp::Error::Credential(
                "credential_scope_conflict".to_owned(),
            )),
        }
    }

    /// The generation of `owner`'s live binding for `key`, or `None`
    /// when no live binding covers it — what a [`ScopedResolver`] pins,
    /// so a retire-and-republish of the same surface stays refused.
    fn binding_generation(&self, owner: ScopeOwner, key: &BindingKey) -> Option<u64> {
        lock(&self.target_scopes)
            .get(&owner)?
            .get(key)?
            .as_ref()
            .map(|binding| binding.generation)
    }

    /// The pinned half of resolution: the resolution must name the exact
    /// binding the adapter was declared under — the resolver's own
    /// owner's slice, the pinned surface, the pinned mechanism and the
    /// pinned generation. A resolution for any other surface or
    /// mechanism never reaches the table — it is outside the declared
    /// binding whether or not another entry would answer it. A live
    /// binding naming a different scope conflicts; one re-established
    /// after a retirement is a different generation and stays refused
    /// even when the same surface and scope came back. An
    /// unauthenticated request never consults the table — it carries no
    /// credential to guard.
    fn resolve_pinned(
        &self,
        owner: ScopeOwner,
        declared: &str,
        target: &str,
        kind: Option<ProviderCredential>,
        generation: u64,
        scope: CredentialScope<'_>,
    ) -> std::result::Result<Credential, a4mp::Error> {
        if matches!(scope.auth, AuthKind::None) {
            return Ok(Credential::None);
        }
        if target_key(scope.target) != target || ProviderCredential::for_auth(scope.auth) != kind {
            return Err(a4mp::Error::Credential(
                "credential_scope_mismatch".to_owned(),
            ));
        }
        let bound = kind.and_then(|kind| {
            let tables = lock(&self.target_scopes);
            tables
                .get(&owner)
                .and_then(|slice| slice.get(&(target.to_owned(), kind)))
                .cloned()
                .flatten()
        });
        match bound {
            Some(binding) if binding.scope != declared => Err(a4mp::Error::Credential(
                "credential_scope_conflict".to_owned(),
            )),
            Some(binding) if binding.generation != generation => Err(a4mp::Error::Credential(
                "credential_scope_retired".to_owned(),
            )),
            Some(binding) => self.resolve_kind(Some(binding.scope), &scope),
            None => Err(a4mp::Error::Credential(
                "credential_scope_retired".to_owned(),
            )),
        }
    }

    /// The shared tail of every resolution: the leased-kind check, the
    /// install-wide deadline and the slot the binding dispatch picked.
    /// One absolute expiry covers every slot the install produced: past
    /// the install's deadline the answer is `credential_lease_expired`,
    /// so a scope materialized late can never outlive the handoff it
    /// came from.
    fn resolve_kind(
        &self,
        scoped: Option<String>,
        scope: &CredentialScope<'_>,
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
        let state = lock(&self.state);
        if state.epoch_source.is_some() && Instant::now() >= state.expires_at {
            return Err(a4mp::Error::Credential(
                "credential_lease_expired".to_owned(),
            ));
        }
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

#[async_trait::async_trait]
impl CredentialResolver for Leases {
    /// Resolve request-time material for the adapter's scope. Resolution
    /// goes through the slot on every call: the lease's own expiry and the
    /// custody epoch are consulted each time, so a revoked lease fails the
    /// very next forward rather than finishing one more request.
    ///
    /// A surface the router registered against a credential scope
    /// resolves only from that scope's slot — the credentials the host
    /// authorized for it — and fails closed when the scope holds none,
    /// when two owners bound the surface to different scopes, or when
    /// every binding for it retired: an adapter detached by a republish
    /// never slips back to the unscoped slot its scope once guarded it
    /// from. Never-bound surfaces answer from the unscoped slot. One absolute
    /// expiry covers every slot the install produced: past the install's
    /// deadline the answer is `credential_lease_expired`, so a scope
    /// materialized late can never outlive the handoff it came from. An
    /// `AuthKind::None` request carries no credential to guard: it
    /// answers `Credential::None` before the binding table is consulted,
    /// so a tombstoned surface never fails an unauthenticated forward.
    async fn resolve(
        &self,
        scope: CredentialScope<'_>,
    ) -> std::result::Result<Credential, a4mp::Error> {
        if matches!(scope.auth, AuthKind::None) {
            return Ok(Credential::None);
        }
        let scoped = match ProviderCredential::for_auth(scope.auth) {
            Some(kind) => self.bound_scope(scope.target, kind)?,
            // A mechanism custody cannot answer never touches the table —
            // `resolve_kind` names the refusal.
            None => None,
        };
        self.resolve_kind(scoped, &scope)
    }
}
