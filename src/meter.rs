//! Metera composed in: the request-admission counter and the
//! response-settlement hook, running beside the forwarded request.
//!
//! Two hooks, two facts, never inside the forward path:
//!
//! - **Request admission** counts what the gateway accepted for
//!   forwarding — bounded per-day agent×model counters in the shape of
//!   `agent-statistics`' `GatewayUsageRecorder`, persisted under the state
//!   root. The caller names its own agent identity; the recorder's
//!   hardcoded product map does not apply here.
//! - **Response settlement** maps the response's usage record through
//!   `token-usage-detector`'s `ProviderMapping` and pushes one bound
//!   observation into the base `UsageJournal` through `UsageSourcePort`.
//!   The observation is bound by the host's own `SourceBinding` — the
//!   provider never names a source, epoch or scope.
//!
//! Fault isolation is the contract: [`Meter::settle_response`] is `async`
//! and the service spawns it after the response exists, so a metering
//! failure is counted in `failures` and never blocks or fails a forwarded
//! request. Settlement also only runs after a response was produced —
//! a failed forward has nothing to settle.

use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agent_statistics::gateway::UsageDocument;
use agent_statistics::journal::{
    MAX_FACT_PAGE, MeteringFact, SettlementEligibility, SourceAdmission,
};
use agent_statistics::source_host::UsageSourceHost;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use token_usage_detector::SourceBinding;
use token_usage_detector::names::is_namespaced;
use token_usage_detector::provider::ProviderMapping;
use token_usage_detector::usage::{Quality, UsageObservation, UsageOperation, wire};

use crate::{Error, Result};

/// The aggregate scope every settled forward lands in — one authorized
/// range the binding issues at open, because per-request scope grants
/// cannot enumerate traffic not yet seen.
const FORWARDED_SCOPE: &str = "gateway:forwarded";

/// The host-issued source identity the gateway settles under.
const SOURCE_REF: &str = "source:fairliny.gateway#1";

/// The extension id the binding declares — this gateway is the source.
const EXTENSION_ID: &str = "fairliny.gateway";

/// Bounds mirror the recorder's own: same retention, same folding, so the
/// exposition contract holds unchanged.
const COUNTERS_SCHEMA: &str = "fairliny.gateway-usage.v1";
const MAX_COUNTERS_BYTES: usize = 512 * 1024;
const MAX_DAYS: usize = 90;
const MAX_MODELS_PER_DAY: usize = 64;
/// The recorder's own agents map stays bounded by its fixed product set;
/// here the caller names its own agent, so the per-day bound must be
/// explicit — same folding discipline as the models bound.
const MAX_AGENTS_PER_DAY: usize = 64;
const MAX_LABEL_BYTES: usize = 128;
const FOLDED_LABEL: &str = "Other";
const COUNTERS_FILE: &str = "gateway-usage.json";

/// The counters document rewrites whole on every persist, so persistence
/// coalesces: the file catches up after this many admissions, or after
/// this much wall time since the last attempt — whichever comes first.
/// The first admission persists at once so the file materializes early.
const PERSIST_EVERY: u64 = 32;
const PERSIST_INTERVAL: Duration = Duration::from_secs(30);

/// One retained day of request counters, as the exposition document
/// carries it.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UsageDay {
    agents: BTreeMap<String, u64>,
    models: BTreeMap<String, u64>,
}

/// The retained counter document — the `UsageDocument` wire shape with
/// caller-named agent attribution rather than the recorder's fixed map.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Counters {
    schema_version: String,
    days: BTreeMap<String, UsageDay>,
}

impl Default for Counters {
    fn default() -> Self {
        Self {
            schema_version: COUNTERS_SCHEMA.to_owned(),
            days: BTreeMap::new(),
        }
    }
}

/// Bounded per-day agent×model request counters, optionally persisted
/// under the state root — the `GatewayUsageRecorder` shape with the agent
/// attribution a gateway needs (the caller's own name, not a hardcoded
/// product map).
struct Admissions {
    path: Option<PathBuf>,
    counters: Counters,
    /// Admissions applied since the counters document last reached the
    /// file — the coalescing counter behind [`PERSIST_EVERY`].
    pending: u64,
    /// When the file was last written, or `None` while the in-memory
    /// state never persisted. A failed write also marks it — retrying on
    /// the next window bounds the cost of a permanently failing target.
    persisted_at: Option<Instant>,
}

impl Admissions {
    /// Open the counters file under `root`; a missing or stale-schema file
    /// starts empty, as the recorder's own open does.
    fn open(path: PathBuf) -> Result<Self> {
        let counters = collection_store::fs::read_private_text_bounded(&path, MAX_COUNTERS_BYTES)
            .map_err(|error| Error::Meter(error.to_string()))?
            .and_then(|text| serde_json::from_str::<Counters>(&text).ok())
            .filter(|document| document.schema_version == COUNTERS_SCHEMA)
            .unwrap_or_default();
        Ok(Self {
            path: Some(path),
            counters,
            pending: 0,
            persisted_at: None,
        })
    }

    /// Counters that never touch a filesystem — the `--no-meter` shape.
    fn in_memory() -> Self {
        Self {
            path: None,
            counters: Counters::default(),
            pending: 0,
            persisted_at: None,
        }
    }

    /// Count one forwarded request under today (UTC). Label bounds mirror
    /// the recorder: agent and model names fold into `Other` past their
    /// per-day bound, days drop oldest past the retention window.
    /// The count lands in memory; the file catches up on the persist
    /// cadence, not per request.
    fn record(&mut self, agent: &str, model: &str) {
        let day = OffsetDateTime::now_utc().date().to_string();
        let usage = self.counters.days.entry(day).or_default();
        bounded_increment(&mut usage.agents, &label(agent), MAX_AGENTS_PER_DAY);
        bounded_increment(&mut usage.models, &label(model), MAX_MODELS_PER_DAY);
        while self.counters.days.len() > MAX_DAYS {
            let Some(oldest) = self.counters.days.keys().next().cloned() else {
                break;
            };
            self.counters.days.remove(&oldest);
        }
        if self.path.is_some() {
            self.pending += 1;
        }
    }

    /// Whether the counters file is due a rewrite: the first admission
    /// persists at once, later ones coalesce by count or by interval.
    fn persist_due(&self) -> bool {
        self.pending > 0
            && (self.persisted_at.is_none()
                || self.pending >= PERSIST_EVERY
                || self
                    .persisted_at
                    .is_some_and(|at| at.elapsed() >= PERSIST_INTERVAL))
    }

    /// Rewrite the counters document if admissions are outstanding — the
    /// shutdown and exposition flush, where the interval does not apply.
    fn persist(&mut self) -> Result<()> {
        self.pending = 0;
        self.persisted_at = Some(Instant::now());
        let Some(path) = &self.path else {
            return Ok(());
        };
        let encoded = serde_json::to_string(&self.counters)
            .map_err(|error| Error::Meter(format!("counters encode: {error}")))?;
        collection_store::fs::atomic_write_private_text_bounded(path, &encoded, MAX_COUNTERS_BYTES)
            .map_err(|error| Error::Meter(format!("counters persist: {error}")))
    }

    /// The counters as the export document — serialized through the pinned
    /// schema so the exposition families never drift from the recorder's.
    fn document(&self) -> Option<UsageDocument> {
        serde_json::to_value(&self.counters)
            .ok()
            .and_then(|value| serde_json::from_value::<UsageDocument>(value).ok())
    }
}

fn increment(values: &mut BTreeMap<String, u64>, key: &str) {
    *values.entry(key.to_owned()).or_default() += 1;
}

/// Count `label` into `values` under the per-day cardinality bound: an
/// unseen label past `max` folds into `Other` rather than growing the
/// map on a caller-controlled name.
fn bounded_increment(values: &mut BTreeMap<String, u64>, label: &str, max: usize) {
    if values.contains_key(label) || values.len() < max {
        increment(values, label);
    } else {
        increment(values, FOLDED_LABEL);
    }
}

/// A label fit for the counter: the recorder's own character and length
/// bounds, with anything else folded into `Other` rather than recorded
/// under a hostile or unbounded name.
fn label(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_LABEL_BYTES
        || !trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
    {
        return FOLDED_LABEL.to_owned();
    }
    trimmed.to_owned()
}

/// The metering middleware: one admission counter plus one settlement
/// hook, both fault-isolated from the forward path.
pub struct Meter {
    admissions: Mutex<Admissions>,
    journal: Option<Arc<Mutex<UsageSourceHost>>>,
    admission: Option<SourceAdmission>,
    sequence: AtomicU64,
    failures: AtomicU64,
}

impl Meter {
    /// Compose the meter over a state root: counters persist to
    /// `gateway-usage.json`; the journal opens in the `agent-usage` ledger
    /// that root holds — one store, additive tables, never a second.
    /// The binding mints a fresh epoch per process boot: a restart is a
    /// new series, exactly the contract's reset semantics.
    pub fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let epoch = format!(
            "boot-{:016x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_millis())
                .unwrap_or_default()
        );
        let binding = gateway_binding(&format!("pid-{}", std::process::id()), &epoch)?;
        Self::compose(state_root, binding)
    }

    /// Compose over an explicit binding — the shape a host uses when it
    /// owns the source identity (instance, generation, epoch, grants).
    pub fn compose(state_root: impl AsRef<Path>, binding: SourceBinding) -> Result<Self> {
        let root = state_root.as_ref();
        let host = UsageSourceHost::open(&json!({"stateRoot": root.to_string_lossy()}))
            .map_err(|error| Error::Meter(error.to_string()))?;
        Self::shared(root, Arc::new(Mutex::new(host)), binding)
    }

    /// Compose over a journal the composition root already owns — the
    /// single-instance shape. One `UsageSourceHost` engine serves every
    /// metering face in the process (the gateway here, agent-side
    /// collection beside it), so the `agent-usage` ledger has exactly
    /// one writer even when the host embeds Metera itself. The binding
    /// still names the gateway's own source identity; admission lands
    /// on the shared host. The counters document remains the gateway's
    /// own file under `state_root`.
    pub fn shared(
        state_root: impl AsRef<Path>,
        host: Arc<Mutex<UsageSourceHost>>,
        binding: SourceBinding,
    ) -> Result<Self> {
        let admissions = Admissions::open(state_root.as_ref().join(COUNTERS_FILE))?;
        let admission = {
            let host = host
                .lock()
                .map_err(|_| Error::Meter("journal lock poisoned".to_owned()))?;
            host.admit_source(binding, SettlementEligibility::SettlementEligible)
        };
        Ok(Self {
            admissions: Mutex::new(admissions),
            journal: Some(host),
            admission: Some(admission),
            sequence: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        })
    }

    /// Counters without a journal — the shape a host uses when Fairliny
    /// runs with no metering state root. Admission still counts and
    /// exports; settlement has nowhere to go and declines quietly.
    pub fn unmetered() -> Self {
        Self {
            admissions: Mutex::new(Admissions::in_memory()),
            journal: None,
            admission: None,
            sequence: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        }
    }

    /// The request-admission hook: count the request the gateway just
    /// accepted for forwarding. Synchronous and infallible — a counter
    /// failure is a persistence bug, never a reason to drop traffic, and
    /// a persistence failure lands in `failures` rather than silently
    /// leaving the file stale.
    pub fn admit_request(&self, agent: &str, model: &str) {
        let Ok(mut admissions) = self.admissions.lock() else {
            self.failures.fetch_add(1, Ordering::SeqCst);
            return;
        };
        admissions.record(agent, model);
        if admissions.persist_due() && admissions.persist().is_err() {
            self.failures.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Persist the counters when admissions are outstanding — the
    /// shutdown and exposition flush, beside the settlement-task drain
    /// in `Service::flush_metering`. A failed write is a metering
    /// failure like any other: counted, never propagated.
    pub fn flush(&self) {
        let Ok(mut admissions) = self.admissions.lock() else {
            self.failures.fetch_add(1, Ordering::SeqCst);
            return;
        };
        if admissions.pending > 0 && admissions.persist().is_err() {
            self.failures.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// The response-settlement hook: map the response's usage record and
    /// push one bound observation into the journal.
    ///
    /// Async by construction — the service spawns it after the response
    /// exists and never awaits it inside the reply path. Every fallible
    /// step lands in `failures`: an unusable mapping, a refused binding,
    /// a locked journal, a store error — none of them is the caller's
    /// problem.
    pub async fn settle_response(&self, provider: &str, usage: Option<&a4mp::Usage>) {
        let (Some(usage), Some(admission), Some(journal)) = (usage, &self.admission, &self.journal)
        else {
            // Absent stays absent: no usage object means no observation,
            // and an uninstalled journal declines rather than fabricates.
            return;
        };
        let settled = (|| -> Result<()> {
            let namespace = format!("{}.usage", provider.to_ascii_lowercase());
            let mapping = ProviderMapping::new(namespace.clone(), Quality::Reported)
                .map_err(|failure| Error::Meter(failure.code.to_string()))?;
            let record = usage_record(usage);
            let mut mapped = mapping
                .normalize(&record)
                .map_err(|failure| Error::Meter(failure.code.to_string()))?
                .unwrap_or_default();
            // Named-but-uncounted settles as Unknown, never absent: the
            // mapping already downgrades the shared counters it knows;
            // provider-native leaves are this layer's to declare under
            // the same contract.
            for metric in uncounted_fields(&record, &mapping, &namespace) {
                if !mapped.unknown.contains(&metric) {
                    mapped.unknown.push(metric);
                }
            }
            let metrics = mapping.metrics(&mapped);
            if metrics.is_empty() {
                return Ok(());
            }
            let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
            let observation = UsageObservation {
                schema: wire::USAGE.to_owned(),
                observation_id: format!("forwarded:{sequence:016x}"),
                revision: 1,
                operation: UsageOperation::Upsert,
                source_epoch: admission.binding().source_epoch.clone(),
                scope_ref: FORWARDED_SCOPE.to_owned(),
                observed_at: OffsetDateTime::now_utc()
                    .format(&Rfc3339)
                    .map_err(|error| Error::Meter(error.to_string()))?,
                interval_start: None,
                metrics,
                cost: None,
            };
            let bound = admission
                .binding()
                .bind_observation(observation, None)
                .map_err(|failure| Error::Meter(failure.code.to_string()))?;
            let mut host = journal
                .lock()
                .map_err(|_| Error::Meter("journal lock poisoned".to_owned()))?;
            host.admit_observation(admission, &bound)
                .map_err(|error| Error::Meter(error.to_string()))?;
            Ok(())
        })();
        if settled.is_err() {
            self.failures.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Metering failures counted since open — observability for the
    /// isolation contract, not an error surface.
    pub fn failure_count(&self) -> u64 {
        self.failures.load(Ordering::SeqCst)
    }

    /// Count one metering failure observed outside the meter itself —
    /// a settlement task the composition could not even spawn. Same
    /// isolation contract: counted, never propagated.
    pub(crate) fn count_failure(&self) {
        self.failures.fetch_add(1, Ordering::SeqCst);
    }

    /// The facts the journal currently retains, paged through the same
    /// read port the exposition uses — for hosts and tests projecting
    /// the settled record.
    pub fn facts(&self) -> Vec<MeteringFact> {
        let mut facts = Vec::new();
        let mut cursor = None;
        self.with_journal(|host| {
            while let Ok(page) = host.read(cursor.as_deref(), MAX_FACT_PAGE) {
                cursor = page.next_cursor;
                facts.extend(page.facts);
                if cursor.is_none() {
                    break;
                }
            }
        });
        facts
    }

    /// The retained counters as the export document, when there is a
    /// journal to project them beside.
    pub fn usage_document(&self) -> Option<UsageDocument> {
        self.admissions.lock().ok()?.document()
    }

    /// Borrow the journal for a read — `None` when unmetered or locked.
    pub fn with_journal<R>(&self, read: impl FnOnce(&UsageSourceHost) -> R) -> Option<R> {
        let host = self.journal.as_ref()?.lock().ok()?;
        Some(read(&host))
    }
}

/// The gateway's own source binding: identity the host issues, never
/// anything a payload could assert. `generation` pins the binding shape;
/// `source_epoch` distinguishes series across restarts.
fn gateway_binding(instance: &str, source_epoch: &str) -> Result<SourceBinding> {
    SourceBinding::new(
        SOURCE_REF,
        EXTENSION_ID,
        instance,
        1,
        source_epoch,
        [FORWARDED_SCOPE],
    )
    .map_err(|failure| Error::Meter(format!("source binding: {}", failure.code)))
}

/// The canonical-counter spelling one usage projection carries: the
/// caller-facing reply spells them camelCase; the settlement record
/// feeds the detector's snake_case aliases.
#[derive(Clone, Copy)]
pub(crate) enum UsageKeyStyle {
    /// `inputTokens` / `outputTokens` — the `chat.complete` reply shape.
    Reply,
    /// `input_tokens` / `output_tokens` — the settlement record shape.
    Record,
}

/// The usage object one projection emits, in either spelling: the
/// canonical counters plus every provider-native field, verbatim — one
/// guard shared by both projections: an extension must not overwrite a
/// canonical counter the provider actually counted, while an extension
/// naming an absent counter still forwards under its own spelling —
/// nothing is overwritten either way.
pub(crate) fn usage_object(usage: &a4mp::Usage, style: UsageKeyStyle) -> Map<String, Value> {
    let (input_key, output_key) = match style {
        UsageKeyStyle::Reply => ("inputTokens", "outputTokens"),
        UsageKeyStyle::Record => ("input_tokens", "output_tokens"),
    };
    let mut object = Map::new();
    if let Some(input) = usage.input_tokens {
        object.insert(input_key.to_owned(), input.into());
    }
    if let Some(output) = usage.output_tokens {
        object.insert(output_key.to_owned(), output.into());
    }
    for (key, value) in &usage.extensions {
        let overwrites = (usage.input_tokens.is_some() && key == input_key)
            || (usage.output_tokens.is_some() && key == output_key);
        if overwrites {
            continue;
        }
        object.insert(key.clone(), value.clone());
    }
    object
}

/// The provider usage record the settlement hook feeds the mapping — the
/// mapping owns alias folding, so nothing is flattened here first.
fn usage_record(usage: &a4mp::Usage) -> Value {
    json!({ "usage": usage_object(usage, UsageKeyStyle::Record) })
}

/// The `namespace/path` metrics for the record's named-but-uncounted
/// leaves that the mapping does not already downgrade. A leaf that is a
/// shared counter's known spelling lands in the mapping's own Unknown
/// readings; every other leaf the record named without a count — a
/// provider-native field carrying `null`, text, or a container with no
/// count below it — is declared here under the same contract: named,
/// unanswered, never zero.
fn uncounted_fields(record: &Value, mapping: &ProviderMapping, namespace: &str) -> Vec<String> {
    let mut paths = Vec::new();
    if let Some(usage) = record.get("usage") {
        collect_uncounted(usage, "", &mut paths);
    }
    let mut metrics = Vec::new();
    for path in paths {
        let metric = format!("{namespace}/{path}");
        // A name that cannot be kept namespaced is dropped rather than
        // renamed — the same rule the mapping applies to counted extras.
        if is_namespaced(&metric) && !mapping_reads_leaf(mapping, &path) {
            metrics.push(metric);
        }
    }
    metrics
}

/// The dotted paths the record named without a count: objects recurse,
/// unsigned integers are counts, and every other leaf is a name alone.
fn collect_uncounted(value: &Value, path: &str, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                let child = match path.is_empty() {
                    true => key.clone(),
                    false => format!("{path}.{key}"),
                };
                collect_uncounted(nested, &child, out);
            }
        }
        Value::Number(number) if number.as_u64().is_some() => {}
        _ => out.push(path.to_owned()),
    }
}

/// Whether the mapping already reads this leaf: it is asked with the
/// leaf named and uncounted — a path the mapping knows projects as its
/// own Unknown reading, so declaring it here would settle the same
/// named field twice. A refusal counts as covered: a leaf the record
/// scan itself refuses is not a field this layer may re-assert.
fn mapping_reads_leaf(mapping: &ProviderMapping, path: &str) -> bool {
    let mut leaf = Value::Null;
    for segment in path.split('.').collect::<Vec<_>>().into_iter().rev() {
        let mut object = Map::new();
        object.insert(segment.to_owned(), leaf);
        leaf = Value::Object(object);
    }
    !matches!(mapping.normalize(&json!({ "usage": leaf })), Ok(None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_stay_bounded_and_hostile_names_fold() {
        assert_eq!(label("kimi-k2"), "kimi-k2");
        assert_eq!(label("  codex  "), "codex");
        assert_eq!(label("bad agent name"), FOLDED_LABEL);
        assert_eq!(label(""), FOLDED_LABEL);
        assert_eq!(label(&"x".repeat(MAX_LABEL_BYTES + 1)), FOLDED_LABEL);
    }

    #[test]
    fn the_usage_record_keeps_provider_native_fields_verbatim() {
        let mut extensions = serde_json::Map::new();
        extensions.insert("cache_read_input_tokens".to_owned(), 7.into());
        let record = usage_record(&a4mp::Usage {
            input_tokens: Some(10),
            output_tokens: Some(5),
            extensions,
        });
        assert_eq!(record["usage"]["input_tokens"], json!(10));
        assert_eq!(record["usage"]["output_tokens"], json!(5));
        assert_eq!(record["usage"]["cache_read_input_tokens"], json!(7));
    }

    #[test]
    fn counters_fold_and_persist_like_the_recorder() {
        let root =
            std::env::temp_dir().join(format!("fairliny-admissions-{}", uuid::Uuid::new_v4()));
        collection_store::fs::ensure_private_dir(&root).unwrap();
        let path = root.join(COUNTERS_FILE);
        {
            let mut admissions = Admissions::open(path.clone()).unwrap();
            for _ in 0..MAX_MODELS_PER_DAY + 2 {
                admissions.record("agent", &format!("model-{}", uuid::Uuid::new_v4()));
            }
            let day = OffsetDateTime::now_utc().date().to_string();
            let usage = &admissions.counters.days[&day];
            // Sixty-four distinct models plus the folded `Other` bucket —
            // the recorder's own bound produces exactly that pair.
            assert_eq!(usage.models.len(), MAX_MODELS_PER_DAY + 1);
            assert_eq!(usage.models[FOLDED_LABEL], 2);
            assert_eq!(usage.agents["agent"], MAX_MODELS_PER_DAY as u64 + 2);
            admissions.persist().expect("persist");
        }
        let reloaded = Admissions::open(path).unwrap();
        let day = OffsetDateTime::now_utc().date().to_string();
        assert_eq!(reloaded.counters.days[&day].models[FOLDED_LABEL], 2);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn persistence_coalesces_instead_of_rewriting_per_request() {
        let root =
            std::env::temp_dir().join(format!("fairliny-admissions-{}", uuid::Uuid::new_v4()));
        collection_store::fs::ensure_private_dir(&root).unwrap();
        let path = root.join(COUNTERS_FILE);
        let mut admissions = Admissions::open(path.clone()).unwrap();

        // The first admission persists at once — the file materializes
        // early; later ones coalesce under the window.
        admissions.record("agent", "model");
        assert!(admissions.persist_due());
        admissions.persist().expect("persist");
        let written = std::fs::read_to_string(&path).expect("counters file");

        // A second admission inside the window stays in memory only.
        admissions.record("agent", "model");
        assert_eq!(admissions.pending, 1);
        assert!(!admissions.persist_due());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), written);

        // The explicit flush writes what the window held back.
        admissions.persist().expect("flush");
        assert_eq!(admissions.pending, 0);
        assert_ne!(std::fs::read_to_string(&path).unwrap(), written);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn caller_named_agents_fold_under_the_same_bound() {
        let mut admissions = Admissions::in_memory();
        let known = format!("agent-{}", uuid::Uuid::new_v4());
        admissions.record(&known, "model");
        for _ in 0..MAX_AGENTS_PER_DAY + 1 {
            admissions.record(&format!("agent-{}", uuid::Uuid::new_v4()), "model");
        }
        let day = OffsetDateTime::now_utc().date().to_string();
        {
            let usage = &admissions.counters.days[&day];
            // Caller-controlled names get the same discipline the models
            // map has: sixty-four distinct agents plus `Other`.
            assert_eq!(usage.agents.len(), MAX_AGENTS_PER_DAY + 1);
            assert_eq!(usage.agents[FOLDED_LABEL], 2);
        }
        // A name the bound already admitted keeps counting under itself;
        // only fresh names fold.
        admissions.record(&known, "model");
        admissions.record(&format!("agent-{}", uuid::Uuid::new_v4()), "model");
        let usage = &admissions.counters.days[&day];
        assert_eq!(usage.agents[&known], 2);
        assert_eq!(usage.agents[FOLDED_LABEL], 3);
    }

    #[test]
    fn extensions_cannot_overwrite_the_canonical_counters() {
        let mut extensions = serde_json::Map::new();
        extensions.insert("input_tokens".to_owned(), 999.into());
        extensions.insert("output_tokens".to_owned(), 888.into());
        extensions.insert("cache_read_input_tokens".to_owned(), 7.into());
        let record = usage_record(&a4mp::Usage {
            input_tokens: Some(10),
            output_tokens: Some(5),
            extensions,
        });
        // The canonical counts stand; the colliding extensions are skipped.
        assert_eq!(record["usage"]["input_tokens"], json!(10));
        assert_eq!(record["usage"]["output_tokens"], json!(5));
        assert_eq!(record["usage"]["cache_read_input_tokens"], json!(7));

        // When the canonical counter is absent nothing is overwritten —
        // the provider-native field still forwards.
        let mut extensions = serde_json::Map::new();
        extensions.insert("input_tokens".to_owned(), 9.into());
        let record = usage_record(&a4mp::Usage {
            input_tokens: None,
            output_tokens: None,
            extensions,
        });
        assert_eq!(record["usage"]["input_tokens"], json!(9));
    }

    #[tokio::test]
    async fn named_but_uncounted_fields_settle_as_unknown_never_absent() {
        let root = std::env::temp_dir().join(format!("fairliny-settle-{}", uuid::Uuid::new_v4()));
        collection_store::fs::ensure_private_dir(&root).unwrap();
        let binding = SourceBinding::new(
            "source:test#1",
            "test.ext",
            "inst",
            1,
            "epoch-A",
            [FORWARDED_SCOPE],
        )
        .expect("binding");
        let meter = Meter::compose(&root, binding).expect("meter");

        let mut extensions = serde_json::Map::new();
        extensions.insert("cache_read_input_tokens".to_owned(), Value::Null);
        extensions.insert("vendor_field".to_owned(), Value::Null);
        extensions.insert("latency_ms".to_owned(), 120.into());
        meter
            .settle_response(
                "stub",
                Some(&a4mp::Usage {
                    input_tokens: Some(10),
                    output_tokens: Some(5),
                    extensions,
                }),
            )
            .await;

        let facts = meter.facts();
        // The provider named `cache_read_input_tokens` without counting
        // it: the input aggregate settles Unknown rather than publish a
        // deceptively precise 10 that silently dropped a named part.
        let input = facts
            .iter()
            .find(|fact| fact.metric == token_usage_detector::metrics::TOKENS_INPUT)
            .expect("input fact");
        assert_eq!(input.value, None);
        assert_eq!(input.quality, Quality::Unknown);
        // A provider-native field named without a count lands under the
        // provider namespace as its own Unknown reading — never dropped.
        let vendor = facts
            .iter()
            .find(|fact| fact.metric == "stub.usage/vendor_field")
            .expect("vendor fact");
        assert_eq!(vendor.value, None);
        assert_eq!(vendor.quality, Quality::Unknown);
        // A counted provider-native field still settles its own number.
        let latency = facts
            .iter()
            .find(|fact| fact.metric == "stub.usage/latency_ms")
            .expect("latency fact");
        assert_eq!(latency.value.as_deref(), Some("120"));
        assert_eq!(latency.quality, Quality::Reported);
        // The leaf the mapping already downgraded is not published twice.
        assert!(
            !facts
                .iter()
                .any(|fact| fact.metric == "stub.usage/cache_read_input_tokens")
        );
        assert_eq!(meter.failure_count(), 0);
        let _ = std::fs::remove_dir_all(root);
    }
}
