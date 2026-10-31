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
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use agent_statistics::gateway::UsageDocument;
use agent_statistics::journal::{
    MAX_FACT_PAGE, MeteringFact, SettlementEligibility, SourceAdmission,
};
use agent_statistics::source_host::UsageSourceHost;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use token_usage_detector::SourceBinding;
use token_usage_detector::provider::ProviderMapping;
use token_usage_detector::usage::{Quality, UsageObservation, UsageOperation, wire};

use crate::{Error, Result};

/// The aggregate scope every settled forward lands in — one authorized
/// range the binding issues at open, because per-request scope grants
/// cannot enumerate traffic not yet seen.
const FORWARDED_SCOPE: &str = "gateway:forwarded";

/// The host-issued source identity the gateway settles under.
const SOURCE_REF: &str = "source:fairlead.gateway#1";

/// The extension id the binding declares — this gateway is the source.
const EXTENSION_ID: &str = "fairlead.gateway";

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
        })
    }

    /// Counters that never touch a filesystem — the `--no-meter` shape.
    fn in_memory() -> Self {
        Self {
            path: None,
            counters: Counters::default(),
        }
    }

    /// Count one forwarded request under today (UTC). Label bounds mirror
    /// the recorder: agent and model names fold into `Other` past their
    /// per-day bound, days drop oldest past the retention window.
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
        if let Some(path) = &self.path
            && let Ok(encoded) = serde_json::to_string(&self.counters)
        {
            let _ = collection_store::fs::atomic_write_private_text_bounded(
                path,
                &encoded,
                MAX_COUNTERS_BYTES,
            );
        }
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
    journal: Option<Mutex<UsageSourceHost>>,
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
        let admissions = Admissions::open(root.join(COUNTERS_FILE))?;
        let host = UsageSourceHost::open(&json!({"stateRoot": root.to_string_lossy()}))
            .map_err(|error| Error::Meter(error.to_string()))?;
        let admission = host.admit_source(binding, SettlementEligibility::SettlementEligible);
        Ok(Self {
            admissions: Mutex::new(admissions),
            journal: Some(Mutex::new(host)),
            admission: Some(admission),
            sequence: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        })
    }

    /// Counters without a journal — the shape a host uses when Fairlead
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
    /// failure is a persistence bug, never a reason to drop traffic.
    pub fn admit_request(&self, agent: &str, model: &str) {
        let Ok(mut admissions) = self.admissions.lock() else {
            self.failures.fetch_add(1, Ordering::SeqCst);
            return;
        };
        admissions.record(agent, model);
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
            let mapping = ProviderMapping::new(namespace, Quality::Reported)
                .map_err(|failure| Error::Meter(failure.code.to_string()))?;
            let Some(mapped) = mapping
                .normalize(&usage_record(usage))
                .map_err(|failure| Error::Meter(failure.code.to_string()))?
            else {
                return Ok(());
            };
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

/// The provider usage record the settlement hook feeds the mapping: the
/// canonical counters plus every provider-native field, verbatim — the
/// mapping owns alias folding, so nothing is flattened here first.
fn usage_record(usage: &a4mp::Usage) -> Value {
    let mut object = serde_json::Map::new();
    if let Some(input) = usage.input_tokens {
        object.insert("input_tokens".to_owned(), input.into());
    }
    if let Some(output) = usage.output_tokens {
        object.insert("output_tokens".to_owned(), output.into());
    }
    for (key, value) in &usage.extensions {
        // An extension must not overwrite the canonical counters; a
        // provider-native field naming one still forwards when the
        // canonical counter itself is absent — nothing is overwritten.
        let overwrites = (usage.input_tokens.is_some() && key == "input_tokens")
            || (usage.output_tokens.is_some() && key == "output_tokens");
        if overwrites {
            continue;
        }
        object.insert(key.clone(), value.clone());
    }
    json!({ "usage": Value::Object(object) })
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
            std::env::temp_dir().join(format!("fairlead-admissions-{}", uuid::Uuid::new_v4()));
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
        }
        let reloaded = Admissions::open(path).unwrap();
        let day = OffsetDateTime::now_utc().date().to_string();
        assert_eq!(reloaded.counters.days[&day].models[FOLDED_LABEL], 2);
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
}
