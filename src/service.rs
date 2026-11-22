//! The outward face: the `fairliny serve` NDJSON loop and dispatch.
//!
//! One JSON request per line — `{"id":N,"method":...,"params":{}}` in,
//! `{"id":N,"result":{...}}` or `{"id":N,"error":"..."}` out. A malformed,
//! oversized or non-UTF-8 line answers `id: null` and the loop continues:
//! a sidecar survives bad input rather than dying on it. Methods:
//!
//! - `models.list` — the bound route table. Configured surfaces, never a
//!   live-availability claim: a profile's or endpoint's presence asserts
//!   a supported access surface, not that the provider is reachable now.
//! - `chat.complete` — forward one `{dialect, body, agent?}` chat request
//!   through the wire codecs and the bound adapter; the result is
//!   `{body, losses}` — the dialect response plus every conversion loss.
//! - `chat.stream` — the same params; the replies are `stream:"data"`
//!   frame lines then exactly one `stream:"end"` line. Frames and other
//!   requests' replies may interleave — correlate by `id`.
//! - `chat.cancel` — `{"requestId"}` cancels that in-flight request's
//!   control token.
//! - `metrics.exposition` — the Prometheus/OpenMetrics text a host mounts
//!   at `/metrics`.
//!
//! Nothing here touches credential material: the router hands the adapter
//! a resolver, the lease answers, and only refusal codes travel back.
//! `upstreamDeadlineSecs` is the host's opt-in bound on one upstream call;
//! absent or `0` waits unbounded — viable work runs to completion and only
//! the caller cancels.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use futures_core::Stream;
use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinSet;

use crate::meter::Meter;
use crate::router::{BoundRoute, Router, auth_label, endpoint_authority, protocol_label};
use crate::{Error, Result};

/// Upper bound on one request line. A line past it is hostile input, not
/// a request: answered `id: null`, its remainder discarded through the
/// next newline without ever being buffered.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

/// What one [`read_capped_line`] call produced.
enum InputLine {
    /// EOF with no bytes read — the loop ends.
    Eof,
    /// A newline-terminated (or EOF-final) line within the cap.
    Complete,
    /// The line ran past `MAX_LINE_BYTES` — its remainder was skipped.
    Oversized,
}

/// Read one request line bounded by `MAX_LINE_BYTES`. The read goes
/// through a `Take` so a line without a newline can never buffer past
/// the cap; an oversized line's remainder is then skipped a buffer at a
/// time, so the discard is bounded too.
///
/// Async so the loop yields while it waits for input — settlement tasks
/// stay pollable between requests rather than stalling behind a blocking
/// stdin read.
async fn read_capped_line(
    input: &mut (impl AsyncBufRead + Unpin),
    line: &mut Vec<u8>,
) -> std::io::Result<InputLine> {
    if (&mut *input)
        .take(MAX_LINE_BYTES as u64 + 1)
        .read_until(b'\n', line)
        .await?
        == 0
    {
        return Ok(InputLine::Eof);
    }
    // `Take` spends at most the cap plus one: a full read ending in the
    // newline is at the cap boundary, anything else means no newline
    // arrived in time and the line is oversized.
    if line.len() <= MAX_LINE_BYTES || line.ends_with(b"\n") {
        return Ok(InputLine::Complete);
    }
    line.clear();
    loop {
        let available = input.fill_buf().await?;
        if available.is_empty() {
            return Ok(InputLine::Oversized);
        }
        match available.iter().position(|byte| *byte == b'\n') {
            Some(position) => {
                input.consume(position + 1);
                return Ok(InputLine::Oversized);
            }
            None => {
                let len = available.len();
                input.consume(len);
            }
        }
    }
}

/// Take a service lock whether or not it is poisoned. Every structure
/// these locks guard — the task sets and the in-flight table — changes
/// only through single, non-panicking operations, so the data a poisoned
/// lock guards is still consistent: recovering it keeps work tracked
/// instead of silently dropping a request.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// In-flight request id → the claim that owns it, for `chat.cancel`.
/// Each claim carries a fresh generation: once `chat.cancel` frees an id,
/// a newer request may claim it, and the older task's release must leave
/// that newer entry alone.
#[derive(Default)]
struct InFlight {
    next_generation: AtomicU64,
    table: Mutex<BTreeMap<String, (u64, a4mp::RequestControl)>>,
}

impl InFlight {
    /// Claim `key` for the life of one forward. A duplicate id is
    /// refused: two requests cannot share one correlation key.
    fn claim(self: &Arc<Self>, key: String, control: &a4mp::RequestControl) -> Option<Claim> {
        let mut table = lock(&self.table);
        if table.contains_key(&key) {
            return None;
        }
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        table.insert(key.clone(), (generation, control.clone()));
        Some(Claim {
            owner: Arc::clone(self),
            key,
            generation,
        })
    }

    /// Remove `key`'s entry for `chat.cancel`, handing back its control.
    fn take(&self, key: &str) -> Option<a4mp::RequestControl> {
        lock(&self.table).remove(key).map(|(_, control)| control)
    }
}

/// One forward's ownership of its request id. Dropping it releases the
/// entry only while the entry is still this claim's own generation — a
/// cancelled request finishing late never touches the request that
/// reused its id. The forward drops it before writing its final reply,
/// so a caller that saw the reply may reuse the id at once.
struct Claim {
    owner: Arc<InFlight>,
    key: String,
    generation: u64,
}

impl Drop for Claim {
    fn drop(&mut self) {
        let mut table = lock(&self.owner.table);
        if table
            .get(&self.key)
            .is_some_and(|(generation, _)| *generation == self.generation)
        {
            table.remove(&self.key);
        }
    }
}

/// The composed gateway: router and meter behind one dispatch surface.
pub struct Service {
    router: Router,
    meter: Arc<Meter>,
    /// The deadline one upstream call gets when the host opted in through
    /// the routes document, or `None` for an unbounded wait — the caller
    /// cancels; the sidecar never cuts viable work off on its own timer.
    upstream_deadline: Option<Duration>,
    /// Settlement tasks — the same fault-isolated set as before, shared
    /// with the forward tasks that spawn into it.
    settle: Arc<Mutex<JoinSet<()>>>,
    /// In-flight request claims, for `chat.cancel`.
    inflight: Arc<InFlight>,
    /// Spawned chat tasks, reaped like the settlement set.
    forward: Mutex<JoinSet<()>>,
    /// The configured catalog sync, when the host declared one —
    /// `catalog.read`/`catalog.refresh` answer from it.
    catalog_sync: Option<crate::catalog::CatalogSync>,
}

impl Service {
    /// Compose the outward face over a bound router and meter.
    pub fn new(router: Router, meter: Meter) -> Self {
        Self {
            router,
            meter: Arc::new(meter),
            upstream_deadline: None,
            settle: Arc::new(Mutex::new(JoinSet::new())),
            inflight: Arc::new(InFlight::default()),
            forward: Mutex::new(JoinSet::new()),
            catalog_sync: None,
        }
    }

    /// Attach the host-configured catalog sync.
    pub fn with_catalog_sync(mut self, sync: Option<crate::catalog::CatalogSync>) -> Self {
        self.catalog_sync = sync;
        self
    }

    /// Set the deadline one upstream call gets: a bound the host chose,
    /// not a default — the forwarded request errors with
    /// `upstream_deadline` once the provider call outlives it, so one
    /// hung provider cannot stall the whole gateway. `None` is the
    /// caller-cancels model for hosts that bound the call themselves.
    pub fn with_upstream_deadline(mut self, deadline: Option<Duration>) -> Self {
        self.upstream_deadline = deadline;
        self
    }

    pub fn router(&self) -> &Router {
        &self.router
    }

    pub fn meter(&self) -> &Meter {
        &self.meter
    }

    /// Settlement tasks currently retained — live work plus whatever the
    /// next dispatch has not reaped yet. The observable bound on the
    /// task set.
    pub fn settle_len(&self) -> usize {
        lock(&self.settle).len()
    }

    /// Reap settlement tasks that already finished: the tracked set
    /// stays proportional to live settlement work instead of growing
    /// one entry per forwarded request for the process lifetime. A
    /// panicked settlement counts as a metering failure like any other.
    fn reap_settlements(&self) {
        let mut tasks = lock(&self.settle);
        while let Some(result) = tasks.try_join_next() {
            if result.is_err() {
                self.meter.count_failure();
            }
        }
    }

    /// Reap forward tasks that already finished — the same bound
    /// `reap_settlements` keeps on the settlement set.
    fn reap_forward(&self) {
        let mut tasks = lock(&self.forward);
        while tasks.try_join_next().is_some() {}
    }

    /// Parse `{dialect, body, agent?}` into the canonical request, resolve
    /// the outward model through the route table, rewrite the model to the
    /// upstream id, and count the admission — all before the task spawns,
    /// so a refused request never enters the in-flight table.
    fn prepare_chat(&self, params: &Value) -> Result<PreparedChat> {
        let dialect = match params.get("dialect").and_then(Value::as_str) {
            Some("openai-chat-completions") => a4mp::wire::WireDialect::OpenAiChatCompletions,
            Some("openai-responses") => a4mp::wire::WireDialect::OpenAiResponses,
            Some("anthropic-messages") => a4mp::wire::WireDialect::AnthropicMessages,
            _ => {
                return Err(Error::Request(
                    "chat params require a supported dialect: openai-chat-completions, \
                     openai-responses or anthropic-messages"
                        .to_owned(),
                ));
            }
        };
        let body = params.get("body").ok_or_else(|| {
            Error::Request("chat params require a dialect request body".to_owned())
        })?;
        let bytes =
            serde_json::to_vec(body).map_err(|e| Error::Request(format!("request body: {e}")))?;
        let (mut request, report) = a4mp::wire::decode_chat_request(dialect, &bytes)
            .map_err(|e| Error::Request(format!("request: {e}")))?;
        let client_model = request.model.clone();
        let bound = self.router.resolve(&client_model)?;
        request.model = bound.upstream_model.clone();
        let agent = params
            .get("agent")
            .and_then(Value::as_str)
            .unwrap_or("stdio")
            .to_owned();
        self.meter.admit_request(&agent, &client_model);
        Ok(PreparedChat {
            bound,
            request,
            client_model,
            dialect,
            losses: report.losses,
            control: a4mp::RequestControl::default(),
        })
    }

    /// `chat.cancel` looks the named request up in the in-flight table
    /// and cancels its control token — the adapter surfaces the
    /// cancellation, whatever it was doing.
    fn chat_cancel(&self, params: &Value) -> Result<Value> {
        let target = params
            .get("requestId")
            .ok_or_else(|| Error::Request("chat.cancel params require requestId".to_owned()))?;
        match self.inflight.take(&id_key(target)) {
            Some(control) => {
                control.cancel.cancel();
                Ok(json!({ "cancelled": true }))
            }
            None => Err(Error::Request("unknown in-flight request".to_owned())),
        }
    }

    /// One request, one reply. The reply never depends on the settlement
    /// that follows it — dispatch is the per-request unit of work.
    pub async fn dispatch(&self, id: Value, method: Option<&str>, params: &Value) -> Value {
        // Finished settlement tasks are reaped on the way in, so the
        // tracked set never grows past live work.
        self.reap_settlements();
        match method {
            Some("models.list") => reply(id, self.models_list()),
            Some("providers.list") => reply(id, self.providers_list()),
            Some("catalog.read") => reply(id, self.catalog_read()),
            Some("catalog.refresh") => reply(id, self.catalog_refresh().await),
            Some("chat.complete") => self.dispatch_buffered(id, params).await,
            // The cancel contract names its refusal verbatim — the
            // variant's own message crosses the wire, not the
            // `request:`-prefixed Display.
            Some("chat.cancel") => match self.chat_cancel(params) {
                Ok(value) => reply(id, Ok(value)),
                Err(Error::Request(message)) => error_reply(id, &message),
                Err(error) => error_reply(id, &error.to_string()),
            },
            Some("chat.stream") => error_reply(id, "chat.stream requires the serve loop"),
            Some("metrics.exposition") => reply(id, self.metrics_exposition().await),
            _ => error_reply(id, "unknown method"),
        }
    }

    /// `dispatch`'s buffered path: same preparation and registry as the
    /// serve loop, awaited inline for callers that drive dispatch
    /// themselves.
    async fn dispatch_buffered(&self, id: Value, params: &Value) -> Value {
        let prepared = match self.prepare_chat(params) {
            Ok(prepared) => prepared,
            Err(error) => return error_reply(id, &error.to_string()),
        };
        let Some(claim) = self.inflight.claim(id_key(&id), &prepared.control) else {
            return error_reply(id, "request id in-flight");
        };
        let result =
            buffered_result(&self.meter, &self.settle, self.upstream_deadline, prepared).await;
        drop(claim);
        reply(id, result)
    }

    /// The stdin loop: unary requests answer inline; chat requests run on
    /// their own task so one slow upstream never serializes the gateway —
    /// replies and stream frames for different requests may interleave,
    /// correlate by `id`. EOF drains in-flight work to completion; the
    /// sidecar cancels nothing on its own.
    pub async fn serve(
        &self,
        mut input: impl AsyncBufRead + Unpin,
        output: impl AsyncWrite + Unpin + Send + 'static,
    ) -> std::io::Result<()> {
        let writer: SharedWriter = Arc::new(tokio::sync::Mutex::new(Box::new(output)));
        let mut line = Vec::new();
        loop {
            line.clear();
            match read_capped_line(&mut input, &mut line).await? {
                InputLine::Eof => break,
                InputLine::Oversized => {
                    write_line(
                        &writer,
                        &json!({"id": null, "error": format!("bad request line: exceeds {MAX_LINE_BYTES} bytes")}),
                    )
                    .await?;
                    continue;
                }
                InputLine::Complete => {}
            }
            let Ok(text) = std::str::from_utf8(&line) else {
                write_line(
                    &writer,
                    &json!({"id": null, "error": "bad request line: not utf-8"}),
                )
                .await?;
                continue;
            };
            if text.trim().is_empty() {
                continue;
            }
            let request: Value = match serde_json::from_str(text) {
                Ok(value) => value,
                Err(error) => {
                    write_line(
                        &writer,
                        &json!({"id": null, "error": format!("bad request line: {error}")}),
                    )
                    .await?;
                    continue;
                }
            };
            let id = request.get("id").cloned().unwrap_or(Value::Null);
            let method = request.get("method").and_then(Value::as_str);
            let params = request.get("params").cloned().unwrap_or(Value::Null);
            match method {
                Some("chat.complete") | Some("chat.stream") => {
                    let prepared = match self.prepare_chat(&params) {
                        Ok(prepared) => prepared,
                        Err(error) => {
                            write_line(&writer, &error_reply(id, &error.to_string())).await?;
                            continue;
                        }
                    };
                    let Some(claim) = self.inflight.claim(id_key(&id), &prepared.control) else {
                        write_line(&writer, &error_reply(id, "request id in-flight")).await?;
                        continue;
                    };
                    self.reap_forward();
                    let meter = Arc::clone(&self.meter);
                    let settle = Arc::clone(&self.settle);
                    let deadline = self.upstream_deadline;
                    let task_writer = Arc::clone(&writer);
                    let mut tasks = lock(&self.forward);
                    if method == Some("chat.complete") {
                        tasks.spawn(async move {
                            let result = buffered_result(&meter, &settle, deadline, prepared).await;
                            drop(claim);
                            let _ = write_line(&task_writer, &reply(id, result)).await;
                        });
                    } else {
                        tasks.spawn(async move {
                            run_stream(
                                &task_writer,
                                &meter,
                                &settle,
                                deadline,
                                id,
                                prepared,
                                claim,
                            )
                            .await;
                        });
                    }
                }
                other => {
                    let reply = self.dispatch(id, other, &params).await;
                    write_line(&writer, &reply).await?;
                }
            }
        }
        // In-flight work runs to completion — its replies still belong on
        // the wire.
        let mut drained = std::mem::take(&mut *lock(&self.forward));
        while drained.join_next().await.is_some() {}
        Ok(())
    }

    /// Drain pending settlement tasks and persist the counters. The
    /// forward path never needs it — this is how a host (or a test, or
    /// the exposition before it answers) observes a settled journal
    /// instead of racing it.
    pub async fn flush_metering(&self) {
        let mut tasks = std::mem::take(&mut *lock(&self.settle));
        while let Some(result) = tasks.join_next().await {
            if result.is_err() {
                self.meter.count_failure();
            }
        }
        self.meter.flush();
    }

    /// The bound route table as a projection — a config answer, not a
    /// reachability probe.
    fn models_list(&self) -> Result<Value> {
        let mut models = Vec::new();
        for (model, route) in self.router.routes() {
            let mut entry = json!({
                "id": model,
                "provider": route.provider.as_str(),
                "protocol": route.protocol.as_ref().map(protocol_label),
                "upstreamModel": route.upstream_model,
                "auth": auth_label(&route.auth),
                "bound": "route",
            });
            if let Some(scope) = self.router.credential_scope(model) {
                entry["credentialScope"] = scope.into();
            }
            models.push(entry);
        }
        for (model, route) in self.router.endpoint_routes() {
            // The endpoint shows its authority only: the base URL
            // carries no credentials and its path stays private.
            let mut entry = json!({
                "id": model,
                "endpoint": endpoint_authority(&route.base_url),
                "protocol": protocol_label(&route.protocol),
                "upstreamModel": route.upstream_model,
                "auth": auth_label(&route.auth),
                "bound": "route",
            });
            if let Some(header) = &route.auth_header {
                entry["authHeader"] = header.as_str().into();
            }
            if let Some(scope) = self.router.credential_scope(model) {
                entry["credentialScope"] = scope.into();
            }
            models.push(entry);
        }
        for (model, adapter, upstream_model) in self.router.prebound() {
            models.push(json!({
                "id": model,
                "provider": adapter.target().provider.as_str(),
                "upstreamModel": upstream_model,
                "bound": "adapter",
            }));
        }
        Ok(json!({ "models": models }))
    }

    /// The base-vendor directory the router's catalog declares — every
    /// vendor's name, accepted mechanisms and declared https endpoints,
    /// a discovery answer, not a reachability probe.
    fn providers_list(&self) -> Result<Value> {
        crate::vendors::directory(self.router.catalog())
    }

    /// The locally cached catalog document — offline-only, never a
    /// fetch.
    fn catalog_read(&self) -> Result<Value> {
        self.catalog_sync
            .as_ref()
            .ok_or_else(|| Error::Catalog("catalog_not_configured".to_owned()))?
            .read()
    }

    /// One explicit revalidation against the configured source: fresh,
    /// unchanged (`304`, no write) or stale-with-kept-catalog.
    async fn catalog_refresh(&self) -> Result<Value> {
        self.catalog_sync
            .as_ref()
            .ok_or_else(|| Error::Catalog("catalog_not_configured".to_owned()))?
            .refresh()
            .await
    }

    /// The exposition text a host mounts at `/metrics`. Pending
    /// settlements drain before the projection so a scrape that follows
    /// a forward sees the settled counters, not a mid-flight journal.
    async fn metrics_exposition(&self) -> Result<Value> {
        self.flush_metering().await;
        Ok(json!({
            "contentType": crate::export::CONTENT_TYPE,
            "exposition": crate::export::render(self.meter())?,
        }))
    }
}

/// The reply channel every writer shares: each line is written and
/// flushed under one lock so frames and replies never interleave
/// mid-line.
type SharedWriter = Arc<tokio::sync::Mutex<Box<dyn AsyncWrite + Unpin + Send>>>;

/// One reply line on the wire: the serialized object plus its newline,
/// written and flushed as one await pair under the shared lock.
async fn write_line(writer: &SharedWriter, value: &Value) -> std::io::Result<()> {
    let mut line = value.to_string();
    line.push('\n');
    let mut guard = writer.lock().await;
    guard.write_all(line.as_bytes()).await?;
    guard.flush().await
}

/// A reply carrying a result or the error text — the aor.rs convention:
/// errors are strings, never exception payloads.
fn reply(id: Value, result: Result<Value>) -> Value {
    match result {
        Ok(result) => json!({ "id": id, "result": result }),
        Err(error) => error_reply(id, &error.to_string()),
    }
}

fn error_reply(id: Value, error: &str) -> Value {
    json!({ "id": id, "error": error })
}

/// In-flight requests register under their request id's JSON form so a
/// `chat.cancel` names the exact same key.
fn id_key(id: &Value) -> String {
    id.to_string()
}

/// Conversion losses on the wire: explicit paths, never silent drops.
fn losses_json(losses: &[a4mp::ConversionLoss]) -> Value {
    Value::Array(
        losses
            .iter()
            .map(|loss| {
                json!({
                    "path": loss.path,
                    "kind": match loss.kind {
                        a4mp::LossKind::Unsupported => "unsupported",
                        a4mp::LossKind::Lossy => "lossy",
                    },
                })
            })
            .collect(),
    )
}

/// One relayed SSE frame as a reply line — the dialect's own frame
/// fields, verbatim.
fn frame_line(id: &Value, event: &a4mp::SseEvent) -> Value {
    json!({"id": id, "stream": "data",
           "frame": {"event": event.event, "id": event.id, "data": event.data}})
}

/// The terminal line of one stream — exactly one per `chat.stream` that
/// produced any frame.
fn end_line(
    id: &Value,
    status: &str,
    losses: &[a4mp::ConversionLoss],
    error: Option<&str>,
) -> Value {
    let mut line = json!({"id": id, "stream": "end", "status": status,
                          "losses": losses_json(losses)});
    if let Some(error) = error {
        line["error"] = Value::String(error.to_owned());
    }
    line
}

/// Settlement is ordered after the response exists and runs on its own
/// task: the reply never waits on the journal.
fn spawn_settle(
    meter: &Arc<Meter>,
    settle: &Mutex<JoinSet<()>>,
    provider: String,
    usage: Option<a4mp::Usage>,
) {
    let meter = Arc::clone(meter);
    lock(settle).spawn(async move {
        meter.settle_response(&provider, usage.as_ref()).await;
    });
}

/// What `chat.complete`/`chat.stream` need after the line is read:
/// dialect, decoded request with the upstream model id, route, decode
/// losses and a fresh control token.
struct PreparedChat {
    bound: BoundRoute,
    request: a4mp::ChatRequest,
    client_model: String,
    dialect: a4mp::wire::WireDialect,
    losses: Vec<a4mp::ConversionLoss>,
    control: a4mp::RequestControl,
}

/// How one streaming call ended — the `stream:"end"` status names it.
enum PumpOutcome {
    Done,
    Ended(a4mp::Error),
    Deadline,
    WriteFailed,
}

/// What the pump accumulated while it ran. Lives outside the deadline
/// future so a fired bound still reports the frames, usage and losses it
/// already observed.
struct PumpState {
    /// Whether any `stream:"data"` line reached the wire.
    wrote_frame: bool,
    /// The last usage event the provider reported, if any.
    last_usage: Option<a4mp::Usage>,
    /// Decode losses plus every encode loss the dialect emitted.
    losses: Vec<a4mp::ConversionLoss>,
}

/// The buffered forward: one upstream call under the host's opt-in
/// deadline, then the dialect response body plus every conversion loss.
async fn buffered_result(
    meter: &Arc<Meter>,
    settle: &Mutex<JoinSet<()>>,
    deadline: Option<Duration>,
    prepared: PreparedChat,
) -> Result<Value> {
    let adapter = Arc::clone(&prepared.bound.adapter);
    let call = adapter.chat(prepared.request, &prepared.control);
    let output = match deadline {
        Some(deadline) => match tokio::time::timeout(deadline, call).await {
            Err(_) => return Err(Error::UpstreamDeadline(deadline)),
            Ok(result) => result?,
        },
        None => call.await?,
    };
    spawn_settle(
        meter,
        settle,
        prepared.bound.provider.as_str().to_owned(),
        output.usage.clone(),
    );
    let (body, encode_report) =
        a4mp::wire::encode_chat_output(prepared.dialect, &output, &prepared.client_model);
    let mut losses = prepared.losses;
    losses.extend(encode_report.losses);
    Ok(json!({ "body": body, "losses": losses_json(&losses) }))
}

/// The pump inside the stream task: dialect SSE frames as `stream:"data"`
/// lines, tracking the last usage event and every encode loss. Returns
/// how the stream ended; the caller writes the terminal line.
async fn pump_frames(
    writer: &SharedWriter,
    id: &Value,
    prepared: PreparedChat,
    state: &mut PumpState,
) -> PumpOutcome {
    let PreparedChat {
        bound,
        request,
        client_model,
        dialect,
        control,
        ..
    } = prepared;
    let mut events = match bound.adapter.chat_stream(request, &control).await {
        Ok(events) => events,
        Err(error) => return PumpOutcome::Ended(error),
    };
    let mut encoder = a4mp::wire::stream_encoder(dialect, &client_model);
    for frame in encoder.preamble() {
        state.wrote_frame = true;
        if write_line(writer, &frame_line(id, &frame)).await.is_err() {
            return PumpOutcome::WriteFailed;
        }
    }
    loop {
        let item = std::future::poll_fn(|cx| Stream::poll_next(events.as_mut(), cx)).await;
        match item {
            Some(Ok(event)) => {
                if let a4mp::StreamEvent::Usage(usage) = &event {
                    state.last_usage = Some(usage.clone());
                }
                for frame in encoder.encode(&event) {
                    state.wrote_frame = true;
                    if write_line(writer, &frame_line(id, &frame)).await.is_err() {
                        return PumpOutcome::WriteFailed;
                    }
                }
                state.losses.extend(encoder.drain_losses());
            }
            Some(Err(error)) => return PumpOutcome::Ended(error),
            None => break,
        }
    }
    for frame in encoder.finish() {
        state.wrote_frame = true;
        if write_line(writer, &frame_line(id, &frame)).await.is_err() {
            return PumpOutcome::WriteFailed;
        }
    }
    state.losses.extend(encoder.drain_losses());
    PumpOutcome::Done
}

/// The streaming forward: frames relayed live, then exactly one
/// `stream:"end"` line — or the ordinary error reply when nothing ever
/// framed. The last usage event settles once, on success, failure or
/// cancel alike, and the request's claim is released before the
/// terminal line is written.
async fn run_stream(
    writer: &SharedWriter,
    meter: &Arc<Meter>,
    settle: &Mutex<JoinSet<()>>,
    deadline: Option<Duration>,
    id: Value,
    mut prepared: PreparedChat,
    claim: Claim,
) {
    let provider = prepared.bound.provider.as_str().to_owned();
    let mut state = PumpState {
        wrote_frame: false,
        last_usage: None,
        losses: std::mem::take(&mut prepared.losses),
    };
    let pump = pump_frames(writer, &id, prepared, &mut state);
    let outcome = match deadline {
        Some(d) => tokio::time::timeout(d, pump)
            .await
            .unwrap_or(PumpOutcome::Deadline),
        None => pump.await,
    };
    spawn_settle(meter, settle, provider, state.last_usage);
    let line = match outcome {
        PumpOutcome::Done => Some(end_line(&id, "done", &state.losses, None)),
        PumpOutcome::Deadline => {
            let error = Error::UpstreamDeadline(deadline.unwrap_or_default()).to_string();
            Some(if state.wrote_frame {
                end_line(&id, "error", &state.losses, Some(&error))
            } else {
                error_reply(id, &error)
            })
        }
        PumpOutcome::Ended(error) => {
            // Adapter failures surface through the same `adapter:`
            // wrapper the buffered path reports — one error dialect on
            // the wire, whether the call framed or not.
            let status = matches!(error, a4mp::Error::Cancelled);
            let message = Error::Adapter(error).to_string();
            Some(match (state.wrote_frame, status) {
                (true, true) => end_line(&id, "cancelled", &state.losses, Some(&message)),
                (true, false) => end_line(&id, "error", &state.losses, Some(&message)),
                (false, _) => error_reply(id, &message),
            })
        }
        PumpOutcome::WriteFailed => None,
    };
    drop(claim);
    if let Some(line) = line {
        let _ = write_line(writer, &line).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn capped_reads_bound_a_hostile_line_and_recover() {
        // A line that runs past the cap never buffers whole: the read
        // stops at the bound and the remainder is skipped to the newline.
        let mut bytes = vec![b'x'; MAX_LINE_BYTES + 8];
        bytes.extend_from_slice(b"\n{\"id\":1}\n");
        let mut input = &bytes[..];
        let mut line = Vec::new();
        assert!(matches!(
            read_capped_line(&mut input, &mut line).await.expect("read"),
            InputLine::Oversized
        ));
        assert!(line.is_empty());
        // The next read starts on the following line — the oversized
        // line's tail did not leak into it.
        assert!(matches!(
            read_capped_line(&mut input, &mut line).await.expect("read"),
            InputLine::Complete
        ));
        assert_eq!(line, b"{\"id\":1}\n");
        assert!(matches!(
            read_capped_line(&mut input, &mut line).await.expect("read"),
            InputLine::Eof
        ));

        // An oversized line with no newline at all still ends at EOF.
        let tail = vec![b'y'; MAX_LINE_BYTES + 3];
        let mut input = &tail[..];
        line.clear();
        assert!(matches!(
            read_capped_line(&mut input, &mut line).await.expect("read"),
            InputLine::Oversized
        ));
        assert!(matches!(
            read_capped_line(&mut input, &mut line).await.expect("read"),
            InputLine::Eof
        ));
    }

    #[tokio::test]
    async fn capped_reads_accept_the_boundary_and_eof_lines() {
        // The cap counts the newline: content at the bound plus its
        // terminator is still a complete line.
        let mut bytes = vec![b'x'; MAX_LINE_BYTES - 1];
        bytes.push(b'\n');
        let mut input = &bytes[..];
        let mut line = Vec::new();
        assert!(matches!(
            read_capped_line(&mut input, &mut line).await.expect("read"),
            InputLine::Complete
        ));
        assert_eq!(line.len(), MAX_LINE_BYTES);

        // A final line ending at EOF without a newline completes too.
        line.clear();
        let mut input = &b"final-line-without-newline"[..];
        assert!(matches!(
            read_capped_line(&mut input, &mut line).await.expect("read"),
            InputLine::Complete
        ));
        assert_eq!(line, b"final-line-without-newline");
        assert!(matches!(
            read_capped_line(&mut input, &mut line).await.expect("read"),
            InputLine::Eof
        ));
    }

    /// Answers every chat with an empty output — enough to forward.
    struct EchoAdapter {
        target: a4mp::ServiceTarget,
    }

    #[async_trait::async_trait]
    impl a4mp::Adapter for EchoAdapter {
        fn target(&self) -> &a4mp::ServiceTarget {
            &self.target
        }

        async fn chat(
            &self,
            _request: a4mp::ChatRequest,
            _control: &a4mp::RequestControl,
        ) -> std::result::Result<a4mp::Output, a4mp::Error> {
            Ok(a4mp::Output::default())
        }
    }

    fn poison<T>(mutex: &Mutex<T>) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = mutex.lock();
            panic!("poison the lock under test");
        }));
        assert!(mutex.is_poisoned());
    }

    #[tokio::test]
    async fn poisoned_locks_never_drop_a_request() {
        let resolver: Arc<dyn a4mp::CredentialResolver> =
            Arc::new(crate::leases::Leases::disconnected());
        let mut router = Router::new(Arc::new(a4mp::ReqwestTransport::new()), resolver);
        router
            .register_adapter(
                "ping-model",
                "upstream-ping",
                Arc::new(EchoAdapter {
                    target: a4mp::ServiceTarget::new(
                        "stub",
                        a4mp::Protocol::Other("stub".to_owned()),
                        url::Url::parse("https://stub.invalid/").expect("url"),
                    ),
                }),
            )
            .expect("register adapter");
        let service = Service::new(router, Meter::unmetered());
        poison(&service.forward);
        poison(&service.settle);
        poison(&service.inflight.table);

        let request = |id: u64| {
            json!({"id": id, "method": "chat.complete", "params": {
                "dialect": "openai-chat-completions",
                "body": {"model": "ping-model", "messages": [{"role": "user", "content": "hi"}]},
            }})
            .to_string()
        };
        let input = format!("{}\n{}\n", request(1), request(2));
        let (writer, mut reader) = tokio::io::duplex(64 * 1024);
        let collected = tokio::spawn(async move {
            let mut buf = Vec::new();
            reader.read_to_end(&mut buf).await.expect("read replies");
            buf
        });
        service
            .serve(input.as_bytes(), writer)
            .await
            .expect("serve loop");
        service.flush_metering().await;
        let output = String::from_utf8(collected.await.expect("reader")).expect("utf8");
        let replies: Vec<Value> = output
            .lines()
            .map(|line| serde_json::from_str(line).expect("reply json"))
            .collect();

        // Both forwards ran and answered through the poisoned task set;
        // their claims were released through the poisoned table, and the
        // settlement set drained to empty.
        assert_eq!(replies.len(), 2, "{replies:?}");
        for id in [1, 2] {
            let reply = replies.iter().find(|r| r["id"] == id).expect("reply");
            assert!(reply["result"]["body"].is_object(), "{reply}");
        }
        assert!(lock(&service.inflight.table).is_empty());
        assert_eq!(service.settle_len(), 0);
    }
}
