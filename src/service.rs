//! The outward face: the `fairliny serve` NDJSON loop and dispatch.
//!
//! One JSON request per line — `{"id":N,"method":...,"params":{}}` in,
//! `{"id":N,"result":{...}}` or `{"id":N,"error":"..."}` out. A malformed,
//! oversized or non-UTF-8 line answers `id: null` and the loop continues:
//! a sidecar survives bad input rather than dying on it. Methods:
//!
//! - `models.list` — the bound route table. Configured surfaces, never a
//!   live-availability claim: a profile's presence asserts a supported
//!   access surface, not that the provider is reachable now.
//! - `chat.complete` — forward one chat request through the bound adapter;
//!   admission counts at accept, settlement follows the response on its
//!   own task.
//! - `metrics.exposition` — the Prometheus/OpenMetrics text a host mounts
//!   at `/metrics`.
//!
//! Nothing here touches credential material: the router hands the adapter
//! a resolver, the lease answers, and only refusal codes travel back.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinSet;

use crate::meter::{Meter, UsageKeyStyle, usage_object};
use crate::router::{BoundRoute, Router, auth_label, protocol_label};
use crate::{Error, Result};

/// Upper bound on one request line. A line past it is hostile input, not
/// a request: answered `id: null`, its remainder discarded through the
/// next newline without ever being buffered.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

/// The default deadline on one upstream call. Provider hangs are
/// indistinguishable from very slow answers at the transport layer, so
/// the bound is generous — six hundred seconds is far past a healthy
/// buffered completion — and `upstreamDeadlineSecs` overrides it in the
/// routes document; `0` means the host accepts an unbounded wait.
pub const DEFAULT_UPSTREAM_DEADLINE: Duration = Duration::from_secs(600);

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

/// The composed gateway: router and meter behind one dispatch surface.
pub struct Service {
    router: Router,
    meter: Arc<Meter>,
    /// The deadline one upstream call gets, or `None` for an unbounded
    /// wait — see [`DEFAULT_UPSTREAM_DEADLINE`].
    upstream_deadline: Option<Duration>,
    /// Settlement tasks spawned beside replies — reaped as they finish
    /// so the set holds live work, never one retained task per request.
    settle: Mutex<JoinSet<()>>,
}

impl Service {
    /// Compose the outward face over a bound router and meter.
    pub fn new(router: Router, meter: Meter) -> Self {
        Self {
            router,
            meter: Arc::new(meter),
            upstream_deadline: Some(DEFAULT_UPSTREAM_DEADLINE),
            settle: Mutex::new(JoinSet::new()),
        }
    }

    /// Set the deadline one upstream call gets: the forwarded request
    /// errors with `upstream_deadline` once the provider call outlives
    /// it, so one hung provider cannot stall the whole gateway. `None`
    /// restores the caller-cancels model for hosts that bound the call
    /// themselves.
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
        self.settle.lock().map(|tasks| tasks.len()).unwrap_or(0)
    }

    /// Reap settlement tasks that already finished: the tracked set
    /// stays proportional to live settlement work instead of growing
    /// one entry per forwarded request for the process lifetime. A
    /// panicked settlement counts as a metering failure like any other.
    fn reap_settlements(&self) {
        let Ok(mut tasks) = self.settle.lock() else {
            self.meter.count_failure();
            return;
        };
        while let Some(result) = tasks.try_join_next() {
            if result.is_err() {
                self.meter.count_failure();
            }
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
            Some("chat.complete") => reply(id, self.chat_complete(params).await),
            Some("metrics.exposition") => reply(id, self.metrics_exposition().await),
            _ => error_reply(id, "unknown method"),
        }
    }

    /// The stdin loop: parse a line, dispatch it, write the reply, and
    /// continue. Returns on EOF or a stream error; a malformed, oversized
    /// or non-UTF-8 line is a per-request `id: null` error, never a fatal
    /// one, and the loop is ready for the next line.
    ///
    /// Input is awaited, never blocked on — an idle sidecar waiting for
    /// the next line still yields to the settlement tasks the replies
    /// spawned.
    pub async fn serve(
        &self,
        mut input: impl AsyncBufRead + Unpin,
        mut output: impl AsyncWrite + Unpin,
    ) -> std::io::Result<()> {
        let mut line = Vec::new();
        loop {
            line.clear();
            match read_capped_line(&mut input, &mut line).await? {
                InputLine::Eof => return Ok(()),
                InputLine::Oversized => {
                    write_line(
                        &mut output,
                        &json!({"id": null, "error": format!("bad request line: exceeds {MAX_LINE_BYTES} bytes")}),
                    )
                    .await?;
                    continue;
                }
                InputLine::Complete => {}
            }
            let Ok(text) = std::str::from_utf8(&line) else {
                write_line(
                    &mut output,
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
                        &mut output,
                        &json!({"id": null, "error": format!("bad request line: {error}")}),
                    )
                    .await?;
                    continue;
                }
            };
            let id = request.get("id").cloned().unwrap_or(Value::Null);
            let method = request.get("method").and_then(Value::as_str);
            let params = request.get("params").cloned().unwrap_or(Value::Null);
            let reply = self.dispatch(id, method, &params).await;
            write_line(&mut output, &reply).await?;
        }
    }

    /// Drain pending settlement tasks and persist the counters. The
    /// forward path never needs it — this is how a host (or a test, or
    /// the exposition before it answers) observes a settled journal
    /// instead of racing it.
    pub async fn flush_metering(&self) {
        let drained = match self.settle.lock() {
            Ok(mut guard) => Some(std::mem::replace(&mut *guard, JoinSet::new())),
            Err(_) => {
                // A poisoned task set is a metering failure like any
                // other — counted, never propagated.
                self.meter.count_failure();
                None
            }
        };
        if let Some(mut tasks) = drained {
            while let Some(result) = tasks.join_next().await {
                if result.is_err() {
                    self.meter.count_failure();
                }
            }
        }
        self.meter.flush();
    }

    /// The bound route table as a projection — a config answer, not a
    /// reachability probe.
    fn models_list(&self) -> Result<Value> {
        let mut models = Vec::new();
        for (model, route) in self.router.routes() {
            models.push(json!({
                "id": model,
                "provider": route.provider.as_str(),
                "upstreamModel": route.upstream_model,
                "protocol": route.protocol.as_ref().map(protocol_label),
                "auth": auth_label(&route.auth),
                "bound": "route",
            }));
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

    /// Forward one chat request: resolve the route, count the admission,
    /// call the adapter under the upstream deadline, spawn the settlement
    /// beside the reply.
    async fn chat_complete(&self, params: &Value) -> Result<Value> {
        let model = params
            .get("model")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Request("chat.complete requires a model".to_owned()))?;
        let bound = self.router.resolve(model)?;
        let agent = params
            .get("agent")
            .and_then(Value::as_str)
            .unwrap_or("stdio");
        // Admission is the accept event: the request exists only once it
        // parses — a payload the gateway rejects is never counted as
        // forwarded traffic.
        let request = chat_request(&bound.upstream_model, params)?;
        self.meter.admit_request(agent, model);
        let control = a4mp::RequestControl::default();
        let output = match self.upstream_deadline {
            Some(deadline) => {
                match tokio::time::timeout(deadline, bound.adapter.chat(request, &control)).await {
                    Ok(output) => output?,
                    Err(_) => {
                        // The provider call is dead work now: cancel it and
                        // let the caller decide whether the request retries —
                        // one hung upstream never becomes an unbounded outage
                        // of the whole gateway.
                        control.cancel.cancel();
                        return Err(Error::UpstreamDeadline(deadline));
                    }
                }
            }
            None => bound.adapter.chat(request, &control).await?,
        };
        // Settlement is ordered after the response exists and runs on its
        // own task: the reply never waits on the journal.
        let meter = Arc::clone(&self.meter);
        let provider = bound.provider.as_str().to_owned();
        let usage = output.usage.clone();
        if let Ok(mut tasks) = self.settle.lock() {
            tasks.spawn(async move {
                meter.settle_response(&provider, usage.as_ref()).await;
            });
        } else {
            // The settlement never spawned: a metering failure like any
            // other — counted, never propagated into the reply.
            self.meter.count_failure();
        }
        Ok(output_json(&bound, &output))
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

/// One reply line on the wire: the serialized object plus its newline,
/// written and flushed as one await pair.
async fn write_line(output: &mut (impl AsyncWrite + Unpin), value: &Value) -> std::io::Result<()> {
    let mut line = value.to_string();
    line.push('\n');
    output.write_all(line.as_bytes()).await?;
    output.flush().await
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

/// Parse a request's messages into the canonical chat request. The
/// outward shape is deliberately small — `{role, text}` messages, common
/// sampling keys, and an `extensions` object forwarded verbatim so
/// provider-native fields never die at the gateway's own parser.
fn chat_request(upstream_model: &str, params: &Value) -> Result<a4mp::ChatRequest> {
    let invalid = |field: &str| Error::Request(format!("chat.complete: {field}"));
    let messages = params
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("requires messages"))?;
    let mut parsed = Vec::with_capacity(messages.len());
    for message in messages {
        let role = match message.get("role").and_then(Value::as_str) {
            Some("system") => a4mp::Role::System,
            Some("user") => a4mp::Role::User,
            Some("assistant") => a4mp::Role::Assistant,
            Some(other) => a4mp::Role::Other(other.to_owned()),
            None => return Err(invalid("message requires a role")),
        };
        let text = message
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("message requires text"))?;
        parsed.push(a4mp::Message::text(role, text));
    }
    let sampling = a4mp::Sampling {
        temperature: params
            .get("temperature")
            .and_then(Value::as_f64)
            .map(|value| value as f32),
        top_p: params
            .get("topP")
            .and_then(Value::as_f64)
            .map(|value| value as f32),
        max_output_tokens: params
            .get("maxOutputTokens")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok()),
        stop: params
            .get("stop")
            .and_then(Value::as_array)
            .map(|stop| {
                stop.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
    };
    let extensions = params
        .get("extensions")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    Ok(a4mp::ChatRequest {
        model: upstream_model.to_owned(),
        messages: parsed,
        sampling,
        extensions,
        ..Default::default()
    })
}

/// The response a caller sees: text and parts verbatim, usage unhidden,
/// provider-native extensions passed through — a gateway relays, it does
/// not editorialize.
fn output_json(bound: &BoundRoute, output: &a4mp::Output) -> Value {
    let parts: Vec<Value> = output
        .parts
        .iter()
        .map(|part| match part {
            a4mp::ContentPart::Text { text } => json!({ "type": "text", "text": text }),
            a4mp::ContentPart::ToolCall(call) => json!({
                "type": "toolCall",
                "id": call.id,
                "name": call.name,
                "arguments": call.arguments,
            }),
            a4mp::ContentPart::ToolResult(result) => json!({
                "type": "toolResult",
                "callId": result.call_id,
                "isError": result.is_error,
            }),
            a4mp::ContentPart::Media { kind, .. } => {
                json!({ "type": "media", "kind": format!("{kind:?}") })
            }
            // Opaque reasoning state is never flattened into visible text —
            // it relays as a marker, not its payload.
            a4mp::ContentPart::Reasoning(_) => json!({ "type": "reasoning" }),
            _ => json!({ "type": "other" }),
        })
        .collect();
    let text = output
        .parts
        .iter()
        .filter_map(|part| match part {
            a4mp::ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<String>();
    json!({
        "provider": bound.provider.as_str(),
        "model": bound.upstream_model,
        "text": text,
        "parts": parts,
        "stopReason": output.stop.as_ref().map(stop_label),
        "usage": usage_json(&output.usage),
        "extensions": output.extensions,
    })
}

fn stop_label(stop: &a4mp::StopReason) -> String {
    match stop {
        a4mp::StopReason::Complete => "complete".to_owned(),
        a4mp::StopReason::Length => "length".to_owned(),
        a4mp::StopReason::ToolUse => "tool-use".to_owned(),
        a4mp::StopReason::Filtered => "filtered".to_owned(),
        a4mp::StopReason::Paused => "paused".to_owned(),
        a4mp::StopReason::Other(reason) => format!("other:{reason}"),
        _ => "other".to_owned(),
    }
}

/// Usage on the wire: the canonical counters plus every provider-native
/// field — absent counters stay absent, they are never zeroed. Shares
/// [`usage_object`] with the settlement record so an extension key can
/// never overwrite a real count in either projection.
fn usage_json(usage: &Option<a4mp::Usage>) -> Value {
    usage
        .as_ref()
        .map(|usage| Value::Object(usage_object(usage, UsageKeyStyle::Reply)))
        .unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_request_maps_the_outward_shape_verbatim() {
        let request = chat_request(
            "upstream-9",
            &json!({
                "messages": [
                    {"role": "system", "text": "sys"},
                    {"role": "user", "text": "hi"}
                ],
                "temperature": 0.5,
                "maxOutputTokens": 64,
                "extensions": {"vendor_flag": true}
            }),
        )
        .expect("request");
        assert_eq!(request.model, "upstream-9");
        assert_eq!(request.messages.len(), 2);
        assert_eq!(request.sampling.temperature, Some(0.5));
        assert_eq!(request.sampling.max_output_tokens, Some(64));
        assert_eq!(request.extensions["vendor_flag"], json!(true));
    }

    #[test]
    fn malformed_messages_fail_closed() {
        assert!(chat_request("m", &json!({})).is_err());
        assert!(chat_request("m", &json!({"messages": [{}]})).is_err());
    }

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

    #[test]
    fn reply_usage_extensions_cannot_overwrite_the_canonical_counts() {
        // The reply projection carries the same canonical-key guard the
        // settlement record does — a provider extension naming
        // `inputTokens` never replaces the counted value.
        let mut extensions = serde_json::Map::new();
        extensions.insert("inputTokens".to_owned(), 999.into());
        extensions.insert("cacheReadInputTokens".to_owned(), 7.into());
        let usage = usage_json(&Some(a4mp::Usage {
            input_tokens: Some(10),
            output_tokens: Some(5),
            extensions,
        }));
        assert_eq!(usage["inputTokens"], json!(10));
        assert_eq!(usage["outputTokens"], json!(5));
        assert_eq!(usage["cacheReadInputTokens"], json!(7));

        // A provider-native field naming an absent counter still
        // forwards under its own spelling — nothing was overwritten.
        let mut extensions = serde_json::Map::new();
        extensions.insert("inputTokens".to_owned(), 9.into());
        let usage = usage_json(&Some(a4mp::Usage {
            input_tokens: None,
            output_tokens: None,
            extensions,
        }));
        assert_eq!(usage["inputTokens"], json!(9));
    }
}
