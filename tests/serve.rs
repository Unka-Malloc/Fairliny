//! The outward face under test: the NDJSON loop, the route binding, the
//! metering composition, and the lease's epoch contract — against stub
//! adapters or a loopback mock upstream, so nothing here ever touches a
//! real provider.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use credential_lease::{CredentialHandoff, LeaseEpochSource, LeasedCredential, SecretBytes};
use fairliny_gateway::leases::{Leases, ProviderCredential};
use fairliny_gateway::meter::Meter;
use fairliny_gateway::router::{EndpointRoute, Route, Router};
use fairliny_gateway::service::Service;

/// An epoch source a test can rotate — the contract the custody owner
/// holds on the host side. `None` is a legal answer; tests keep an epoch
/// installed throughout.
#[derive(Debug)]
struct Epochs {
    current: Mutex<String>,
}

impl LeaseEpochSource for Epochs {
    fn active_epoch(&self) -> anyhow::Result<Option<String>> {
        Ok(Some(self.current.lock().expect("epoch").clone()))
    }
}

/// A canned reply: the provider answer a forwarded request settles with.
fn reply_output() -> a4mp::Output {
    a4mp::Output {
        parts: vec![a4mp::ContentPart::Text {
            text: "pong".to_owned(),
        }],
        stop: Some(a4mp::StopReason::Complete),
        usage: Some(a4mp::Usage {
            input_tokens: Some(3),
            output_tokens: Some(1),
            extensions: Default::default(),
        }),
        ..Default::default()
    }
}

/// The adapter the tests bind: it resolves credentials through the real
/// resolver — the way every catalog adapter does at request time —
/// records the forwarded request so a test can see the gateway rewrote
/// the model, and answers with the canned output.
struct StubAdapter {
    target: a4mp::ServiceTarget,
    resolver: Arc<dyn a4mp::CredentialResolver>,
    requests: Arc<Mutex<Vec<a4mp::ChatRequest>>>,
    output: a4mp::Output,
}

#[async_trait::async_trait]
impl a4mp::Adapter for StubAdapter {
    fn target(&self) -> &a4mp::ServiceTarget {
        &self.target
    }

    async fn chat(
        &self,
        request: a4mp::ChatRequest,
        _control: &a4mp::RequestControl,
    ) -> std::result::Result<a4mp::Output, a4mp::Error> {
        let scope = a4mp::CredentialScope {
            target: &self.target,
            auth: &a4mp::AuthKind::ApiKey,
        };
        self.resolver.resolve(scope).await?;
        self.requests.lock().expect("requests").push(request);
        Ok(self.output.clone())
    }
}

/// The adapter that never answers: the upstream-hang shape the deadline
/// bounds. It resolves nothing and returns nothing.
struct HungAdapter {
    target: a4mp::ServiceTarget,
}

#[async_trait::async_trait]
impl a4mp::Adapter for HungAdapter {
    fn target(&self) -> &a4mp::ServiceTarget {
        &self.target
    }

    async fn chat(
        &self,
        _request: a4mp::ChatRequest,
        _control: &a4mp::RequestControl,
    ) -> std::result::Result<a4mp::Output, a4mp::Error> {
        std::future::pending::<()>().await;
        unreachable!("a pending future never completes")
    }
}

/// A handoff document minted under `epoch` carrying one API-key
/// credential per `(credential_id, secret)` pair — the material the
/// host would hand this process.
fn handoff_document(epoch: &str, credentials: &[(&str, &[u8])]) -> Vec<u8> {
    handoff_document_for(epoch, credentials, 3600)
}

/// [`handoff_document`] with an explicit lease duration in seconds.
fn handoff_document_for(
    epoch: &str,
    credentials: &[(&str, &[u8])],
    duration_seconds: u64,
) -> Vec<u8> {
    let credentials = credentials
        .iter()
        .map(|(id, secret)| {
            LeasedCredential::new(
                (*id).to_owned(),
                SecretBytes::try_from_bytes(secret.to_vec()).expect("secret"),
                None,
            )
            .expect("credential")
        })
        .collect();
    let mut map = BTreeMap::new();
    map.insert(ProviderCredential::ApiKey, credentials);
    let handoff =
        CredentialHandoff::new(map, Duration::from_secs(duration_seconds), epoch.to_owned())
            .expect("handoff");
    handoff.to_json().expect("document").expose_bytes().to_vec()
}

/// The lease the host would hand this process: one API-key credential in
/// the `ProviderCredential` family, minted under `epoch`.
fn handoff_bytes(epoch: &str) -> Vec<u8> {
    let id = uuid::Uuid::new_v4().to_string();
    handoff_document(epoch, &[(&id, b"test-credential-material")])
}

/// The target every test adapter claims — a prebound stub surface.
fn stub_target() -> a4mp::ServiceTarget {
    a4mp::ServiceTarget::new(
        "stub",
        a4mp::Protocol::Other("stub".to_owned()),
        url::Url::parse("https://stub.invalid/").expect("url"),
    )
}

/// A second surface distinct from the adapter stub's — what scope
/// bindings register against in the lease tests so the stub surface
/// keeps answering unscoped.
fn scoped_target() -> a4mp::ServiceTarget {
    a4mp::ServiceTarget::new(
        "vendor",
        a4mp::Protocol::Other("vendor".to_owned()),
        url::Url::parse("https://vendor.invalid/").expect("url"),
    )
}

/// Bind `adapter` under the `ping-model`/`upstream-ping` pair — the
/// outward name every chat test forwards through. The transport is real
/// but never invoked — every test route is prebound.
fn test_router_with(
    resolver: Arc<dyn a4mp::CredentialResolver>,
    adapter: Arc<dyn a4mp::Adapter>,
) -> Router {
    let transport = Arc::new(a4mp::ReqwestTransport::new());
    let mut router = Router::new(transport, resolver);
    router.register_adapter("ping-model", "upstream-ping", adapter);
    router
}

/// A router over the stub: the outward name `ping-model` forwards to the
/// stub adapter as `upstream-ping`.
fn test_router(
    resolver: Arc<dyn a4mp::CredentialResolver>,
    requests: Arc<Mutex<Vec<a4mp::ChatRequest>>>,
) -> Router {
    let adapter = Arc::new(StubAdapter {
        target: stub_target(),
        resolver: Arc::clone(&resolver),
        requests,
        output: reply_output(),
    });
    test_router_with(resolver, adapter)
}

/// A resolver holding one installed API-key lease — the working custody
/// answer an adapter expects per call.
fn resolver_with_lease() -> Arc<dyn a4mp::CredentialResolver> {
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let leases = Leases::disconnected();
    let epoch_id = epoch.current.lock().unwrap().clone();
    leases
        .install_handoff(&handoff_bytes(&epoch_id), epoch)
        .expect("install");
    Arc::new(leases)
}

/// Resolve one API key for `target` — the scoped answer when the
/// surface is bound to a credential scope, the unscoped one otherwise.
async fn resolve_for_target(
    leases: &Leases,
    target: &a4mp::ServiceTarget,
) -> std::result::Result<a4mp::Credential, a4mp::Error> {
    a4mp::CredentialResolver::resolve(
        leases,
        a4mp::CredentialScope {
            target,
            auth: &a4mp::AuthKind::ApiKey,
        },
    )
    .await
}

/// Resolve one API key through the port's resolver under an
/// unregistered surface — the unscoped answer an adapter sees per call.
async fn resolve_unscoped(leases: &Leases) -> std::result::Result<a4mp::Credential, a4mp::Error> {
    resolve_for_target(leases, &stub_target()).await
}

/// `{dialect, body, agent?}` params for a chat request.
fn chat_params(body: serde_json::Value, agent: Option<&str>) -> serde_json::Value {
    let mut params = serde_json::json!({"dialect": "openai-chat-completions", "body": body});
    if let Some(agent) = agent {
        params["agent"] = agent.into();
    }
    params
}

/// The reply line carrying `id`, wherever multiplexing placed it.
fn reply_for(replies: &[serde_json::Value], id: i64) -> &serde_json::Value {
    replies
        .iter()
        .find(|r| r["id"] == id)
        .expect("reply for id")
}

/// One request line carrying `params` for `method`.
fn request_line(id: i64, method: &str, params: serde_json::Value) -> Vec<u8> {
    let mut line = serde_json::json!({"id": id, "method": method, "params": params})
        .to_string()
        .into_bytes();
    line.push(b'\n');
    line
}

/// A scripted canonical event stream — the shape an adapter hands the
/// dialect encoder.
struct ScriptedStream {
    events: std::collections::VecDeque<std::result::Result<a4mp::StreamEvent, a4mp::Error>>,
}

impl futures_core::Stream for ScriptedStream {
    type Item = std::result::Result<a4mp::StreamEvent, a4mp::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::task::Poll::Ready(self.events.pop_front())
    }
}

/// A stream that pends until the request's own control token cancels —
/// the cancel path a hung upstream takes.
struct StallStream {
    wait: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
}

impl futures_core::Stream for StallStream {
    type Item = std::result::Result<a4mp::StreamEvent, a4mp::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match self.wait.as_mut().poll(cx) {
            std::task::Poll::Ready(()) => std::task::Poll::Ready(Some(Err(a4mp::Error::Cancelled))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Streams for `chat_stream`: scripted events, or a stall that only the
/// caller's cancel token ends. `chat` behaves like the stub.
struct StreamAdapter {
    target: a4mp::ServiceTarget,
    resolver: Arc<dyn a4mp::CredentialResolver>,
    requests: Arc<Mutex<Vec<a4mp::ChatRequest>>>,
    events: Mutex<std::collections::VecDeque<std::result::Result<a4mp::StreamEvent, a4mp::Error>>>,
    stall: bool,
}

#[async_trait::async_trait]
impl a4mp::Adapter for StreamAdapter {
    fn target(&self) -> &a4mp::ServiceTarget {
        &self.target
    }

    async fn chat(
        &self,
        request: a4mp::ChatRequest,
        _control: &a4mp::RequestControl,
    ) -> std::result::Result<a4mp::Output, a4mp::Error> {
        let scope = a4mp::CredentialScope {
            target: &self.target,
            auth: &a4mp::AuthKind::ApiKey,
        };
        self.resolver.resolve(scope).await?;
        self.requests.lock().expect("requests").push(request);
        Ok(a4mp::Output::default())
    }

    async fn chat_stream(
        &self,
        request: a4mp::ChatRequest,
        control: &a4mp::RequestControl,
    ) -> std::result::Result<a4mp::DynStream<'static, a4mp::StreamEvent>, a4mp::Error> {
        let scope = a4mp::CredentialScope {
            target: &self.target,
            auth: &a4mp::AuthKind::ApiKey,
        };
        self.resolver.resolve(scope).await?;
        self.requests.lock().expect("requests").push(request);
        if self.stall {
            Ok(Box::pin(StallStream {
                wait: Box::pin(control.cancel.clone().cancelled_owned()),
            }))
        } else {
            Ok(Box::pin(ScriptedStream {
                events: self.events.lock().expect("events").drain(..).collect(),
            }))
        }
    }
}

/// A meter settling into a scratch ledger under the test's own binding.
fn test_meter(root: &std::path::Path) -> Meter {
    let binding = token_usage_detector::SourceBinding::new(
        "source:test#1",
        "test.ext",
        "inst",
        1,
        "epoch-A",
        ["gateway:forwarded"],
    )
    .expect("binding");
    Meter::compose(root, binding).expect("meter")
}

/// Drive the service over an in-memory stream and collect the replies,
/// then drain the settlement tasks so metering assertions see a settled
/// journal rather than racing it. The wire is a duplex channel the
/// service owns — spawned chat tasks write through it from other tasks,
/// so the reader drains it concurrently.
async fn run(service: &Service, input: &[u8]) -> Vec<serde_json::Value> {
    let (writer, mut reader) = tokio::io::duplex(64 * 1024);
    let collected = tokio::spawn(async move {
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buf)
            .await
            .expect("read replies");
        buf
    });
    service.serve(input, writer).await.expect("serve loop");
    service.flush_metering().await;
    let output = collected.await.expect("reader task");
    String::from_utf8(output)
        .expect("utf8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("reply json"))
        .collect()
}

#[tokio::test]
async fn the_loop_answers_and_settles_one_forwarded_request() {
    let dir = tempfile::tempdir().expect("tempdir");
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let leases = Leases::disconnected();
    let epoch_id = epoch.current.lock().unwrap().clone();
    let bytes = handoff_bytes(&epoch_id);
    leases.install_handoff(&bytes, epoch).expect("install");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver: Arc<dyn a4mp::CredentialResolver> = Arc::new(leases);
    let service = Service::new(
        test_router(resolver, Arc::clone(&requests)),
        test_meter(dir.path()),
    );

    let mut input = br#"{"id":1,"method":"models.list","params":{}}
"#
    .to_vec();
    input.extend_from_slice(&request_line(
        2,
        "chat.complete",
        chat_params(
            serde_json::json!({
                "model": "ping-model",
                "messages": [{"role": "user", "content": "hi"}]
            }),
            Some("caller"),
        ),
    ));
    let replies = run(&service, &input).await;

    let models = &replies[0]["result"]["models"][0];
    assert_eq!(models["id"], "ping-model");
    assert_eq!(models["provider"], "stub");
    assert_eq!(models["upstreamModel"], "upstream-ping");

    let result = &replies[1]["result"];
    let body = &result["body"];
    assert_eq!(body["choices"][0]["message"]["content"], "pong");
    // The dialect body echoes the client's own outward model name.
    assert_eq!(body["model"], "ping-model");
    assert_eq!(body["usage"]["prompt_tokens"], 3);
    assert_eq!(body["usage"]["completion_tokens"], 1);
    assert!(result["losses"].is_array());
    // The outward model name was rewritten to the upstream id.
    assert_eq!(requests.lock().unwrap()[0].model, "upstream-ping");

    // Admission landed and settlement pushed bound facts into the journal.
    let exposition = fairliny_gateway::export::render(service.meter()).expect("render");
    assert!(exposition.contains("metera_gateway_agent_requests_total"));
    assert!(exposition.contains("metera_usage_tokens{kind=\"input\""));
    let facts = service.meter().facts();
    assert!(
        facts.iter().any(|fact| {
            fact.scope_ref == "gateway:forwarded"
                && fact.metric == token_usage_detector::metrics::TOKENS_INPUT
                && fact.value.as_deref() == Some("3")
        }),
        "the settled input count is a fact: {facts:?}"
    );
}

#[tokio::test]
async fn malformed_lines_and_unknown_methods_reply_and_recover() {
    let resolver: Arc<dyn a4mp::CredentialResolver> = Arc::new(Leases::disconnected());
    let service = Service::new(
        test_router(resolver, Arc::new(Mutex::new(Vec::new()))),
        Meter::unmetered(),
    );
    let replies = run(
        &service,
        b"not json at all\n{\"id\":9,\"method\":\"does.not.exist\"}\n{\"id\":10,\"method\":\"models.list\"}\n",
    )
    .await;
    assert!(replies[0]["id"].is_null());
    assert!(
        replies[0]["error"]
            .as_str()
            .unwrap()
            .contains("bad request line")
    );
    assert_eq!(replies[1]["error"], "unknown method");
    // The loop survived the malformed line and still answered the next request.
    assert!(replies[2]["result"]["models"].is_array());
}

#[tokio::test]
async fn oversized_and_non_utf8_lines_error_without_killing_the_loop() {
    let resolver: Arc<dyn a4mp::CredentialResolver> = Arc::new(Leases::disconnected());
    let service = Service::new(
        test_router(resolver, Arc::new(Mutex::new(Vec::new()))),
        Meter::unmetered(),
    );
    let mut input = Vec::new();
    // A hostile line past the byte cap — never fully buffered, answered
    // `id: null`, remainder discarded to the next newline.
    input.resize(fairliny_gateway::service::MAX_LINE_BYTES + 64, b'x');
    input.push(b'\n');
    input.extend_from_slice(b"{\"id\":1,\"method\":\"models.list\"}\n");
    // Non-UTF-8 input is a malformed line, not a loop-killing read error.
    input.extend_from_slice(&[0xff, 0xfe, b'\n']);
    input.extend_from_slice(b"{\"id\":2,\"method\":\"models.list\"}\n");

    let replies = run(&service, &input).await;
    assert!(replies[0]["id"].is_null());
    assert!(
        replies[0]["error"]
            .as_str()
            .unwrap()
            .contains("bad request line")
    );
    assert!(replies[1]["result"]["models"].is_array());
    assert!(replies[2]["id"].is_null());
    assert!(
        replies[2]["error"]
            .as_str()
            .unwrap()
            .contains("bad request line")
    );
    // The loop survived both hostile inputs and still answers.
    assert!(replies[3]["result"]["models"].is_array());
}

#[tokio::test]
async fn a_failed_meter_never_fails_the_reply() {
    let dir = tempfile::tempdir().expect("tempdir");
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let leases = Leases::disconnected();
    let epoch_id = epoch.current.lock().unwrap().clone();
    leases
        .install_handoff(&handoff_bytes(&epoch_id), epoch)
        .expect("install");
    // A binding whose grants exclude the forwarded scope: settlement is
    // refused on every reply, and the reply must be unaffected.
    let binding = token_usage_detector::SourceBinding::new(
        "source:test#1",
        "test.ext",
        "inst",
        1,
        "epoch-A",
        ["some:other-scope"],
    )
    .expect("binding");
    let meter = Meter::compose(dir.path(), binding).expect("meter");
    let resolver: Arc<dyn a4mp::CredentialResolver> = Arc::new(leases);
    let service = Service::new(
        test_router(resolver, Arc::new(Mutex::new(Vec::new()))),
        meter,
    );
    let replies = run(
        &service,
        &request_line(
            1,
            "chat.complete",
            chat_params(
                serde_json::json!({
                    "model": "ping-model",
                    "messages": [{"role": "user", "content": "hi"}]
                }),
                None,
            ),
        ),
    )
    .await;
    assert_eq!(
        replies[0]["result"]["body"]["choices"][0]["message"]["content"],
        "pong"
    );
    assert!(service.meter().failure_count() >= 1);
    assert!(service.meter().facts().is_empty());
}

#[tokio::test]
async fn an_unresolved_credential_or_model_fails_closed() {
    let resolver: Arc<dyn a4mp::CredentialResolver> = Arc::new(Leases::disconnected());
    let service = Service::new(
        test_router(resolver, Arc::new(Mutex::new(Vec::new()))),
        Meter::unmetered(),
    );
    // No lease is installed: the credential resolver refuses, and an
    // unknown model is refused before any adapter is touched.
    let mut input = request_line(
        1,
        "chat.complete",
        chat_params(
            serde_json::json!({
                "model": "ping-model",
                "messages": [{"role": "user", "content": "hi"}]
            }),
            None,
        ),
    );
    input.extend_from_slice(&request_line(
        2,
        "chat.complete",
        chat_params(
            serde_json::json!({
                "model": "no-such-model",
                "messages": [{"role": "user", "content": "hi"}]
            }),
            None,
        ),
    ));
    let replies = run(&service, &input).await;
    assert!(
        reply_for(&replies, 1)["error"]
            .as_str()
            .unwrap()
            .contains("credential_lease_unavailable")
    );
    assert!(
        reply_for(&replies, 2)["error"]
            .as_str()
            .unwrap()
            .contains("unknown model")
    );
}

#[tokio::test]
async fn a_rotated_epoch_refuses_the_lease_on_next_use() {
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let leases = Leases::disconnected();
    let epoch_id = epoch.current.lock().unwrap().clone();
    leases
        .install_handoff(&handoff_bytes(&epoch_id), epoch.clone())
        .expect("install");
    resolve_unscoped(&leases).await.expect("first resolve");
    *epoch.current.lock().unwrap() = uuid::Uuid::new_v4().to_string();
    // The slot consults the epoch source on every resolution: after the
    // rotation the same lease refuses as revoked.
    let error = resolve_unscoped(&leases).await.expect_err("revoked");
    assert!(error.to_string().contains("credential_lease_revoked"));
}

#[tokio::test]
async fn a_scrape_right_after_a_forward_sees_the_settled_counters() {
    let dir = tempfile::tempdir().expect("tempdir");
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let leases = Leases::disconnected();
    let epoch_id = epoch.current.lock().unwrap().clone();
    leases
        .install_handoff(&handoff_bytes(&epoch_id), epoch)
        .expect("install");
    let resolver: Arc<dyn a4mp::CredentialResolver> = Arc::new(leases);
    let service = Service::new(
        test_router(resolver, Arc::new(Mutex::new(Vec::new()))),
        test_meter(dir.path()),
    );

    // The exposition request arrives right behind the forward — the
    // answer must already carry the settled record, not a mid-flight
    // journal. `dispatch` awaits the buffered forward inline, so the
    // settlement was spawned before the scrape drains it.
    let first = service
        .dispatch(
            serde_json::json!(1),
            Some("chat.complete"),
            &chat_params(
                serde_json::json!({
                    "model": "ping-model",
                    "messages": [{"role": "user", "content": "hi"}]
                }),
                Some("caller"),
            ),
        )
        .await;
    let second = service
        .dispatch(
            serde_json::json!(2),
            Some("metrics.exposition"),
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(
        first["result"]["body"]["choices"][0]["message"]["content"],
        "pong"
    );
    let exposition = second["result"]["exposition"]
        .as_str()
        .expect("exposition text");
    assert!(
        exposition.contains("metera_gateway_agent_requests_total{agent=\"caller\""),
        "admission counter in exposition: {exposition}"
    );
    assert!(
        exposition.contains("metera_usage_tokens{kind=\"input\""),
        "settled usage in exposition: {exposition}"
    );
}

#[tokio::test]
async fn settlement_tracking_stays_bounded_across_forwards() {
    let dir = tempfile::tempdir().expect("tempdir");
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let leases = Leases::disconnected();
    let epoch_id = epoch.current.lock().unwrap().clone();
    leases
        .install_handoff(&handoff_bytes(&epoch_id), epoch)
        .expect("install");
    let resolver: Arc<dyn a4mp::CredentialResolver> = Arc::new(leases);
    let service = Service::new(
        test_router(resolver, Arc::new(Mutex::new(Vec::new()))),
        test_meter(dir.path()),
    );

    let params = chat_params(
        serde_json::json!({
            "model": "ping-model",
            "messages": [{"role": "user", "content": "hi"}]
        }),
        Some("caller"),
    );
    for _ in 0..32 {
        service
            .dispatch(serde_json::json!(1), Some("chat.complete"), &params)
            .await;
        // Let the settlement task settle, then confirm the reaper keeps
        // the tracked set proportional to live work — never one retained
        // task per forwarded request.
        tokio::task::yield_now().await;
        assert!(
            service.settle_len() <= 1,
            "settlement set stays bounded: {}",
            service.settle_len()
        );
    }
    service.flush_metering().await;
    assert_eq!(service.settle_len(), 0);
}

#[tokio::test]
async fn a_hung_upstream_errors_on_the_deadline_and_the_loop_recovers() {
    let mut router = Router::new(
        Arc::new(a4mp::ReqwestTransport::new()),
        Arc::new(Leases::disconnected()),
    );
    router.register_adapter(
        "hang-model",
        "upstream-hang",
        Arc::new(HungAdapter {
            target: a4mp::ServiceTarget::new(
                "stub",
                a4mp::Protocol::Other("stub".to_owned()),
                url::Url::parse("https://stub.invalid/").expect("url"),
            ),
        }),
    );
    let service = Service::new(router, Meter::unmetered())
        .with_upstream_deadline(Some(Duration::from_millis(50)));

    let mut input = request_line(
        1,
        "chat.complete",
        chat_params(
            serde_json::json!({
                "model": "hang-model",
                "messages": [{"role": "user", "content": "hi"}]
            }),
            None,
        ),
    );
    input.extend_from_slice(b"{\"id\":2,\"method\":\"models.list\"}\n");
    let replies = run(&service, &input).await;
    assert!(
        reply_for(&replies, 1)["error"]
            .as_str()
            .expect("deadline error")
            .contains("upstream deadline"),
        "the hung call answers with the deadline error: {replies:?}"
    );
    // The hung call did not poison the loop — the next request answers.
    assert!(reply_for(&replies, 2)["result"]["models"].is_array());
}

#[tokio::test]
async fn a_rejected_request_is_not_counted_as_forwarded() {
    let resolver: Arc<dyn a4mp::CredentialResolver> = Arc::new(Leases::disconnected());
    let service = Service::new(
        test_router(resolver, Arc::new(Mutex::new(Vec::new()))),
        Meter::unmetered(),
    );
    // `chat.complete` with a body the dialect cannot decode is refused at
    // the wire codec — the request was never admitted, so nothing counts
    // it.
    let replies = run(
        &service,
        &request_line(
            1,
            "chat.complete",
            chat_params(serde_json::json!({"model": "ping-model"}), None),
        ),
    )
    .await;
    assert!(replies[0]["error"].is_string());
    let document =
        serde_json::to_value(service.meter().usage_document().expect("counters document"))
            .expect("document json");
    assert!(
        document["days"].as_object().expect("days").is_empty(),
        "a rejected payload leaves the admission counters empty: {document}"
    );
}

#[tokio::test]
async fn a_rewritten_epoch_file_revokes_the_next_resolve() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("epoch");
    // Custody epochs are canonical UUIDs — the file carries the minted
    // value verbatim.
    let epoch = uuid::Uuid::new_v4().to_string();
    std::fs::write(&path, &epoch).expect("epoch file");
    let leases = Leases::disconnected();
    leases
        .install_handoff(
            &handoff_bytes(&epoch),
            Arc::new(fairliny_gateway::leases::FileEpochSource::new(&path)),
        )
        .expect("install");
    // While the file agrees, the lease resolves.
    resolve_unscoped(&leases).await.expect("first resolve");
    // The custody owner rewrote the file: the next resolve consults the
    // file again and refuses as revoked.
    std::fs::write(&path, uuid::Uuid::new_v4().to_string()).expect("rotate");
    let error = resolve_unscoped(&leases).await.expect_err("revoked");
    assert!(error.to_string().contains("credential_lease_revoked"));
}

#[test]
fn the_routes_document_refuses_malformed_entries_and_loads_well_formed_ones() {
    let resolver: Arc<dyn a4mp::CredentialResolver> = Arc::new(Leases::disconnected());
    let transport = Arc::new(a4mp::ReqwestTransport::new());
    let mut router = Router::new(transport, resolver);

    // A missing required field refuses the whole document — never half
    // a route table.
    assert!(
        router
            .load_routes(&serde_json::json!({"routes": [{"model": "chat"}]}))
            .is_err()
    );
    // So does a vocabulary word the document format never defined.
    assert!(
        router
            .load_routes(&serde_json::json!({
                "routes": [{"model": "chat", "provider": "ollama", "auth": "oauth-magic"}]
            }))
            .is_err()
    );
    // A runtime-supplied endpoint is part of the route: a local profile
    // carries no address of its own, so a route without the variable is
    // refused at declaration — the error names the missing variable,
    // not a deferred bind failure at first forward.
    let error = router
        .load_routes(&serde_json::json!({
            "routes": [{
                "model": "local-chat",
                "provider": "ollama",
                "upstreamModel": "llama3.1",
                "protocol": "other:ollama",
                "auth": "none"
            }]
        }))
        .expect_err("a route missing its endpoint variable refuses");
    assert!(error.to_string().contains("{endpoint}"), "{error}");
    assert!(router.resolve("local-chat").is_err());
    router
        .load_routes(&serde_json::json!({
            "routes": [{
                "model": "local-chat",
                "provider": "ollama",
                "upstreamModel": "llama3.1",
                "protocol": "other:ollama",
                "auth": "none",
                "vars": {"endpoint": "http://models.internal:11434"}
            }]
        }))
        .expect("routes");
    let bound = router.resolve("local-chat").expect("bound");
    assert_eq!(bound.upstream_model, "llama3.1");
    assert_eq!(bound.provider.as_str(), "ollama");
}

#[test]
fn meter_open_over_a_fresh_state_root_persists_admissions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let meter = Meter::open(dir.path()).expect("meter");
    meter.admit_request("agent", "model");
    // The first admission persists at once so the file materializes early.
    let document = serde_json::to_value(meter.usage_document().expect("counters document"))
        .expect("document json");
    assert!(
        !document["days"].as_object().expect("days").is_empty(),
        "the admission landed in the counters: {document}"
    );
    assert!(dir.path().join("gateway-usage.json").exists());
}

#[test]
fn the_binary_serves_ndjson_over_stdio() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("routes.json");
    std::fs::write(&config, r#"{"routes":[]}"#).expect("config");
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_fairliny"))
        .args(["serve", "--no-meter", "--config"])
        .arg(&config)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn fairliny");
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().expect("stdin");
        stdin
            .write_all(br#"{"id":1,"method":"models.list","params":{}}"#)
            .expect("request line");
        // Closing stdin is the EOF the sidecar exits on.
    }
    let output = child.wait_with_output().expect("exit");
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    let reply: serde_json::Value =
        serde_json::from_str(stdout.lines().next().expect("reply line")).expect("reply json");
    assert_eq!(reply["id"], 1);
    assert_eq!(reply["result"]["models"], serde_json::json!([]));
}

#[test]
fn a_route_naming_an_unknown_provider_fails_closed() {
    let resolver: Arc<dyn a4mp::CredentialResolver> = Arc::new(Leases::disconnected());
    let mut router = Router::new(Arc::new(a4mp::ReqwestTransport::new()), resolver);
    // The published `Route` fields — `provider`, `protocol`, `region`,
    // `vars` — stay the construction API this package version ships.
    let route = Route {
        provider: a4mp::ProviderId::new("no-such-provider"),
        protocol: None,
        region: None,
        auth: a4mp::AuthKind::ApiKey,
        upstream_model: "x".to_owned(),
        vars: Default::default(),
    };
    let error = router
        .add_route_scoped("model", route, "vendor-scope")
        .expect_err("closed");
    assert!(error.to_string().contains("unknown provider"));
    assert!(router.resolve("model").is_err());
}

/// A `StreamAdapter` bound under the test target: `events` script the
/// canonical stream, `stall` switches to the cancel-only stream.
fn stream_adapter(
    resolver: Arc<dyn a4mp::CredentialResolver>,
    requests: Arc<Mutex<Vec<a4mp::ChatRequest>>>,
    events: Vec<std::result::Result<a4mp::StreamEvent, a4mp::Error>>,
    stall: bool,
) -> Arc<StreamAdapter> {
    Arc::new(StreamAdapter {
        target: stub_target(),
        resolver,
        requests,
        events: Mutex::new(events.into_iter().collect()),
        stall,
    })
}

/// The scripted canonical stream every streaming test shares: a text
/// part, a tool call, tail usage, a clean finish.
fn scripted_events() -> Vec<std::result::Result<a4mp::StreamEvent, a4mp::Error>> {
    vec![
        Ok(a4mp::StreamEvent::PartStarted {
            index: 0,
            kind: a4mp::PartKind::Text,
        }),
        Ok(a4mp::StreamEvent::TextDelta {
            index: 0,
            text: "po".to_owned(),
        }),
        Ok(a4mp::StreamEvent::TextDelta {
            index: 0,
            text: "ng".to_owned(),
        }),
        Ok(a4mp::StreamEvent::ToolCallStarted {
            index: 1,
            id: "c1".to_owned(),
            name: "lookup".to_owned(),
        }),
        Ok(a4mp::StreamEvent::ToolCallDelta {
            index: 1,
            arguments: "{}".to_owned(),
        }),
        Ok(a4mp::StreamEvent::PartFinished { index: 0 }),
        Ok(a4mp::StreamEvent::PartFinished { index: 1 }),
        Ok(a4mp::StreamEvent::Usage(a4mp::Usage {
            input_tokens: Some(3),
            output_tokens: Some(1),
            extensions: Default::default(),
        })),
        Ok(a4mp::StreamEvent::Finished {
            stop: Some(a4mp::StopReason::Complete),
        }),
    ]
}

/// A chat body naming the bound model plus one user message.
fn stream_body() -> serde_json::Value {
    serde_json::json!({
        "model": "ping-model",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true
    })
}

/// Every `stream:"data"` frame's decoded `frame.data` for `id`, in wire
/// order; `"[DONE]"` stays the literal string.
fn frame_data(replies: &[serde_json::Value], id: i64) -> Vec<&str> {
    replies
        .iter()
        .filter(|r| r["id"] == id && r["stream"] == "data")
        .filter_map(|r| r["frame"]["data"].as_str())
        .collect()
}

#[tokio::test]
async fn chat_complete_relays_tools_and_choice_through_the_dialect() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = resolver_with_lease();
    let adapter = Arc::new(StubAdapter {
        target: stub_target(),
        resolver: Arc::clone(&resolver),
        requests: Arc::clone(&requests),
        output: a4mp::Output {
            parts: vec![
                a4mp::ContentPart::Text {
                    text: "pong".to_owned(),
                },
                a4mp::ContentPart::ToolCall(a4mp::ToolCall {
                    id: "c1".to_owned(),
                    name: "lookup".to_owned(),
                    arguments: serde_json::json!({}),
                }),
            ],
            stop: Some(a4mp::StopReason::ToolUse),
            usage: Some(a4mp::Usage {
                input_tokens: Some(3),
                output_tokens: Some(1),
                extensions: Default::default(),
            }),
            ..Default::default()
        },
    });
    let service = Service::new(test_router_with(resolver, adapter), Meter::unmetered());

    let replies = run(
        &service,
        &request_line(
            1,
            "chat.complete",
            chat_params(
                serde_json::json!({
                    "model": "ping-model",
                    "messages": [
                        {"role": "user", "content": "hi"},
                        {"role": "tool", "tool_call_id": "c1", "content": "ok"}
                    ],
                    "tools": [{
                        "type": "function",
                        "function": {"name": "lookup", "parameters": {"type": "object"}}
                    }],
                    "tool_choice": "auto",
                    "parallel_tool_calls": false
                }),
                None,
            ),
        ),
    )
    .await;

    // The dialect decoded into the canonical request: the tool
    // definition, the choice and the parallel-call flag all survived.
    let forwarded = &requests.lock().expect("requests")[0];
    assert_eq!(forwarded.tools.len(), 1);
    assert_eq!(forwarded.tool_choice, Some(a4mp::ToolChoice::Auto));
    assert_eq!(forwarded.parallel_tool_calls, Some(false));
    assert_eq!(forwarded.model, "upstream-ping");

    let body = &reply_for(&replies, 1)["result"]["body"];
    assert_eq!(
        body["choices"][0]["message"]["tool_calls"][0]["function"]["name"],
        "lookup"
    );
    assert_eq!(body["usage"]["prompt_tokens"], 3);
}

#[tokio::test]
async fn chat_stream_relays_dialect_frames_and_settles_tail_usage() {
    let dir = tempfile::tempdir().expect("tempdir");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = resolver_with_lease();
    let adapter = stream_adapter(
        Arc::clone(&resolver),
        Arc::clone(&requests),
        scripted_events(),
        false,
    );
    let service = Service::new(test_router_with(resolver, adapter), test_meter(dir.path()));

    let replies = run(
        &service,
        &request_line(1, "chat.stream", chat_params(stream_body(), None)),
    )
    .await;

    let frames = frame_data(&replies, 1);
    let chunks: Vec<serde_json::Value> = frames
        .iter()
        .filter(|data| **data != "[DONE]")
        .map(|data| serde_json::from_str(data).expect("chunk json"))
        .collect();
    assert!(
        chunks.iter().any(|chunk| {
            chunk["object"] == "chat.completion.chunk"
                && chunk["choices"][0]["delta"]["content"] == "po"
        }),
        "a delta chunk carried the text: {frames:?}"
    );
    assert!(
        chunks
            .iter()
            .any(|chunk| { chunk["choices"][0]["delta"]["tool_calls"].is_array() }),
        "a delta chunk carried the tool call: {frames:?}"
    );
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk["usage"]["prompt_tokens"] == 3),
        "the tail usage chunk: {frames:?}"
    );
    assert!(
        frames.contains(&"[DONE]"),
        "the stream terminator: {frames:?}"
    );
    let end = replies
        .iter()
        .filter(|r| r["id"] == 1 && r["stream"] == "end")
        .collect::<Vec<_>>();
    assert_eq!(end.len(), 1, "exactly one stream end line: {replies:?}");
    assert_eq!(end[0]["status"], "done");
    assert!(end[0]["losses"].is_array());

    // The last usage event settled once, after the end line was written.
    let facts = service.meter().facts();
    assert!(
        facts.iter().any(|fact| {
            fact.scope_ref == "gateway:forwarded"
                && fact.metric == token_usage_detector::metrics::TOKENS_INPUT
                && fact.value.as_deref() == Some("3")
        }),
        "the settled input count is a fact: {facts:?}"
    );
}

#[tokio::test]
async fn chat_cancel_stops_an_in_flight_stream() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = resolver_with_lease();
    let adapter = stream_adapter(
        Arc::clone(&resolver),
        Arc::clone(&requests),
        Vec::new(),
        true,
    );
    let service = Service::new(test_router_with(resolver, adapter), Meter::unmetered());

    let mut input = request_line(1, "chat.stream", chat_params(stream_body(), None));
    input
        .extend_from_slice(b"{\"id\":2,\"method\":\"chat.cancel\",\"params\":{\"requestId\":1}}\n");
    let replies = run(&service, &input).await;

    assert_eq!(reply_for(&replies, 2)["result"]["cancelled"], true);
    // The stall produced no frame, so the cancelled call answers the
    // ordinary error shape rather than a stream end line.
    let cancelled = reply_for(&replies, 1);
    assert!(
        cancelled["error"]
            .as_str()
            .expect("error text")
            .contains("cancelled"),
        "the cancelled stream answers the error reply: {cancelled}"
    );
    assert!(cancelled["stream"].is_null());
}

#[tokio::test]
async fn a_duplicate_in_flight_id_is_refused() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = resolver_with_lease();
    let adapter = stream_adapter(
        Arc::clone(&resolver),
        Arc::clone(&requests),
        Vec::new(),
        true,
    );
    let service = Service::new(test_router_with(resolver, adapter), Meter::unmetered());

    let mut input = request_line(1, "chat.stream", chat_params(stream_body(), None));
    input.extend_from_slice(&request_line(
        1,
        "chat.stream",
        chat_params(stream_body(), None),
    ));
    input
        .extend_from_slice(b"{\"id\":3,\"method\":\"chat.cancel\",\"params\":{\"requestId\":1}}\n");
    let replies = run(&service, &input).await;

    // The first id=1 line is the refusal — two requests never share one
    // correlation key; the second is the cancelled call's own error.
    assert_eq!(reply_for(&replies, 1)["error"], "request id in-flight");
    assert_eq!(reply_for(&replies, 3)["result"]["cancelled"], true);
}

#[tokio::test]
async fn a_stream_completes_after_input_eof() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = resolver_with_lease();
    let adapter = stream_adapter(
        Arc::clone(&resolver),
        Arc::clone(&requests),
        scripted_events(),
        false,
    );
    let service = Service::new(test_router_with(resolver, adapter), Meter::unmetered());

    // EOF right after the request line: the loop drains in-flight work
    // to completion — it never cancels what the caller started.
    let replies = run(
        &service,
        &request_line(1, "chat.stream", chat_params(stream_body(), None)),
    )
    .await;

    let frames = frame_data(&replies, 1);
    assert!(
        frames.contains(&"[DONE]"),
        "frames drained past EOF: {frames:?}"
    );
    let end = replies
        .iter()
        .find(|r| r["id"] == 1 && r["stream"] == "end")
        .expect("stream end line");
    assert_eq!(end["status"], "done");
}

#[tokio::test]
async fn chat_cancel_names_an_unknown_request() {
    let resolver: Arc<dyn a4mp::CredentialResolver> = Arc::new(Leases::disconnected());
    let service = Service::new(
        test_router(resolver, Arc::new(Mutex::new(Vec::new()))),
        Meter::unmetered(),
    );
    let replies = run(
        &service,
        b"{\"id\":1,\"method\":\"chat.cancel\",\"params\":{\"requestId\":42}}\n",
    )
    .await;
    assert_eq!(replies[0]["error"], "unknown in-flight request");
}

#[tokio::test]
async fn a_failed_meter_never_fails_the_stream() {
    let dir = tempfile::tempdir().expect("tempdir");
    let resolver = resolver_with_lease();
    // A binding whose grants exclude the forwarded scope: settlement is
    // refused on every reply, and the stream must be unaffected.
    let binding = token_usage_detector::SourceBinding::new(
        "source:test#1",
        "test.ext",
        "inst",
        1,
        "epoch-A",
        ["some:other-scope"],
    )
    .expect("binding");
    let meter = Meter::compose(dir.path(), binding).expect("meter");
    let adapter = stream_adapter(
        Arc::clone(&resolver),
        Arc::new(Mutex::new(Vec::new())),
        scripted_events(),
        false,
    );
    let service = Service::new(test_router_with(resolver, adapter), meter);

    let replies = run(
        &service,
        &request_line(1, "chat.stream", chat_params(stream_body(), None)),
    )
    .await;
    let end = replies
        .iter()
        .find(|r| r["id"] == 1 && r["stream"] == "end")
        .expect("stream end line");
    assert_eq!(end["status"], "done");
    assert!(service.meter().failure_count() >= 1);
    assert!(service.meter().facts().is_empty());
}

/// Each `chat` call announces itself, then: the first call waits for its
/// cancel and then for `release_first` before it answers — the late
/// finish of a cancelled request; the second waits for its cancel; every
/// later call answers at once.
struct GatedAdapter {
    target: a4mp::ServiceTarget,
    calls: std::sync::atomic::AtomicUsize,
    entered: tokio::sync::mpsc::UnboundedSender<usize>,
    release_first: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl a4mp::Adapter for GatedAdapter {
    fn target(&self) -> &a4mp::ServiceTarget {
        &self.target
    }

    async fn chat(
        &self,
        _request: a4mp::ChatRequest,
        control: &a4mp::RequestControl,
    ) -> std::result::Result<a4mp::Output, a4mp::Error> {
        let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.entered.send(call).expect("test observer");
        if call >= 2 {
            return Ok(reply_output());
        }
        control.cancel.cancelled().await;
        if call == 0 {
            self.release_first.notified().await;
        }
        Err(a4mp::Error::Cancelled)
    }
}

#[tokio::test]
async fn a_cancelled_request_finishing_late_never_releases_a_reused_id() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let (entered, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
    let release_first = Arc::new(tokio::sync::Notify::new());
    let adapter = Arc::new(GatedAdapter {
        target: stub_target(),
        calls: std::sync::atomic::AtomicUsize::new(0),
        entered,
        release_first: Arc::clone(&release_first),
    });
    let resolver: Arc<dyn a4mp::CredentialResolver> = Arc::new(Leases::disconnected());
    let service = Service::new(test_router_with(resolver, adapter), Meter::unmetered());

    let (mut client, server_in) = tokio::io::duplex(64 * 1024);
    let (server_out, client_out) = tokio::io::duplex(64 * 1024);
    let mut replies = tokio::io::BufReader::new(client_out).lines();
    let body =
        serde_json::json!({"model": "ping-model", "messages": [{"role": "user", "content": "hi"}]});
    let complete = request_line(1, "chat.complete", chat_params(body, None));
    let cancel = |id: i64| request_line(id, "chat.cancel", serde_json::json!({"requestId": 1}));

    let driver = async {
        let mut next = async || -> serde_json::Value {
            let line = replies
                .next_line()
                .await
                .expect("read")
                .expect("reply line");
            serde_json::from_str(&line).expect("reply json")
        };
        // Request A claims id 1 and is cancelled; its adapter holds the
        // late finish back.
        client.write_all(&complete).await.expect("write");
        assert_eq!(entered_rx.recv().await, Some(0));
        client.write_all(&cancel(2)).await.expect("write");
        let reply = next().await;
        assert_eq!(reply["id"], 2);
        assert_eq!(reply["result"]["cancelled"], true);

        // Request B reuses id 1 while A is still running.
        client.write_all(&complete).await.expect("write");
        assert_eq!(entered_rx.recv().await, Some(1));

        // A finishes late; its claim is released before its reply.
        release_first.notify_one();
        let reply = next().await;
        assert_eq!(reply["id"], 1);
        assert!(
            reply["error"]
                .as_str()
                .expect("error")
                .contains("cancelled"),
            "{reply}"
        );

        // B still owns id 1: a third claim is refused ...
        client.write_all(&complete).await.expect("write");
        assert_eq!(next().await["error"], "request id in-flight");

        // ... and B is still cancellable, and completes.
        client.write_all(&cancel(3)).await.expect("write");
        let pair = [next().await, next().await];
        let cancelled = pair.iter().find(|r| r["id"] == 3).expect("cancel reply");
        assert_eq!(cancelled["result"]["cancelled"], true);
        let finished = pair.iter().find(|r| r["id"] == 1).expect("B reply");
        assert!(
            finished["error"]
                .as_str()
                .expect("error")
                .contains("cancelled"),
            "{finished}"
        );

        // With B finished, id 1 is free again and a new request completes.
        client.write_all(&complete).await.expect("write");
        assert_eq!(entered_rx.recv().await, Some(2));
        let reply = next().await;
        assert_eq!(reply["id"], 1);
        assert!(reply["result"]["body"].is_object(), "{reply}");
        drop(client);
    };
    let (served, ()) = tokio::join!(
        service.serve(tokio::io::BufReader::new(server_in), server_out),
        driver
    );
    served.expect("serve loop");
}

/// One request a loopback mock upstream received.
struct Received {
    request_line: String,
    headers: Vec<(String, String)>,
    body: serde_json::Value,
}

impl Received {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A loopback HTTP upstream answering exactly one request with `reply`
/// as JSON; the join handle yields what it received. Bound to
/// `127.0.0.1` only — no external network.
fn mock_upstream(
    reply: serde_json::Value,
) -> (std::net::SocketAddr, std::thread::JoinHandle<Received>) {
    use std::io::{BufRead, Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("addr");
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone"));
        let mut request_line = String::new();
        reader.read_line(&mut request_line).expect("request line");
        let mut headers = Vec::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("header line");
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            let (key, value) = line.split_once(':').expect("header");
            headers.push((key.trim().to_owned(), value.trim().to_owned()));
        }
        let length: usize = headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.parse().expect("length"))
            .unwrap_or(0);
        let mut body = vec![0; length];
        reader.read_exact(&mut body).expect("body");
        let payload = reply.to_string();
        let mut stream = stream;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
            payload.len()
        )
        .expect("reply");
        Received {
            request_line: request_line.trim_end().to_owned(),
            headers,
            body: serde_json::from_slice(&body).expect("request json"),
        }
    });
    (addr, handle)
}

/// A real transport that never consults proxy settings, so loopback
/// traffic stays on the loopback interface whatever the environment.
fn loopback_transport() -> Arc<dyn a4mp::Transport> {
    Arc::new(a4mp::ReqwestTransport::with_client(
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("client"),
    ))
}

/// The canned OpenAI chat-completions answer.
fn openai_reply() -> serde_json::Value {
    serde_json::json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 0,
        "model": "vendor-model-1",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "pong"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4}
    })
}

/// A custody port holding `credentials` in one lease, each authorized
/// scope carrying exactly its own credential — the host-authorized shape
/// every leased-auth route resolves through.
fn scoped_leases(credentials: &[(&str, &[u8], &str)]) -> Arc<Leases> {
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let epoch_id = epoch.current.lock().unwrap().clone();
    let leases = Arc::new(Leases::disconnected());
    for (credential_id, _, scope) in credentials {
        leases
            .authorize_scope(scope, [credential_id])
            .expect("authorize");
    }
    let material: Vec<(&str, &[u8])> = credentials
        .iter()
        .map(|(id, secret, _)| (*id, *secret))
        .collect();
    leases
        .install_handoff(&handoff_document(&epoch_id, &material), epoch)
        .expect("install");
    leases
}

/// Load one endpoint route whose base URL is the mock upstream plus
/// `base_path` into a scope-authorized, lease-backed router, serve
/// `models.list` then one `chat.complete` for it, and return the replies
/// plus what the upstream received.
async fn serve_endpoint_route(
    route: serde_json::Value,
    base_path: &str,
    reply: serde_json::Value,
) -> (Vec<serde_json::Value>, Received) {
    let (addr, upstream) = mock_upstream(reply);
    let mut route = route;
    route["endpoint"]["baseUrl"] = format!("http://{addr}{base_path}").into();
    let credential_id = uuid::Uuid::new_v4().to_string();
    let leases = if matches!(route["auth"].as_str(), Some("api-key" | "bearer")) {
        route["credentialScope"] = "vendor-scope".into();
        scoped_leases(&[(&credential_id, b"test-credential-material", "vendor-scope")])
    } else {
        Arc::new(Leases::disconnected())
    };
    let mut router = Router::with_leases(loopback_transport(), leases);
    router
        .load_routes(&serde_json::json!({ "routes": [route] }))
        .expect("endpoint route declares");
    let service = Service::new(router, Meter::unmetered());
    let body = serde_json::json!({
        "model": "vendor-chat",
        "messages": [{"role": "user", "content": "ping"}]
    });
    let mut input = request_line(1, "models.list", serde_json::json!({}));
    input.extend(request_line(2, "chat.complete", chat_params(body, None)));
    let replies = run(&service, &input).await;
    (replies, upstream.join().expect("upstream thread"))
}

#[tokio::test]
async fn an_endpoint_route_forwards_to_an_uncatalogued_vendor() {
    let (replies, received) = serve_endpoint_route(
        serde_json::json!({
            "model": "vendor-chat",
            "endpoint": {"protocol": "openai-chat-completions"},
            "auth": "api-key",
            "authHeader": "authorization",
            "upstreamModel": "vendor-model-1"
        }),
        "/v1",
        openai_reply(),
    )
    .await;

    // The upstream saw the protocol path under the declared base, the
    // rewritten model and the leased key in a4mp's placement.
    assert_eq!(received.request_line, "POST /v1/chat/completions HTTP/1.1");
    assert_eq!(received.body["model"], "vendor-model-1");
    assert_eq!(
        received.header("authorization"),
        Some("Bearer test-credential-material")
    );

    let listed = reply_for(&replies, 1);
    let entry = &listed["result"]["models"][0];
    assert_eq!(entry["id"], "vendor-chat");
    assert_eq!(entry["protocol"], "openai-chat-completions");
    assert_eq!(entry["auth"], "api-key");
    assert_eq!(entry["authHeader"], "authorization");
    assert!(
        entry["endpoint"]
            .as_str()
            .expect("endpoint")
            .starts_with("127.0.0.1:")
    );
    assert!(entry.get("provider").is_none(), "{entry}");
    // No projection or reply ever carries the secret.
    for reply in &replies {
        assert!(
            !reply.to_string().contains("test-credential-material"),
            "{reply}"
        );
    }

    let answer = reply_for(&replies, 2);
    assert_eq!(
        answer["result"]["body"]["choices"][0]["message"]["content"], "pong",
        "{answer}"
    );
}

#[tokio::test]
async fn an_endpoint_route_speaks_the_declared_protocol_family() {
    let (replies, received) = serve_endpoint_route(
        serde_json::json!({
            "model": "vendor-chat",
            "endpoint": {"protocol": "anthropic-messages"},
            "auth": "api-key",
            "authHeader": "x-api-key",
            "upstreamModel": "vendor-messages-1"
        }),
        // a4mp's Messages adapter joins `v1/messages` onto the base.
        "",
        serde_json::json!({
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "vendor-messages-1",
            "content": [{"type": "text", "text": "pong"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 3, "output_tokens": 1}
        }),
    )
    .await;

    // An OpenAI-dialect caller reaches an Anthropic-protocol vendor: the
    // adapter speaks Messages and carries the key as `x-api-key`.
    assert_eq!(received.request_line, "POST /v1/messages HTTP/1.1");
    assert_eq!(received.body["model"], "vendor-messages-1");
    assert_eq!(
        received.header("x-api-key"),
        Some("test-credential-material")
    );
    assert_eq!(received.header("authorization"), None);
    let answer = reply_for(&replies, 2);
    assert_eq!(
        answer["result"]["body"]["choices"][0]["message"]["content"], "pong",
        "{answer}"
    );
}

#[test]
fn the_binary_serves_an_endpoint_route_from_its_config() {
    let (addr, upstream) = mock_upstream(openai_reply());
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("routes.json");
    let routes = serde_json::json!({"routes": [{
        "model": "vendor-chat",
        "endpoint": {"baseUrl": format!("http://{addr}/v1"), "protocol": "openai-chat-completions"},
        "upstreamModel": "vendor-model-1"
    }]});
    std::fs::write(&config, routes.to_string()).expect("config");
    let body = serde_json::json!({
        "model": "vendor-chat",
        "messages": [{"role": "user", "content": "ping"}]
    });
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_fairliny"))
        .args(["serve", "--no-meter", "--config"])
        .arg(&config)
        // The sidecar's transport honors proxy settings; loopback traffic
        // must not leave through one.
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn fairliny");
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().expect("stdin");
        stdin
            .write_all(&request_line(1, "chat.complete", chat_params(body, None)))
            .expect("request line");
    }
    let output = child.wait_with_output().expect("exit");
    let received = upstream.join().expect("upstream thread");
    assert_eq!(received.body["model"], "vendor-model-1");
    assert_eq!(received.header("authorization"), None);
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    let reply: serde_json::Value =
        serde_json::from_str(stdout.lines().next().expect("reply line")).expect("reply json");
    assert_eq!(reply["id"], 1);
    assert_eq!(
        reply["result"]["body"]["choices"][0]["message"]["content"], "pong",
        "{reply}"
    );
}

#[tokio::test]
async fn each_scoped_route_resolves_only_the_credentials_its_host_authorized() {
    // Two vendors, two authorized scopes, one handoff carrying both
    // keys: each route resolves only the credential its host authorized
    // for its scope — the auth mechanism alone never picks one.
    let (addr_a, upstream_a) = mock_upstream(openai_reply());
    let (addr_b, upstream_b) = mock_upstream(openai_reply());
    let id_a = uuid::Uuid::new_v4().to_string();
    let id_b = uuid::Uuid::new_v4().to_string();
    let leases = scoped_leases(&[
        (&id_a, b"key-for-vendor-a", "vendor-a"),
        (&id_b, b"key-for-vendor-b", "vendor-b"),
    ]);
    let mut router = Router::with_leases(loopback_transport(), leases);
    router
        .load_routes(&serde_json::json!({"routes": [
            {"model": "a-chat",
             "endpoint": {"baseUrl": format!("http://{addr_a}/v1"), "protocol": "openai-chat-completions"},
             "auth": "api-key", "credentialScope": "vendor-a"},
            {"model": "b-chat",
             "endpoint": {"baseUrl": format!("http://{addr_b}/v1"), "protocol": "openai-chat-completions"},
             "auth": "api-key", "credentialScope": "vendor-b"}
        ]}))
        .expect("routes");
    let service = Service::new(router, Meter::unmetered());
    let body = |model: &str| serde_json::json!({"model": model, "messages": [{"role": "user", "content": "ping"}]});
    let mut input = request_line(1, "chat.complete", chat_params(body("a-chat"), None));
    input.extend(request_line(
        2,
        "chat.complete",
        chat_params(body("b-chat"), None),
    ));
    let replies = run(&service, &input).await;
    assert!(reply_for(&replies, 1).get("error").is_none());
    assert!(reply_for(&replies, 2).get("error").is_none());
    let a = upstream_a.join().expect("upstream a");
    let b = upstream_b.join().expect("upstream b");
    assert_eq!(a.header("authorization"), Some("Bearer key-for-vendor-a"));
    assert_eq!(b.header("authorization"), Some("Bearer key-for-vendor-b"));
}

#[tokio::test]
async fn a_scope_whose_credential_the_handoff_lacks_fails_closed() {
    // The scope is authorized — for a credential id the installed
    // handoff does not carry. The scope's slot is empty, so every
    // forward refuses with the lease contract's unavailable code rather
    // than borrowing the lease's other credential.
    let (addr, _upstream) = mock_upstream(openai_reply());
    let real_id = uuid::Uuid::new_v4().to_string();
    let ghost_id = uuid::Uuid::new_v4().to_string();
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let epoch_id = epoch.current.lock().unwrap().clone();
    let leases = Arc::new(Leases::disconnected());
    leases
        .authorize_scope("vendor-scope", [&ghost_id])
        .expect("authorize");
    leases
        .install_handoff(
            &handoff_document(&epoch_id, &[(&real_id, b"the-other-key")]),
            epoch,
        )
        .expect("install");
    let mut router = Router::with_leases(loopback_transport(), leases);
    router
        .load_routes(&serde_json::json!({"routes": [{
            "model": "vendor-chat",
            "endpoint": {"baseUrl": format!("http://{addr}/v1"), "protocol": "openai-chat-completions"},
            "auth": "api-key", "credentialScope": "vendor-scope"
        }]}))
        .expect("declares");
    let service = Service::new(router, Meter::unmetered());
    let body = serde_json::json!({
        "model": "vendor-chat",
        "messages": [{"role": "user", "content": "ping"}]
    });
    let input = request_line(1, "chat.complete", chat_params(body, None));
    let replies = run(&service, &input).await;
    let reply = reply_for(&replies, 1);
    assert!(
        reply["error"]
            .as_str()
            .expect("error")
            .contains("credential_lease_unavailable"),
        "{reply}"
    );
}

#[test]
fn a_route_naming_a_scope_the_host_never_authorized_refuses_to_declare() {
    // `credentialScope` names an entry in `credentialScopes`; a route
    // pointing at nothing fails at startup, not at first forward.
    let leases = scoped_leases(&[(
        &uuid::Uuid::new_v4().to_string(),
        b"test-credential-material",
        "vendor-scope",
    )]);
    let mut router = Router::with_leases(loopback_transport(), leases);
    let error = router
        .load_routes(&serde_json::json!({"routes": [{
            "model": "m",
            "endpoint": {"baseUrl": "https://api.vendor.example", "protocol": "openai-chat-completions"},
            "auth": "api-key", "credentialScope": "misspelled-scope"
        }]}))
        .expect_err("unauthorized scope");
    assert!(error.to_string().contains("unauthorized"), "{error}");
}

#[test]
fn a_scoped_route_is_refused_when_the_resolver_cannot_enforce_it() {
    // `Router::new`/`with_catalog` run a host-supplied resolver that
    // owns its own credential dispatch — it cannot honor a declared
    // credential scope, so the declaration refuses rather than
    // projecting a scope resolution would silently ignore.
    let endpoint = serde_json::json!({"baseUrl": "https://api.vendor.example", "protocol": "openai-chat-completions"});
    let mut router = Router::new(
        Arc::new(a4mp::ReqwestTransport::new()),
        Arc::new(a4mp::NoCredentials),
    );
    let error = router
        .load_routes(&serde_json::json!({"routes": [{
            "model": "m", "endpoint": endpoint,
            "auth": "api-key", "credentialScope": "vendor-scope"
        }]}))
        .expect_err("scope without the lease port");
    assert!(error.to_string().contains("lease port"), "{error}");
    assert!(router.credential_scope("m").is_none());
    assert!(router.resolve("m").is_err());

    // A catalog profile route refuses the same way — the refusal is
    // about enforcement, not the surface shape.
    let route = Route {
        provider: a4mp::ProviderId::new("openai"),
        protocol: None,
        region: None,
        auth: a4mp::AuthKind::ApiKey,
        upstream_model: "gpt".to_owned(),
        vars: Default::default(),
    };
    let error = router
        .add_route_scoped("m", route, "vendor-scope")
        .expect_err("scoped profile route without the lease port");
    assert!(error.to_string().contains("lease port"), "{error}");
    assert!(router.resolve("m").is_err());
}

#[tokio::test]
async fn clearing_or_replacing_the_lease_reaches_every_scoped_surface() {
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let epoch_id = epoch.current.lock().unwrap().clone();
    let id = uuid::Uuid::new_v4().to_string();
    let leases = Leases::disconnected();
    leases
        .authorize_scope("vendor-scope", [&id])
        .expect("authorize");
    leases
        .install_handoff(&handoff_document(&epoch_id, &[(&id, b"vendor-key")]), epoch)
        .expect("install");
    let target = scoped_target();
    leases
        .replace_target_scopes([(&target, "vendor-scope")])
        .expect("bind");
    resolve_for_target(&leases, &target)
        .await
        .expect("scoped resolve");
    resolve_unscoped(&leases).await.expect("unscoped resolve");

    // Lock-down retires the whole state: scoped and unscoped surfaces
    // fail closed on the very next resolution.
    leases.clear();
    for result in [
        resolve_for_target(&leases, &target).await,
        resolve_unscoped(&leases).await,
    ] {
        let error = result.expect_err("cleared");
        assert!(
            error.to_string().contains("credential_lease_unavailable"),
            "{error}"
        );
    }

    // A host-driven replacement lands whole: the unscoped slot answers
    // the new lease while the scoped surface fails closed rather than
    // keeping credentials the new lease never granted.
    let replacement_epoch = uuid::Uuid::new_v4().to_string();
    let mut credentials = BTreeMap::new();
    credentials.insert(
        ProviderCredential::ApiKey,
        vec![
            LeasedCredential::new(
                uuid::Uuid::new_v4().to_string(),
                SecretBytes::try_from_bytes(b"fresh-key".to_vec()).expect("secret"),
                None,
            )
            .expect("credential"),
        ],
    );
    let lease = credential_lease::CredentialLease::new(
        credentials,
        Duration::from_secs(3600),
        replacement_epoch.clone(),
        Arc::new(Epochs {
            current: Mutex::new(replacement_epoch),
        }),
    )
    .expect("lease");
    leases.install_lease(lease);
    let error = resolve_for_target(&leases, &target)
        .await
        .expect_err("scoped fails closed after replacement");
    assert!(
        error.to_string().contains("credential_lease_unavailable"),
        "{error}"
    );
    match resolve_unscoped(&leases)
        .await
        .expect("replacement resolves")
    {
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), "fresh-key"),
        other => panic!("expected an api-key credential: {other:?}"),
    }
}

#[tokio::test]
async fn authorizing_a_scope_late_never_extends_the_installed_expiry() {
    // The installed lease's expiry was fixed when the handoff landed.
    // Authorizing a scope after that expiry must not mint a fresh
    // duration — it fails closed rather than restoring access.
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let epoch_id = epoch.current.lock().unwrap().clone();
    let id = uuid::Uuid::new_v4().to_string();
    let leases = Leases::disconnected();
    leases
        .install_handoff(
            &handoff_document_for(&epoch_id, &[(&id, b"vendor-key")], 1),
            epoch,
        )
        .expect("install");
    std::thread::sleep(Duration::from_millis(1300));
    leases
        .authorize_scope("vendor-scope", [&id])
        .expect("authorize");
    let target = scoped_target();
    leases
        .replace_target_scopes([(&target, "vendor-scope")])
        .expect("bind");
    let error = resolve_for_target(&leases, &target)
        .await
        .expect_err("no restarted lease");
    assert!(
        error.to_string().contains("credential_lease_unavailable"),
        "{error}"
    );
    let error = resolve_unscoped(&leases)
        .await
        .expect_err("install expiry reached");
    assert!(
        error.to_string().contains("credential_lease_expired"),
        "{error}"
    );
}

#[tokio::test]
async fn a_reinstalled_handoff_replaces_the_whole_lease_state() {
    // Authorized before the first install, the scope re-materializes
    // from each installed document: after the hot-apply it resolves
    // only the credentials the new document carries, under the new
    // epoch source.
    let id_a = uuid::Uuid::new_v4().to_string();
    let id_b = uuid::Uuid::new_v4().to_string();
    let epoch_a = uuid::Uuid::new_v4().to_string();
    let epoch_b = uuid::Uuid::new_v4().to_string();
    let leases = Leases::disconnected();
    leases
        .authorize_scope("vendor-scope", [&id_a, &id_b])
        .expect("authorize");
    leases
        .install_handoff(
            &handoff_document(&epoch_a, &[(&id_a, b"key-a")]),
            Arc::new(Epochs {
                current: Mutex::new(epoch_a),
            }),
        )
        .expect("install a");
    let target = scoped_target();
    leases
        .replace_target_scopes([(&target, "vendor-scope")])
        .expect("bind");
    match resolve_for_target(&leases, &target)
        .await
        .expect("scoped a")
    {
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), "key-a"),
        other => panic!("expected an api-key credential: {other:?}"),
    }
    leases
        .install_handoff(
            &handoff_document(&epoch_b, &[(&id_b, b"key-b")]),
            Arc::new(Epochs {
                current: Mutex::new(epoch_b),
            }),
        )
        .expect("install b");
    match resolve_for_target(&leases, &target)
        .await
        .expect("scoped b")
    {
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), "key-b"),
        other => panic!("expected an api-key credential: {other:?}"),
    }
    match resolve_unscoped(&leases).await.expect("unscoped b") {
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), "key-b"),
        other => panic!("expected an api-key credential: {other:?}"),
    }
}

#[test]
fn a_routes_member_must_be_an_array_and_the_whole_table_must_validate() {
    let mut router = Router::new(
        Arc::new(a4mp::ReqwestTransport::new()),
        Arc::new(Leases::disconnected()),
    );
    // A present `routes` member that is not an array refuses — it can
    // never masquerade as an empty route table.
    for document in [
        serde_json::json!({"routes": {"model": "chat"}}),
        serde_json::json!({"routes": "chat"}),
        serde_json::json!({"routes": 7}),
    ] {
        assert!(router.load_routes(&document).is_err(), "{document}");
    }
    // A bad entry after a good one refuses the whole document: the
    // earlier entry is never committed, and no scope registration
    // survives either.
    let document = serde_json::json!({"routes": [
        {"model": "good",
         "endpoint": {"baseUrl": "https://a.example", "protocol": "openai-chat-completions"},
         "auth": "none"},
        {"model": "bad"}
    ]});
    assert!(router.load_routes(&document).is_err());
    assert!(router.resolve("good").is_err());
    assert!(router.resolve("bad").is_err());
}

#[test]
fn replacing_a_route_releases_its_scope_binding() {
    // A scoped route replaced by an unscoped one drops its projection
    // and its surface binding — reusing the freed surface under a
    // different scope cannot conflict with what the old route left.
    let id_a = uuid::Uuid::new_v4().to_string();
    let id_b = uuid::Uuid::new_v4().to_string();
    let leases = Arc::new(Leases::disconnected());
    leases.authorize_scope("scope-a", [&id_a]).expect("a");
    leases.authorize_scope("scope-b", [&id_b]).expect("b");
    let mut router = Router::with_leases(loopback_transport(), leases);
    let endpoint = || {
        EndpointRoute::from_document(&serde_json::json!({
            "model": "m",
            "endpoint": {"baseUrl": "https://api.vendor.example/v1", "protocol": "openai-chat-completions"},
            "auth": "api-key"
        }))
        .expect("route")
        .1
    };
    router
        .add_endpoint_route_scoped("m", endpoint(), "scope-a")
        .expect("scoped m");
    assert_eq!(router.credential_scope("m"), Some("scope-a"));
    // Re-scoping the same model onto the same surface replaces the
    // binding rather than conflicting with it.
    router
        .add_endpoint_route_scoped("m", endpoint(), "scope-b")
        .expect("rescoped m");
    assert_eq!(router.credential_scope("m"), Some("scope-b"));
    // Replacing it with an unscoped route frees the surface entirely.
    let unscoped = EndpointRoute::from_document(&serde_json::json!({
        "model": "m",
        "endpoint": {"baseUrl": "https://other.vendor.example/v1", "protocol": "openai-chat-completions"}
    }))
    .expect("route")
    .1;
    router
        .add_endpoint_route("m", unscoped)
        .expect("unscoped m");
    assert_eq!(router.credential_scope("m"), None);
    router
        .add_endpoint_route_scoped("m2", endpoint(), "scope-a")
        .expect("the freed surface binds a new scope");
    assert_eq!(router.credential_scope("m2"), Some("scope-a"));
}
