//! The outward face under test: the NDJSON loop, the route binding, the
//! metering composition, and the lease's epoch contract — against stub
//! adapters or a loopback mock upstream, so nothing here ever touches a
//! real provider.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use credential_lease::{CredentialHandoff, LeaseEpochSource, LeasedCredential, SecretBytes};
use fairliny_gateway::leases::{Leases, ProviderCredential, ScopeOwner};
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
    handoff_document(epoch, &[(&id, secret_a().as_bytes())])
}

/// Scope names for lease fixtures — one generated identifier per name
/// for the whole test binary so fixtures never carry a static scope
/// string that reads as checked-in material.
fn vendor_scope() -> &'static str {
    static SCOPE: OnceLock<String> = OnceLock::new();
    SCOPE.get_or_init(|| uuid::Uuid::new_v4().to_string())
}

fn scope_a() -> &'static str {
    static SCOPE: OnceLock<String> = OnceLock::new();
    SCOPE.get_or_init(|| uuid::Uuid::new_v4().to_string())
}

fn scope_b() -> &'static str {
    static SCOPE: OnceLock<String> = OnceLock::new();
    SCOPE.get_or_init(|| uuid::Uuid::new_v4().to_string())
}

/// Secret material for handoff fixtures — generated once per name so
/// no credential-shaped literal ever sits in the tree.
fn secret_a() -> &'static str {
    static SECRET: OnceLock<String> = OnceLock::new();
    SECRET.get_or_init(|| uuid::Uuid::new_v4().to_string())
}

fn secret_b() -> &'static str {
    static SECRET: OnceLock<String> = OnceLock::new();
    SECRET.get_or_init(|| uuid::Uuid::new_v4().to_string())
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
    router
        .register_adapter("ping-model", "upstream-ping", adapter)
        .expect("register adapter");
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
async fn a_lost_reply_still_drains_and_persists_metering() {
    // The reply never reaches the wire — the serve fails — but the
    // settlement the forward spawned is drained and the counters
    // persist before the error returns: a lost reply never forfeits
    // the journal.
    let dir = tempfile::tempdir().expect("tempdir");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let service = Service::new(
        test_router(resolver_with_lease(), Arc::clone(&requests)),
        test_meter(dir.path()),
    );
    let (output, reader) = tokio::io::duplex(64 * 1024);
    drop(reader);
    let input = request_line(
        1,
        "chat.complete",
        chat_params(
            serde_json::json!({
                "model": "ping-model",
                "messages": [{"role": "user", "content": "hi"}]
            }),
            Some("caller"),
        ),
    );
    assert!(
        service.serve(&input[..], output).await.is_err(),
        "a lost reply is a serve failure"
    );
    // No flush_metering call here — the serve itself drained the
    // settle set and persisted before returning the error.
    assert_eq!(service.settle_len(), 0, "settlements drained");
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
        // The reaper keeps the tracked set proportional to live work —
        // never one retained task per forwarded request. A settle spans
        // a blocking-pool hop of real I/O and finished tasks only leave
        // the set when a dispatch reaps them, so drive light dispatches
        // until the real work drains — bounded by a deadline, not a set
        // size at one instant.
        let converged = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                service
                    .dispatch(
                        serde_json::json!(null),
                        Some("models.list"),
                        &serde_json::json!({}),
                    )
                    .await;
                if service.settle_len() <= 1 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await;
        assert!(
            converged.is_ok(),
            "settlement set drains with the work: {}",
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
    router
        .register_adapter(
            "hang-model",
            "upstream-hang",
            Arc::new(HungAdapter {
                target: a4mp::ServiceTarget::new(
                    "stub",
                    a4mp::Protocol::Other("stub".to_owned()),
                    url::Url::parse("https://stub.invalid/").expect("url"),
                ),
            }),
        )
        .expect("register adapter");
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
                "routes": [{"model": "chat", "provider": "ollama",
                            "auth": format!("oauth-{}", uuid::Uuid::new_v4())}]
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
                "vars": {"endpoint": "http://localhost:11434"}
            }]
        }))
        .expect("routes");
    let bound = router.resolve("local-chat").expect("bound");
    assert_eq!(bound.upstream_model, "llama3.1");
    assert_eq!(bound.provider.as_str(), "ollama");
}

#[tokio::test]
async fn meter_open_over_a_fresh_state_root_persists_admissions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let meter = Meter::open(dir.path()).expect("meter");
    meter.admit_request("agent", "model").await;
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
        .add_route_scoped("model", route, vendor_scope())
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
        route["credentialScope"] = vendor_scope().into();
        scoped_leases(&[(&credential_id, secret_a().as_bytes(), vendor_scope())])
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
        Some(format!("Bearer {}", secret_a()).as_str())
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
        assert!(!reply.to_string().contains(secret_a()), "{reply}");
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
    assert_eq!(received.header("x-api-key"), Some(secret_a()));
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
    let scope_a = uuid::Uuid::new_v4().to_string();
    let scope_b = uuid::Uuid::new_v4().to_string();
    let leases = scoped_leases(&[
        (&id_a, secret_a().as_bytes(), &scope_a),
        (&id_b, secret_b().as_bytes(), &scope_b),
    ]);
    let mut router = Router::with_leases(loopback_transport(), leases);
    router
        .load_routes(&serde_json::json!({"routes": [
            {"model": "a-chat",
             "endpoint": {"baseUrl": format!("http://{addr_a}/v1"), "protocol": "openai-chat-completions"},
             "auth": "api-key", "credentialScope": scope_a},
            {"model": "b-chat",
             "endpoint": {"baseUrl": format!("http://{addr_b}/v1"), "protocol": "openai-chat-completions"},
             "auth": "api-key", "credentialScope": scope_b}
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
    let bearer_a = format!("Bearer {}", secret_a());
    let bearer_b = format!("Bearer {}", secret_b());
    assert_eq!(a.header("authorization"), Some(bearer_a.as_str()));
    assert_eq!(b.header("authorization"), Some(bearer_b.as_str()));
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
    let scope = uuid::Uuid::new_v4().to_string();
    leases
        .authorize_scope(&scope, [&ghost_id])
        .expect("authorize");
    leases
        .install_handoff(
            &handoff_document(&epoch_id, &[(&real_id, secret_a().as_bytes())]),
            epoch,
        )
        .expect("install");
    let mut router = Router::with_leases(loopback_transport(), leases);
    router
        .load_routes(&serde_json::json!({"routes": [{
            "model": "vendor-chat",
            "endpoint": {"baseUrl": format!("http://{addr}/v1"), "protocol": "openai-chat-completions"},
            "auth": "api-key", "credentialScope": scope
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
        secret_a().as_bytes(),
        vendor_scope(),
    )]);
    let mut router = Router::with_leases(loopback_transport(), leases);
    let error = router
        .load_routes(&serde_json::json!({"routes": [{
            "model": "m",
            "endpoint": {"baseUrl": "https://api.vendor.example", "protocol": "openai-chat-completions"},
            "auth": "api-key", "credentialScope": uuid::Uuid::new_v4().to_string()
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
            "auth": "api-key", "credentialScope": vendor_scope()
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
        .add_route_scoped("m", route, vendor_scope())
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
        .authorize_scope(vendor_scope(), [&id])
        .expect("authorize");
    leases
        .install_handoff(
            &handoff_document(&epoch_id, &[(&id, secret_a().as_bytes())]),
            epoch,
        )
        .expect("install");
    let target = scoped_target();
    leases
        .replace_target_scopes(
            ScopeOwner::new(),
            [(&target, vendor_scope(), ProviderCredential::ApiKey)],
        )
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
                SecretBytes::try_from_bytes(secret_a().as_bytes().to_vec()).expect("secret"),
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
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), secret_a()),
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
            &handoff_document_for(&epoch_id, &[(&id, secret_a().as_bytes())], 1),
            epoch,
        )
        .expect("install");
    std::thread::sleep(Duration::from_millis(1300));
    leases
        .authorize_scope(vendor_scope(), [&id])
        .expect("authorize");
    let target = scoped_target();
    leases
        .replace_target_scopes(
            ScopeOwner::new(),
            [(&target, vendor_scope(), ProviderCredential::ApiKey)],
        )
        .expect("bind");
    let error = resolve_for_target(&leases, &target)
        .await
        .expect_err("no restarted lease");
    assert!(
        error.to_string().contains("credential_lease_expired"),
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
        .authorize_scope(vendor_scope(), [&id_a, &id_b])
        .expect("authorize");
    leases
        .install_handoff(
            &handoff_document(&epoch_a, &[(&id_a, secret_a().as_bytes())]),
            Arc::new(Epochs {
                current: Mutex::new(epoch_a),
            }),
        )
        .expect("install a");
    let target = scoped_target();
    leases
        .replace_target_scopes(
            ScopeOwner::new(),
            [(&target, vendor_scope(), ProviderCredential::ApiKey)],
        )
        .expect("bind");
    match resolve_for_target(&leases, &target)
        .await
        .expect("scoped a")
    {
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), secret_a()),
        other => panic!("expected an api-key credential: {other:?}"),
    }
    leases
        .install_handoff(
            &handoff_document(&epoch_b, &[(&id_b, secret_b().as_bytes())]),
            Arc::new(Epochs {
                current: Mutex::new(epoch_b),
            }),
        )
        .expect("install b");
    match resolve_for_target(&leases, &target)
        .await
        .expect("scoped b")
    {
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), secret_b()),
        other => panic!("expected an api-key credential: {other:?}"),
    }
    match resolve_unscoped(&leases).await.expect("unscoped b") {
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), secret_b()),
        other => panic!("expected an api-key credential: {other:?}"),
    }
}

#[test]
fn a_routes_member_must_be_an_array_and_the_whole_table_must_validate() {
    let mut router = Router::new(
        Arc::new(a4mp::ReqwestTransport::new()),
        Arc::new(Leases::disconnected()),
    );
    // A document that is not a JSON object refuses — an array, scalar
    // or `null` has no `routes` member and can never masquerade as an
    // empty route table.
    for document in [
        serde_json::json!([]),
        serde_json::json!(5),
        serde_json::json!("routes"),
        serde_json::Value::Null,
    ] {
        assert!(router.load_routes(&document).is_err(), "{document}");
    }
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
    leases.authorize_scope(scope_a(), [&id_a]).expect("a");
    leases.authorize_scope(scope_b(), [&id_b]).expect("b");
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
        .add_endpoint_route_scoped("m", endpoint(), scope_a())
        .expect("scoped m");
    assert_eq!(router.credential_scope("m"), Some(scope_a()));
    // Re-scoping the same model onto the same surface replaces the
    // binding rather than conflicting with it.
    router
        .add_endpoint_route_scoped("m", endpoint(), scope_b())
        .expect("rescoped m");
    assert_eq!(router.credential_scope("m"), Some(scope_b()));
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
        .add_endpoint_route_scoped("m2", endpoint(), scope_a())
        .expect("the freed surface binds a new scope");
    assert_eq!(router.credential_scope("m2"), Some(scope_a()));
}

#[tokio::test]
async fn a_late_scoped_slot_dies_at_the_install_deadline() {
    // The scope materializes mid-lease: the document's own duration
    // would let its slot outlive the install's expiry, but one absolute
    // deadline covers every slot the install produced — the minted slot
    // resolves before it and refuses after it.
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let epoch_id = epoch.current.lock().unwrap().clone();
    let id = uuid::Uuid::new_v4().to_string();
    let leases = Leases::disconnected();
    leases
        .install_handoff(
            &handoff_document_for(&epoch_id, &[(&id, secret_a().as_bytes())], 3),
            epoch,
        )
        .expect("install");
    // Authorized while well over a second remains, the slot mints and
    // resolves — the remaining lifetime gates creation, not use.
    std::thread::sleep(Duration::from_millis(1200));
    leases
        .authorize_scope(vendor_scope(), [&id])
        .expect("authorize");
    let target = scoped_target();
    leases
        .replace_target_scopes(
            ScopeOwner::new(),
            [(&target, vendor_scope(), ProviderCredential::ApiKey)],
        )
        .expect("bind");
    match resolve_for_target(&leases, &target)
        .await
        .expect("scoped resolves inside the lease")
    {
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), secret_a()),
        other => panic!("expected an api-key credential: {other:?}"),
    }
    // Past the install's deadline the slot must not answer — the
    // document's 3-second duration would otherwise keep it alive a full
    // second longer.
    std::thread::sleep(Duration::from_millis(2200));
    let error = resolve_for_target(&leases, &target)
        .await
        .expect_err("the install's expiry covers scoped slots");
    assert!(error.to_string().contains("credential_lease_"), "{error}");
}

#[tokio::test]
async fn reauthorizing_a_scope_commits_the_new_ids_with_their_slot() {
    // The authorized id set and the materialized slot land as one
    // commit: re-authorizing the scope swaps both together, so the next
    // resolution answers only the latest authorized credential — never
    // a recorded set beside an outdated slot.
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let epoch_id = epoch.current.lock().unwrap().clone();
    let id_a = uuid::Uuid::new_v4().to_string();
    let id_b = uuid::Uuid::new_v4().to_string();
    let leases = Leases::disconnected();
    leases
        .install_handoff(
            &handoff_document(
                &epoch_id,
                &[
                    (&id_a, secret_a().as_bytes()),
                    (&id_b, secret_b().as_bytes()),
                ],
            ),
            epoch,
        )
        .expect("install");
    leases
        .authorize_scope(vendor_scope(), [&id_a])
        .expect("authorize");
    let target = scoped_target();
    leases
        .replace_target_scopes(
            ScopeOwner::new(),
            [(&target, vendor_scope(), ProviderCredential::ApiKey)],
        )
        .expect("bind");
    for (id, secret) in [
        (&id_a, secret_a()),
        (&id_b, secret_b()),
        (&id_a, secret_a()),
    ] {
        leases
            .authorize_scope(vendor_scope(), [id])
            .expect("authorize");
        match resolve_for_target(&leases, &target)
            .await
            .expect("scoped resolve")
        {
            a4mp::Credential::ApiKey(resolved) => assert_eq!(resolved.expose(), secret),
            other => panic!("expected an api-key credential: {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_sibling_routers_publish_never_erases_the_live_bindings() {
    // Two routers share one lease port. Router A's scoped route binds a
    // scope the handoff does not carry, so its surface must keep failing
    // closed; a whole-table publish from router B — even one carrying no
    // scoped bindings at all — retiring it would drop the surface back
    // to the unscoped pool, which resolves.
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let epoch_id = epoch.current.lock().unwrap().clone();
    let id = uuid::Uuid::new_v4().to_string();
    let ghost = uuid::Uuid::new_v4().to_string();
    let leases = Arc::new(Leases::disconnected());
    leases
        .authorize_scope("ghost-scope", [&ghost])
        .expect("ghost scope");
    leases
        .authorize_scope(vendor_scope(), [&id])
        .expect("vendor scope");
    leases
        .install_handoff(
            &handoff_document(&epoch_id, &[(&id, secret_a().as_bytes())]),
            epoch,
        )
        .expect("install");
    let endpoint = |base_url: &str| {
        EndpointRoute::from_document(&serde_json::json!({
            "model": "m",
            "endpoint": {"baseUrl": base_url, "protocol": "openai-chat-completions"},
            "auth": "api-key"
        }))
        .expect("route")
        .1
    };

    let mut router_a = Router::with_leases(loopback_transport(), Arc::clone(&leases));
    router_a
        .add_endpoint_route_scoped(
            "m-a",
            endpoint("https://a.vendor.example/v1"),
            "ghost-scope",
        )
        .expect("declare a");
    let surface_a = router_a
        .resolve("m-a")
        .expect("resolve a")
        .adapter
        .target()
        .clone();

    // Router B's publish — a credential-free route with an empty scope
    // table — must leave A's slice alone: the ghost-scoped surface still
    // fails closed instead of slipping into the unscoped pool.
    let mut router_b = Router::with_leases(loopback_transport(), Arc::clone(&leases));
    router_b
        .add_endpoint_route(
            "m-b",
            EndpointRoute::from_document(&serde_json::json!({
                "model": "m-b",
                "endpoint": {"baseUrl": "https://b.vendor.example/v1", "protocol": "openai-chat-completions"}
            }))
            .expect("route")
            .1,
        )
        .expect("declare b");
    let error = resolve_for_target(&leases, &surface_a)
        .await
        .expect_err("a scoped surface without a binding never resolves unscoped");
    assert!(
        error.to_string().contains("credential_lease_unavailable"),
        "{error}"
    );

    // And a surface already bound by another owner refuses a different
    // scope at declaration — resolution could never tell the two
    // bindings apart, so the conflict dies before the route commits.
    let error = router_b
        .add_endpoint_route_scoped(
            "m-c",
            endpoint("https://a.vendor.example/v1"),
            vendor_scope(),
        )
        .expect_err("a foreign-held surface refuses a conflicting scope");
    assert!(error.to_string().contains("conflict"), "{error}");
    assert!(router_b.resolve("m-c").is_err());
}

#[test]
fn a_rejected_scope_table_authorizes_nothing() {
    // The whole credentialScopes table validates and stages before any
    // of it publishes: a malformed later entry refuses the document
    // without leaving the earlier valid entry authorized — otherwise a
    // rejected table would already have changed which credentials live
    // routes resolve.
    let id = uuid::Uuid::new_v4().to_string();
    let leases = Leases::disconnected();
    let document = serde_json::json!({
        "credentialScopes": {"good": [id], "bad": "not-an-array"}
    });
    let error = leases
        .authorize_scopes(&document)
        .expect_err("a malformed entry rejects the table");
    assert!(
        error.to_string().contains("credential_scope_invalid"),
        "{error}"
    );
    assert!(!leases.scope_authorized("good"));
    let valid = serde_json::json!({"credentialScopes": {"good": [id]}});
    leases.authorize_scopes(&valid).expect("a clean table");
    assert!(leases.scope_authorized("good"));
}

#[test]
fn the_binary_refuses_a_non_object_config_file() {
    // A supplied config that is not a JSON object — an array, a scalar
    // or `null` — carries no `routes` member; treating it as empty
    // would start a silently unconfigured gateway, so startup refuses.
    let dir = tempfile::tempdir().expect("tempdir");
    for (name, contents) in [("array", "[]"), ("scalar", "5"), ("null", "null")] {
        let config = dir.path().join(format!("{name}.json"));
        std::fs::write(&config, contents).expect("config");
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_fairliny"))
            .args(["serve", "--no-meter", "--config"])
            .arg(&config)
            .output()
            .expect("spawn fairliny");
        assert!(!output.status.success(), "{name}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("JSON object"), "{name}: {stderr}");
    }
}

#[tokio::test]
async fn a_detached_scoped_adapter_fails_closed_when_its_binding_retires() {
    // An adapter resolve() already returned keeps its bound surface.
    // Replacing the route republishes a table that no longer binds it —
    // but the retired surface must fail closed, never slip back into
    // the unscoped pool the binding guarded it from.
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let epoch_id = epoch.current.lock().unwrap().clone();
    let id = uuid::Uuid::new_v4().to_string();
    let leases = Arc::new(Leases::disconnected());
    leases
        .authorize_scope(vendor_scope(), [&id])
        .expect("scope");
    leases
        .install_handoff(
            &handoff_document(&epoch_id, &[(&id, secret_a().as_bytes())]),
            epoch,
        )
        .expect("install");
    let endpoint = |base_url: &str| {
        EndpointRoute::from_document(&serde_json::json!({
            "model": "m",
            "endpoint": {"baseUrl": base_url, "protocol": "openai-chat-completions"},
            "auth": "api-key"
        }))
        .expect("route")
        .1
    };
    let mut router = Router::with_leases(loopback_transport(), Arc::clone(&leases));
    router
        .add_endpoint_route_scoped("m", endpoint("https://a.vendor.example/v1"), vendor_scope())
        .expect("declare");
    let surface = router
        .resolve("m")
        .expect("resolve")
        .adapter
        .target()
        .clone();
    match resolve_for_target(&leases, &surface)
        .await
        .expect("scoped while bound")
    {
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), secret_a()),
        other => panic!("expected an api-key credential: {other:?}"),
    }

    // The replacement declares no scope, so the publish retires the old
    // surface — the detached adapter fails closed on its next resolve.
    let unscoped = EndpointRoute::from_document(&serde_json::json!({
        "model": "m",
        "endpoint": {"baseUrl": "https://b.vendor.example/v1", "protocol": "openai-chat-completions"}
    }))
    .expect("route")
    .1;
    router.add_endpoint_route("m", unscoped).expect("replace");
    let error = resolve_for_target(&leases, &surface)
        .await
        .expect_err("a retired surface never falls back to unscoped");
    assert!(
        error.to_string().contains("credential_scope_retired"),
        "{error}"
    );

    // And a still-scoped route keeps its credentials: retirement marks
    // only the surfaces a republish dropped.
    router
        .add_endpoint_route_scoped(
            "m2",
            endpoint("https://a.vendor.example/v1"),
            vendor_scope(),
        )
        .expect("the retired surface binds again under its scope");
    match resolve_for_target(&leases, &surface)
        .await
        .expect("rebound scoped resolves")
    {
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), secret_a()),
        other => panic!("expected an api-key credential: {other:?}"),
    }
}

#[test]
fn a_declared_route_and_a_prebound_adapter_never_share_a_model() {
    // The prebound map resolves first and `models.list` projects both —
    // a shared name would advertise two entries while every forward
    // bypassed the declared scope. The collision refuses in both
    // directions rather than splitting the projection.
    let id = uuid::Uuid::new_v4().to_string();
    let leases = Arc::new(Leases::disconnected());
    leases
        .authorize_scope(vendor_scope(), [&id])
        .expect("scope");
    let endpoint = || {
        EndpointRoute::from_document(&serde_json::json!({
            "model": "m",
            "endpoint": {"baseUrl": "https://a.vendor.example/v1", "protocol": "openai-chat-completions"},
            "auth": "api-key"
        }))
        .expect("route")
        .1
    };
    let adapter = || {
        Arc::new(HungAdapter {
            target: stub_target(),
        }) as Arc<dyn a4mp::Adapter>
    };

    let mut router = Router::with_leases(loopback_transport(), Arc::clone(&leases));
    router
        .register_adapter("m", "upstream-m", adapter())
        .expect("prebound");
    let error = router
        .add_endpoint_route_scoped("m", endpoint(), vendor_scope())
        .expect_err("a declared route refuses a prebound name");
    assert!(error.to_string().contains("host-registered"), "{error}");
    assert!(router.credential_scope("m").is_none());

    let mut router = Router::with_leases(loopback_transport(), Arc::clone(&leases));
    router
        .add_endpoint_route_scoped("m", endpoint(), vendor_scope())
        .expect("declare");
    let error = router
        .register_adapter("m", "upstream-m", adapter())
        .expect_err("a prebound adapter refuses a declared name");
    assert!(error.to_string().contains("declared route"), "{error}");
    assert_eq!(router.credential_scope("m"), Some(vendor_scope()));
}

#[tokio::test]
async fn a_short_lease_still_materializes_its_scoped_slots() {
    // A one-second handoff authorized with less than a second left
    // still mints its scoped slot: the document's own duration carries
    // the contract's whole-second minimum and the install's absolute
    // deadline ends the mint on time. The whole-second gate is the
    // minted lease's, not the remaining lifetime's.
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let epoch_id = epoch.current.lock().unwrap().clone();
    let id = uuid::Uuid::new_v4().to_string();
    let leases = Leases::disconnected();
    leases
        .install_handoff(
            &handoff_document_for(&epoch_id, &[(&id, secret_a().as_bytes())], 1),
            epoch,
        )
        .expect("install");
    std::thread::sleep(Duration::from_millis(200));
    leases
        .authorize_scope(vendor_scope(), [&id])
        .expect("authorize");
    let target = scoped_target();
    leases
        .replace_target_scopes(
            ScopeOwner::new(),
            [(&target, vendor_scope(), ProviderCredential::ApiKey)],
        )
        .expect("bind");
    match resolve_for_target(&leases, &target)
        .await
        .expect("a positive remaining duration still mints")
    {
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), secret_a()),
        other => panic!("expected an api-key credential: {other:?}"),
    }

    // And the install's deadline still ends it — minting never
    // restarted the expiry the install fixed.
    std::thread::sleep(Duration::from_secs(1));
    let error = resolve_for_target(&leases, &target)
        .await
        .expect_err("the absolute deadline holds");
    assert!(
        error.to_string().contains("credential_lease_expired"),
        "{error}"
    );
}

#[tokio::test]
async fn a_dropped_router_releases_its_scope_bindings() {
    // A router sharing a lease port must not hold its bound surfaces
    // past its own lifetime: dropping it retires the slice, so a
    // replacement router binds the freed surface to another scope
    // instead of answering credential_scope_conflict forever — while
    // the tombstone keeps a detached resolution failing closed.
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let epoch_id = epoch.current.lock().unwrap().clone();
    let id_a = uuid::Uuid::new_v4().to_string();
    let id_b = uuid::Uuid::new_v4().to_string();
    let leases = Arc::new(Leases::disconnected());
    leases.authorize_scope(scope_a(), [&id_a]).expect("a");
    leases.authorize_scope(scope_b(), [&id_b]).expect("b");
    leases
        .install_handoff(
            &handoff_document(
                &epoch_id,
                &[
                    (&id_a, secret_a().as_bytes()),
                    (&id_b, secret_b().as_bytes()),
                ],
            ),
            epoch,
        )
        .expect("install");
    let endpoint = || {
        EndpointRoute::from_document(&serde_json::json!({
            "model": "m",
            "endpoint": {"baseUrl": "https://a.vendor.example/v1", "protocol": "openai-chat-completions"},
            "auth": "api-key"
        }))
        .expect("route")
        .1
    };

    let surface = {
        let mut router_a = Router::with_leases(loopback_transport(), Arc::clone(&leases));
        router_a
            .add_endpoint_route_scoped("m", endpoint(), scope_a())
            .expect("declare");
        router_a
            .resolve("m")
            .expect("resolve")
            .adapter
            .target()
            .clone()
        // router_a drops here, retiring its published slice.
    };

    // The retired binding fails a detached resolution closed — the
    // tombstone is kept, not erased.
    let error = resolve_for_target(&leases, &surface)
        .await
        .expect_err("a dropped router's surface fails closed");
    assert!(
        error.to_string().contains("credential_scope_retired"),
        "{error}"
    );

    // And a replacement router binds the freed surface to a different
    // scope — the retired slice no longer conflicts.
    let mut router_b = Router::with_leases(loopback_transport(), Arc::clone(&leases));
    router_b
        .add_endpoint_route_scoped("m", endpoint(), scope_b())
        .expect("the freed surface binds a new scope");
    assert_eq!(router_b.credential_scope("m"), Some(scope_b()));
}

#[tokio::test]
async fn a_detached_adapter_stays_pinned_to_its_declared_scope() {
    // An adapter resolve() already returned keeps its bound surface —
    // and the scope it was declared against. Rebinding that surface to
    // another scope must not hand the retained adapter the new scope's
    // credentials: its resolution is pinned to the declaration and
    // fails closed once the live binding no longer matches.
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let epoch_id = epoch.current.lock().unwrap().clone();
    let id_a = uuid::Uuid::new_v4().to_string();
    let id_b = uuid::Uuid::new_v4().to_string();
    let leases = Arc::new(Leases::disconnected());
    leases.authorize_scope(scope_a(), [&id_a]).expect("a");
    leases.authorize_scope(scope_b(), [&id_b]).expect("b");
    leases
        .install_handoff(
            &handoff_document(
                &epoch_id,
                &[
                    (&id_a, secret_a().as_bytes()),
                    (&id_b, secret_b().as_bytes()),
                ],
            ),
            epoch,
        )
        .expect("install");

    // A catalog whose adapter factory records the resolver each bind
    // receives — the scoped resolution bind's resolver is under test.
    let resolvers: Arc<Mutex<Vec<Arc<dyn a4mp::CredentialResolver>>>> =
        Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&resolvers);
    let mut catalog = a4mp::Catalog::new(Vec::new()).expect("catalog");
    catalog.register_adapter(
        a4mp::Protocol::Other("vendor".to_owned()),
        Arc::new(move |target, _auth, _transport, resolver, _effects| {
            recorded.lock().expect("resolvers").push(resolver);
            Ok(Arc::new(HungAdapter { target }) as Arc<dyn a4mp::Adapter>)
        }),
    );
    let mut router =
        Router::with_catalog_leases(catalog, loopback_transport(), Arc::clone(&leases));
    let endpoint = || {
        EndpointRoute::from_document(&serde_json::json!({
            "model": "m",
            "endpoint": {"baseUrl": "https://a.vendor.example/v1", "protocol": "other:vendor"},
            "auth": "api-key"
        }))
        .expect("route")
        .1
    };
    router
        .add_endpoint_route_scoped("m", endpoint(), scope_a())
        .expect("declare");
    let surface = router
        .resolve("m")
        .expect("resolve")
        .adapter
        .target()
        .clone();
    let pinned = resolvers
        .lock()
        .expect("resolvers")
        .last()
        .expect("the resolution bind's resolver")
        .clone();
    let pinned_scope = || a4mp::CredentialScope {
        target: &surface,
        auth: &a4mp::AuthKind::ApiKey,
    };
    match a4mp::CredentialResolver::resolve(pinned.as_ref(), pinned_scope())
        .await
        .expect("the declared scope resolves")
    {
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), secret_a()),
        other => panic!("expected an api-key credential: {other:?}"),
    }

    // Rebind the same surface to another scope: the port answers the
    // live binding while the retained adapter's pin refuses.
    router
        .add_endpoint_route_scoped("m", endpoint(), scope_b())
        .expect("rebind");
    let error = a4mp::CredentialResolver::resolve(pinned.as_ref(), pinned_scope())
        .await
        .expect_err("a rebound surface never inherits the new scope");
    assert!(error.to_string().contains("credential_scope_"), "{error}");
    match resolve_for_target(&leases, &surface)
        .await
        .expect("the live binding resolves")
    {
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), secret_b()),
        other => panic!("expected an api-key credential: {other:?}"),
    }
}

#[test]
fn a_host_resolver_keeps_the_leased_mechanism_routes() {
    // Router::new and with_catalog run the host's own credential port —
    // there is no scope table to authorize into, so api-key and bearer
    // routes declare unscoped and resolve through the host's resolver.
    // The scope contract binds only lease-backed routers, where the
    // port enforces it.
    let mut router = Router::new(
        Arc::new(a4mp::ReqwestTransport::new()),
        Arc::new(a4mp::NoCredentials),
    );
    router
        .load_routes(&serde_json::json!({"routes": [
            {"model": "m-key", "provider": "openai", "auth": "api-key"},
            {"model": "m-bearer", "provider": "anthropic", "auth": "bearer"},
            {"model": "m-endpoint",
             "endpoint": {"baseUrl": "https://api.vendor.example", "protocol": "openai-chat-completions"},
             "auth": "api-key"}
        ]}))
        .expect("leased mechanisms declare unscoped on a host resolver");
    for model in ["m-key", "m-bearer", "m-endpoint"] {
        assert!(router.resolve(model).is_ok(), "{model}");
    }
}

#[tokio::test]
async fn a_retained_adapter_dies_with_its_own_binding_owner() {
    // Two routers share one lease port and bind the same surface to the
    // same scope — legal, both bindings agree. When the first router
    // drops, its slice retires: the adapter it detached is pinned to
    // *its* owner's binding and must fail closed even while the sibling
    // router's identical binding keeps the live surface resolving.
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let epoch_id = epoch.current.lock().unwrap().clone();
    let id = uuid::Uuid::new_v4().to_string();
    let leases = Arc::new(Leases::disconnected());
    leases.authorize_scope(scope_a(), [&id]).expect("scope");
    leases
        .install_handoff(
            &handoff_document(&epoch_id, &[(&id, secret_a().as_bytes())]),
            epoch,
        )
        .expect("install");

    // A catalog whose adapter factory records the resolver each bind
    // receives — the scoped resolution binds' resolvers are under test.
    let resolvers: Arc<Mutex<Vec<Arc<dyn a4mp::CredentialResolver>>>> =
        Arc::new(Mutex::new(Vec::new()));
    let catalog = || {
        let recorded = Arc::clone(&resolvers);
        let mut catalog = a4mp::Catalog::new(Vec::new()).expect("catalog");
        catalog.register_adapter(
            a4mp::Protocol::Other("vendor".to_owned()),
            Arc::new(move |target, _auth, _transport, resolver, _effects| {
                recorded.lock().expect("resolvers").push(resolver);
                Ok(Arc::new(HungAdapter { target }) as Arc<dyn a4mp::Adapter>)
            }),
        );
        catalog
    };
    let endpoint = || {
        EndpointRoute::from_document(&serde_json::json!({
            "model": "m",
            "endpoint": {"baseUrl": "https://a.vendor.example/v1", "protocol": "other:vendor"},
            "auth": "api-key"
        }))
        .expect("route")
        .1
    };

    let mut router_a =
        Router::with_catalog_leases(catalog(), loopback_transport(), Arc::clone(&leases));
    router_a
        .add_endpoint_route_scoped("m", endpoint(), scope_a())
        .expect("declare a");
    let surface = router_a
        .resolve("m")
        .expect("resolve a")
        .adapter
        .target()
        .clone();
    let mut router_b =
        Router::with_catalog_leases(catalog(), loopback_transport(), Arc::clone(&leases));
    router_b
        .add_endpoint_route_scoped("m", endpoint(), scope_a())
        .expect("declare b — the same binding under another owner");
    router_b.resolve("m").expect("resolve b");

    // The factory recorded, in order: declare a, resolve a, declare b,
    // resolve b — each resolution bind's resolver is the pinned one.
    let binds: Vec<_> = resolvers.lock().expect("resolvers").clone();
    let pinned_a = binds[1].clone();
    let pinned_b = binds[3].clone();
    let pinned_scope = || a4mp::CredentialScope {
        target: &surface,
        auth: &a4mp::AuthKind::ApiKey,
    };
    match a4mp::CredentialResolver::resolve(pinned_a.as_ref(), pinned_scope())
        .await
        .expect("the shared binding resolves while both owners live")
    {
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), secret_a()),
        other => panic!("expected an api-key credential: {other:?}"),
    }

    drop(router_a);
    let error = a4mp::CredentialResolver::resolve(pinned_a.as_ref(), pinned_scope())
        .await
        .expect_err("the detached adapter dies with its owner's slice");
    assert!(
        error.to_string().contains("credential_scope_retired"),
        "{error}"
    );
    match a4mp::CredentialResolver::resolve(pinned_b.as_ref(), pinned_scope())
        .await
        .expect("the sibling's live binding keeps forwarding")
    {
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), secret_a()),
        other => panic!("expected an api-key credential: {other:?}"),
    }

    // And a replacement router republishing the same binding revives
    // nothing — the retired adapter's owner slice stays tombstoned.
    let mut router_c =
        Router::with_catalog_leases(catalog(), loopback_transport(), Arc::clone(&leases));
    router_c
        .add_endpoint_route_scoped("m", endpoint(), scope_a())
        .expect("declare c");
    let error = a4mp::CredentialResolver::resolve(pinned_a.as_ref(), pinned_scope())
        .await
        .expect_err("a sibling's binding never revives a retired adapter");
    assert!(
        error.to_string().contains("credential_scope_retired"),
        "{error}"
    );
}

#[tokio::test]
async fn an_unauthenticated_route_forwards_over_a_retired_surface() {
    // A scoped route's retirement tombstones its surface — the
    // credential lookup still fails closed — but the auth:none
    // replacement on the same surface needs no credential, so the
    // tombstone must not fail its forward.
    let (addr, upstream) = mock_upstream(openai_reply());
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let epoch_id = epoch.current.lock().unwrap().clone();
    let id = uuid::Uuid::new_v4().to_string();
    let leases = Arc::new(Leases::disconnected());
    leases
        .authorize_scope(vendor_scope(), [&id])
        .expect("scope");
    leases
        .install_handoff(
            &handoff_document(&epoch_id, &[(&id, secret_a().as_bytes())]),
            epoch,
        )
        .expect("install");
    let endpoint = |auth: &str| {
        EndpointRoute::from_document(&serde_json::json!({
            "model": "m",
            "endpoint": {"baseUrl": format!("http://{addr}/v1"), "protocol": "openai-chat-completions"},
            "auth": auth
        }))
        .expect("route")
        .1
    };

    let mut router = Router::with_leases(loopback_transport(), Arc::clone(&leases));
    router
        .add_endpoint_route_scoped("m", endpoint("api-key"), vendor_scope())
        .expect("declare scoped");
    let surface = router
        .resolve("m")
        .expect("resolve")
        .adapter
        .target()
        .clone();
    router
        .add_endpoint_route("m", endpoint("none"))
        .expect("the unauthenticated replacement declares");

    // The tombstone still fails credential lookups closed...
    let error = resolve_for_target(&leases, &surface)
        .await
        .expect_err("a retired surface never resolves credentials");
    assert!(
        error.to_string().contains("credential_scope_retired"),
        "{error}"
    );

    // ...while the replacement forwards without an auth header.
    let service = Service::new(router, Meter::unmetered());
    let body = serde_json::json!({
        "model": "m",
        "messages": [{"role": "user", "content": "ping"}]
    });
    let replies = run(
        &service,
        &request_line(1, "chat.complete", chat_params(body, None)),
    )
    .await;
    let received = upstream.join().expect("upstream thread");
    assert_eq!(received.header("authorization"), None);
    let answer = reply_for(&replies, 1);
    assert_eq!(
        answer["result"]["body"]["choices"][0]["message"]["content"], "pong",
        "{answer}"
    );
}

#[tokio::test]
async fn a_scoped_custom_factory_receives_the_declared_target() {
    // A custom adapter factory may transform the target it is fed —
    // this one moves the surface under `/vendor`. Declaration registers
    // the *output* the adapter reports; a rebind must feed the
    // factory's original input again, never its own output, or the
    // transformation applies twice and the live adapter drifts off the
    // registered surface.
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let epoch_id = epoch.current.lock().unwrap().clone();
    let id = uuid::Uuid::new_v4().to_string();
    let leases = Arc::new(Leases::disconnected());
    leases.authorize_scope(scope_a(), [&id]).expect("scope");
    leases
        .install_handoff(
            &handoff_document(&epoch_id, &[(&id, secret_a().as_bytes())]),
            epoch,
        )
        .expect("install");

    let produced: Arc<Mutex<Vec<a4mp::ServiceTarget>>> = Arc::new(Mutex::new(Vec::new()));
    let resolvers: Arc<Mutex<Vec<Arc<dyn a4mp::CredentialResolver>>>> =
        Arc::new(Mutex::new(Vec::new()));
    let mut catalog = a4mp::Catalog::new(Vec::new()).expect("catalog");
    {
        let produced = Arc::clone(&produced);
        let resolvers = Arc::clone(&resolvers);
        catalog.register_adapter(
            a4mp::Protocol::Other("vendor".to_owned()),
            Arc::new(move |mut target, _auth, _transport, resolver, _effects| {
                resolvers.lock().expect("resolvers").push(resolver);
                let path = target.base_url.path().trim_end_matches('/').to_owned();
                target.base_url.set_path(&format!("{path}/vendor"));
                produced.lock().expect("produced").push(target.clone());
                Ok(Arc::new(HungAdapter { target }) as Arc<dyn a4mp::Adapter>)
            }),
        );
    }
    let mut router =
        Router::with_catalog_leases(catalog, loopback_transport(), Arc::clone(&leases));
    router
        .add_endpoint_route_scoped(
            "m",
            EndpointRoute::from_document(&serde_json::json!({
                "model": "m",
                "endpoint": {"baseUrl": "https://a.vendor.example/v1", "protocol": "other:vendor"},
                "auth": "api-key"
            }))
            .expect("route")
            .1,
            scope_a(),
        )
        .expect("declare");

    // The registered surface is the declaration bind's transformed
    // output — one `/vendor` applied to the declared input.
    let registered = produced.lock().expect("produced")[0].clone();
    assert_eq!(registered.base_url.path(), "/v1/vendor");

    let adapter = router
        .resolve("m")
        .expect("the rebind feeds the declared input")
        .adapter;
    // The rebound adapter's output matches the registered surface —
    // the transformation applied exactly once.
    assert_eq!(adapter.target().base_url, registered.base_url);
    assert!(
        produced
            .lock()
            .expect("produced")
            .iter()
            .all(|target| target.base_url == registered.base_url),
        "every bind produced the registered surface"
    );

    // And the pinned resolver answers the scope's credential for it.
    let pinned = resolvers
        .lock()
        .expect("resolvers")
        .last()
        .expect("the scoped bind's resolver")
        .clone();
    match a4mp::CredentialResolver::resolve(
        pinned.as_ref(),
        a4mp::CredentialScope {
            target: adapter.target(),
            auth: &a4mp::AuthKind::ApiKey,
        },
    )
    .await
    .expect("the registered surface resolves its scope")
    {
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), secret_a()),
        other => panic!("expected an api-key credential: {other:?}"),
    }
}

#[tokio::test]
async fn a_republished_binding_is_a_new_generation_for_retained_adapters() {
    // A publish that leaves a binding untouched keeps the retained
    // adapter's pin alive, but a retirement followed by an identical
    // republish is a different binding: the surface and scope read the
    // same, yet the detached adapter's pin must stay refused.
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let epoch_id = epoch.current.lock().unwrap().clone();
    let id = uuid::Uuid::new_v4().to_string();
    let leases = Arc::new(Leases::disconnected());
    leases.authorize_scope(scope_a(), [&id]).expect("scope");
    leases
        .install_handoff(
            &handoff_document(&epoch_id, &[(&id, secret_a().as_bytes())]),
            epoch,
        )
        .expect("install");

    let resolvers: Arc<Mutex<Vec<Arc<dyn a4mp::CredentialResolver>>>> =
        Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&resolvers);
    let mut catalog = a4mp::Catalog::new(Vec::new()).expect("catalog");
    catalog.register_adapter(
        a4mp::Protocol::Other("vendor".to_owned()),
        Arc::new(move |target, _auth, _transport, resolver, _effects| {
            recorded.lock().expect("resolvers").push(resolver);
            Ok(Arc::new(HungAdapter { target }) as Arc<dyn a4mp::Adapter>)
        }),
    );
    let endpoint = |base_url: &str| {
        EndpointRoute::from_document(&serde_json::json!({
            "model": "m",
            "endpoint": {"baseUrl": base_url, "protocol": "other:vendor"},
            "auth": "api-key"
        }))
        .expect("route")
        .1
    };
    let mut router =
        Router::with_catalog_leases(catalog, loopback_transport(), Arc::clone(&leases));
    router
        .add_endpoint_route_scoped("m", endpoint("https://a.vendor.example/v1"), scope_a())
        .expect("declare m");
    let surface_a = router
        .resolve("m")
        .expect("resolve m")
        .adapter
        .target()
        .clone();
    // The resolution bind's resolver is the pinned one — the
    // declaration bind records its own first.
    let pinned = resolvers
        .lock()
        .expect("resolvers")
        .last()
        .expect("the scoped bind's resolver")
        .clone();
    static API_KEY: a4mp::AuthKind = a4mp::AuthKind::ApiKey;
    let pinned_scope = || a4mp::CredentialScope {
        target: &surface_a,
        auth: &API_KEY,
    };
    match a4mp::CredentialResolver::resolve(pinned.as_ref(), pinned_scope())
        .await
        .expect("the live binding resolves")
    {
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), secret_a()),
        other => panic!("expected an api-key credential: {other:?}"),
    }

    // A republish adding a sibling route leaves m's binding untouched:
    // the retained pin — generation and all — keeps resolving.
    router
        .add_endpoint_route_scoped("m2", endpoint("https://b.vendor.example/v1"), scope_a())
        .expect("declare m2");
    a4mp::CredentialResolver::resolve(pinned.as_ref(), pinned_scope())
        .await
        .expect("an unchanged publish keeps the pin alive");

    // Retire m's surface: replacing it with an unauthenticated route
    // drops the binding, and the pin fails closed.
    let none = EndpointRoute::from_document(&serde_json::json!({
        "model": "m",
        "endpoint": {"baseUrl": "https://c.vendor.example/v1", "protocol": "other:vendor"}
    }))
    .expect("route")
    .1;
    router
        .add_endpoint_route("m", none)
        .expect("an unscoped replacement retires the binding");
    let error = a4mp::CredentialResolver::resolve(pinned.as_ref(), pinned_scope())
        .await
        .expect_err("a retired binding fails closed");
    assert!(
        error.to_string().contains("credential_scope_retired"),
        "{error}"
    );

    // Publish the same surface and scope again: a different binding —
    // the retained adapter's pin never regains credentials.
    router
        .add_endpoint_route_scoped("m3", endpoint("https://a.vendor.example/v1"), scope_a())
        .expect("the identical republish declares");
    let error = a4mp::CredentialResolver::resolve(pinned.as_ref(), pinned_scope())
        .await
        .expect_err("a republished binding never revives a retired pin");
    assert!(
        error.to_string().contains("credential_scope_retired"),
        "{error}"
    );

    // While the new binding's own adapter resolves normally.
    router.resolve("m3").expect("resolve m3");
    let pinned_new = resolvers
        .lock()
        .expect("resolvers")
        .last()
        .expect("the republished bind's resolver")
        .clone();
    match a4mp::CredentialResolver::resolve(pinned_new.as_ref(), pinned_scope())
        .await
        .expect("the republished binding resolves for its own pin")
    {
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), secret_a()),
        other => panic!("expected an api-key credential: {other:?}"),
    }
}

/// Poll a resolver's answer synchronously — every resolver a bind sees
/// here answers from in-process tables and completes on the first poll,
/// so a no-op waker settles it inside the synchronous factory.
fn resolve_now<'a>(
    resolver: &Arc<dyn a4mp::CredentialResolver>,
    target: &'a a4mp::ServiceTarget,
    auth: &'a a4mp::AuthKind,
) -> std::result::Result<a4mp::Credential, a4mp::Error> {
    let mut future = Box::pin(resolver.resolve(a4mp::CredentialScope { target, auth }));
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => panic!("an in-process resolver never pends"),
    }
}

#[tokio::test]
async fn a_scoped_resolver_answers_only_its_declared_binding() {
    // The declaration bind hands the factory a credential-disabled
    // resolver — resolving through it answers `Credential::None` rather
    // than reaching the custody port before the binding publishes. The
    // pinned resolver an adapter receives at bind answers only for the
    // registered surface and the declared mechanism: a sibling surface
    // sharing the owner's slice and scope, or another mechanism, is
    // outside the declared binding.
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let epoch_id = epoch.current.lock().unwrap().clone();
    let id = uuid::Uuid::new_v4().to_string();
    let leases = Arc::new(Leases::disconnected());
    leases.authorize_scope(scope_a(), [&id]).expect("scope");
    leases
        .install_handoff(
            &handoff_document(&epoch_id, &[(&id, secret_a().as_bytes())]),
            epoch,
        )
        .expect("install");

    let resolvers: Arc<Mutex<Vec<Arc<dyn a4mp::CredentialResolver>>>> =
        Arc::new(Mutex::new(Vec::new()));
    let saw_none: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
    let mut catalog = a4mp::Catalog::new(Vec::new()).expect("catalog");
    {
        let resolvers = Arc::clone(&resolvers);
        let saw_none = Arc::clone(&saw_none);
        catalog.register_adapter(
            a4mp::Protocol::Other("vendor".to_owned()),
            Arc::new(move |target, _auth, _transport, resolver, _effects| {
                let answer = resolve_now(&resolver, &target, &a4mp::AuthKind::ApiKey);
                saw_none
                    .lock()
                    .expect("saw_none")
                    .push(matches!(answer, Ok(a4mp::Credential::None)));
                resolvers.lock().expect("resolvers").push(resolver);
                Ok(Arc::new(HungAdapter { target }) as Arc<dyn a4mp::Adapter>)
            }),
        );
    }
    let endpoint = |base_url: &str| {
        EndpointRoute::from_document(&serde_json::json!({
            "model": "m",
            "endpoint": {"baseUrl": base_url, "protocol": "other:vendor"},
            "auth": "api-key"
        }))
        .expect("route")
        .1
    };
    let mut router =
        Router::with_catalog_leases(catalog, loopback_transport(), Arc::clone(&leases));
    router
        .add_endpoint_route_scoped("m1", endpoint("https://a.vendor.example/v1"), scope_a())
        .expect("declare m1");
    router
        .add_endpoint_route_scoped("m2", endpoint("https://b.vendor.example/v1"), scope_a())
        .expect("declare m2");

    // Both declaration binds resolved nothing: the factory saw the
    // credential-disabled resolver, never the lease port.
    assert_eq!(*saw_none.lock().expect("saw_none"), [true, true]);

    let surface_a = router
        .resolve("m1")
        .expect("resolve m1")
        .adapter
        .target()
        .clone();
    let surface_b = router
        .resolve("m2")
        .expect("resolve m2")
        .adapter
        .target()
        .clone();
    // Binds ran: declare m1, declare m2, resolve m1, resolve m2 — the
    // m1 resolution bind's pinned resolver is the third recorded.
    let binds: Vec<_> = resolvers.lock().expect("resolvers").clone();
    let pinned = binds[2].clone();
    static API_KEY: a4mp::AuthKind = a4mp::AuthKind::ApiKey;
    static BEARER: a4mp::AuthKind = a4mp::AuthKind::Bearer;
    match a4mp::CredentialResolver::resolve(
        pinned.as_ref(),
        a4mp::CredentialScope {
            target: &surface_a,
            auth: &API_KEY,
        },
    )
    .await
    .expect("the declared surface and mechanism resolve")
    {
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), secret_a()),
        other => panic!("expected an api-key credential: {other:?}"),
    }
    // The sibling surface shares the owner's slice and scope — and is
    // still outside this adapter's declared binding.
    let error = a4mp::CredentialResolver::resolve(
        pinned.as_ref(),
        a4mp::CredentialScope {
            target: &surface_b,
            auth: &API_KEY,
        },
    )
    .await
    .expect_err("a sibling surface is outside the pin");
    assert!(
        error.to_string().contains("credential_scope_mismatch"),
        "{error}"
    );
    // As is another mechanism on the pinned surface itself.
    let error = a4mp::CredentialResolver::resolve(
        pinned.as_ref(),
        a4mp::CredentialScope {
            target: &surface_a,
            auth: &BEARER,
        },
    )
    .await
    .expect_err("another mechanism is outside the pin");
    assert!(
        error.to_string().contains("credential_scope_mismatch"),
        "{error}"
    );
}

#[test]
fn a_transformed_target_must_pass_the_bound_surface_policy() {
    // The credential scope registers the surface the bound adapter
    // reports — the factory's output, not its input — so the bare-base
    // and cleartext-credential rules apply to that output: a factory
    // rewriting the surface onto cleartext http to a public host, or
    // onto a URL carrying credentials, refuses at declaration and
    // nothing commits.
    let id = uuid::Uuid::new_v4().to_string();
    let leases = Arc::new(Leases::disconnected());
    leases.authorize_scope(scope_a(), [&id]).expect("scope");
    let endpoint = || {
        EndpointRoute::from_document(&serde_json::json!({
            "model": "m",
            "endpoint": {"baseUrl": "https://a.vendor.example/v1", "protocol": "other:vendor"},
            "auth": "api-key"
        }))
        .expect("route")
        .1
    };
    let catalog_with = |rewrite: fn(&mut url::Url)| {
        let mut catalog = a4mp::Catalog::new(Vec::new()).expect("catalog");
        catalog.register_adapter(
            a4mp::Protocol::Other("vendor".to_owned()),
            Arc::new(move |mut target, _auth, _transport, _resolver, _effects| {
                rewrite(&mut target.base_url);
                Ok(Arc::new(HungAdapter { target }) as Arc<dyn a4mp::Adapter>)
            }),
        );
        catalog
    };

    // Cleartext http to a public host: the declared input was https,
    // but the surface credentials would flow to is not.
    let mut router = Router::with_catalog_leases(
        catalog_with(|url| {
            url.set_scheme("http").expect("scheme");
            url.set_host(Some("203.0.113.9")).expect("host");
        }),
        loopback_transport(),
        Arc::clone(&leases),
    );
    let error = router
        .add_endpoint_route_scoped("m", endpoint(), scope_a())
        .expect_err("a cleartext-public output refuses");
    assert!(error.to_string().contains("cleartext"), "{error}");
    assert!(router.resolve("m").is_err());

    // Embedded credentials in the reported surface: the bound target
    // must stay a bare base like the declared one.
    let mut router = Router::with_catalog_leases(
        catalog_with(|url| {
            url.set_username("svc").expect("username");
            url.set_password(Some("hunter2")).expect("password");
        }),
        loopback_transport(),
        Arc::clone(&leases),
    );
    let error = router
        .add_endpoint_route_scoped("m", endpoint(), scope_a())
        .expect_err("a credential-bearing output refuses");
    assert!(error.to_string().contains("bound target"), "{error}");
    assert!(router.resolve("m").is_err());

    // A profile route takes the same check: the openai profile's chat
    // factory rewritten to a cleartext-public surface refuses too.
    let mut catalog = a4mp::Catalog::new(a4mp::catalog::builtin_profiles()).expect("catalog");
    catalog.register_adapter(
        a4mp::Protocol::OpenAiChatCompletions,
        Arc::new(|mut target, _auth, _transport, _resolver, _effects| {
            target.base_url.set_scheme("http").expect("scheme");
            target.base_url.set_host(Some("203.0.113.9")).expect("host");
            Ok(Arc::new(HungAdapter { target }) as Arc<dyn a4mp::Adapter>)
        }),
    );
    let mut router =
        Router::with_catalog_leases(catalog, loopback_transport(), Arc::clone(&leases));
    let route = Route {
        provider: a4mp::ProviderId::new("openai"),
        protocol: Some(a4mp::Protocol::OpenAiChatCompletions),
        region: None,
        auth: a4mp::AuthKind::ApiKey,
        upstream_model: "gpt".to_owned(),
        vars: Default::default(),
    };
    let error = router
        .add_route_scoped("m", route, scope_a())
        .expect_err("a cleartext-public profile output refuses");
    assert!(error.to_string().contains("cleartext"), "{error}");
    assert!(router.resolve("m").is_err());
}

/// A handoff document carrying one credential per `(kind,
/// credential_id, secret)` triple — the material the host would hand
/// this process when scopes span more than one mechanism.
fn handoff_document_kinds(
    epoch: &str,
    credentials: &[(ProviderCredential, &str, &[u8])],
) -> Vec<u8> {
    let mut map: BTreeMap<ProviderCredential, Vec<LeasedCredential>> = BTreeMap::new();
    for (kind, id, secret) in credentials {
        map.entry(*kind).or_default().push(
            LeasedCredential::new(
                (*id).to_owned(),
                SecretBytes::try_from_bytes(secret.to_vec()).expect("secret"),
                None,
            )
            .expect("credential"),
        );
    }
    let handoff =
        CredentialHandoff::new(map, Duration::from_secs(3600), epoch.to_owned()).expect("handoff");
    handoff.to_json().expect("document").expose_bytes().to_vec()
}

#[tokio::test]
async fn a_rebound_mechanism_retires_the_old_binding() {
    // Replacing an api-key route with a bearer route on the same
    // surface and scope is a mechanism swap, not the same binding:
    // while a sibling route still declares api-key on that surface the
    // binding lives on and a retained adapter's pin keeps resolving,
    // but when the last api-key route leaves, the binding's generation
    // dies with it — the retained adapter never regains its key even
    // though the surface's new bearer binding resolves normally.
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let epoch_id = epoch.current.lock().unwrap().clone();
    let key_id = uuid::Uuid::new_v4().to_string();
    let token_id = uuid::Uuid::new_v4().to_string();
    let leases = Arc::new(Leases::disconnected());
    leases
        .authorize_scope(scope_a(), [&key_id, &token_id])
        .expect("scope");
    leases
        .install_handoff(
            &handoff_document_kinds(
                &epoch_id,
                &[
                    (ProviderCredential::ApiKey, &key_id, secret_a().as_bytes()),
                    (ProviderCredential::Bearer, &token_id, secret_b().as_bytes()),
                ],
            ),
            epoch,
        )
        .expect("install");

    let resolvers: Arc<Mutex<Vec<Arc<dyn a4mp::CredentialResolver>>>> =
        Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&resolvers);
    let mut catalog = a4mp::Catalog::new(Vec::new()).expect("catalog");
    catalog.register_adapter(
        a4mp::Protocol::Other("vendor".to_owned()),
        Arc::new(move |target, _auth, _transport, resolver, _effects| {
            recorded.lock().expect("resolvers").push(resolver);
            Ok(Arc::new(HungAdapter { target }) as Arc<dyn a4mp::Adapter>)
        }),
    );
    let endpoint = |auth: &str| {
        EndpointRoute::from_document(&serde_json::json!({
            "model": "m",
            "endpoint": {"baseUrl": "https://a.vendor.example/v1", "protocol": "other:vendor"},
            "auth": auth
        }))
        .expect("route")
        .1
    };
    let unscoped = || {
        EndpointRoute::from_document(&serde_json::json!({
            "model": "m",
            "endpoint": {"baseUrl": "https://c.vendor.example/v1", "protocol": "other:vendor"}
        }))
        .expect("route")
        .1
    };
    let mut router =
        Router::with_catalog_leases(catalog, loopback_transport(), Arc::clone(&leases));
    router
        .add_endpoint_route_scoped("m", endpoint("api-key"), scope_a())
        .expect("declare m");
    let surface_a = router
        .resolve("m")
        .expect("resolve m")
        .adapter
        .target()
        .clone();
    // Binds ran declaration-then-serving; the resolution bind's pinned
    // resolver is the second recorded.
    let pinned = resolvers
        .lock()
        .expect("resolvers")
        .last()
        .expect("the scoped bind's resolver")
        .clone();
    static API_KEY: a4mp::AuthKind = a4mp::AuthKind::ApiKey;
    static BEARER: a4mp::AuthKind = a4mp::AuthKind::Bearer;
    let api_key_scope = || a4mp::CredentialScope {
        target: &surface_a,
        auth: &API_KEY,
    };
    let bearer_scope = || a4mp::CredentialScope {
        target: &surface_a,
        auth: &BEARER,
    };
    match a4mp::CredentialResolver::resolve(pinned.as_ref(), api_key_scope())
        .await
        .expect("the api-key binding resolves")
    {
        a4mp::Credential::ApiKey(secret) => assert_eq!(secret.expose(), secret_a()),
        other => panic!("expected an api-key credential: {other:?}"),
    }

    // A sibling route still declaring api-key keeps the surface's
    // api-key binding alive while m itself swaps to bearer: the publish
    // drops m's stake but not the binding m2 shares.
    router
        .add_endpoint_route_scoped("m2", endpoint("api-key"), scope_a())
        .expect("declare m2");
    router
        .add_endpoint_route_scoped("m", endpoint("bearer"), scope_a())
        .expect("m swaps mechanism");
    a4mp::CredentialResolver::resolve(pinned.as_ref(), api_key_scope())
        .await
        .expect("a shared api-key binding survives the swap");

    // When the last api-key route leaves the surface, the binding's
    // generation dies: the retained adapter's pin fails closed.
    router
        .add_endpoint_route("m2", unscoped())
        .expect("an unscoped replacement retires the api-key binding");
    let error = a4mp::CredentialResolver::resolve(pinned.as_ref(), api_key_scope())
        .await
        .expect_err("a mechanism swap retires the old binding");
    assert!(
        error.to_string().contains("credential_scope_retired"),
        "{error}"
    );

    // While the surface's bearer binding — a different binding on the
    // same surface and scope — resolves its own credential normally.
    router.resolve("m").expect("resolve m as bearer");
    let pinned_bearer = resolvers
        .lock()
        .expect("resolvers")
        .last()
        .expect("the bearer bind's resolver")
        .clone();
    match a4mp::CredentialResolver::resolve(pinned_bearer.as_ref(), bearer_scope())
        .await
        .expect("the bearer binding resolves")
    {
        a4mp::Credential::Bearer { token, .. } => assert_eq!(token.expose(), secret_b()),
        other => panic!("expected a bearer credential: {other:?}"),
    }
}

#[test]
fn a_serving_bind_target_must_pass_the_bound_surface_policy() {
    // The surface checks gating the declaration bind gate the serving
    // bind too — on every declared route, scoped or not. A factory that
    // reported a clean https surface to declaration but binds a
    // cleartext-public target when the route resolves must fail the
    // resolve instead of forwarding credentials to it.
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut catalog = a4mp::Catalog::new(Vec::new()).expect("catalog");
    {
        let calls = Arc::clone(&calls);
        catalog.register_adapter(
            a4mp::Protocol::Other("vendor".to_owned()),
            Arc::new(move |mut target, _auth, _transport, _resolver, _effects| {
                if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
                    target.base_url.set_scheme("http").expect("scheme");
                    target.base_url.set_host(Some("203.0.113.9")).expect("host");
                }
                Ok(Arc::new(HungAdapter { target }) as Arc<dyn a4mp::Adapter>)
            }),
        );
    }
    let mut router =
        Router::with_catalog(catalog, loopback_transport(), Arc::new(a4mp::NoCredentials));
    router
        .add_endpoint_route(
            "m",
            EndpointRoute::from_document(&serde_json::json!({
                "model": "m",
                "endpoint": {"baseUrl": "https://a.vendor.example/v1", "protocol": "other:vendor"},
                "auth": "api-key"
            }))
            .expect("route")
            .1,
        )
        .expect("a clean declaration binds");
    let error = router
        .resolve("m")
        .err()
        .expect("a cleartext-public serving target refuses");
    assert!(error.to_string().contains("cleartext"), "{error}");
}
