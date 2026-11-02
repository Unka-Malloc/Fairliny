//! The outward face under test: the NDJSON loop, the route binding, the
//! metering composition, and the lease's epoch contract — all against a
//! stub adapter, so nothing here ever touches a real provider.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use credential_lease::{CredentialHandoff, LeaseEpochSource, LeasedCredential, SecretBytes};
use fairliny_gateway::leases::{Leases, ProviderCredential};
use fairliny_gateway::meter::Meter;
use fairliny_gateway::router::{Route, Router};
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

/// The lease the host would hand this process: one API-key credential in
/// the `ProviderCredential` family, minted under `epoch`.
fn handoff_bytes(epoch: &str) -> Vec<u8> {
    let credential = LeasedCredential::new(
        uuid::Uuid::new_v4().to_string(),
        SecretBytes::try_from_bytes(b"test-credential-material".to_vec()).expect("secret"),
        None,
    )
    .expect("credential");
    let mut credentials = BTreeMap::new();
    credentials.insert(ProviderCredential::ApiKey, vec![credential]);
    let handoff = CredentialHandoff::new(credentials, Duration::from_secs(3600), epoch.to_owned())
        .expect("handoff");
    handoff.to_json().expect("document").expose_bytes().to_vec()
}

/// A router over the stub: the outward name `ping-model` forwards to the
/// stub adapter as `upstream-ping`. The transport is real but never
/// invoked — every test route is prebound.
fn test_router(
    resolver: Arc<dyn a4mp::CredentialResolver>,
    requests: Arc<Mutex<Vec<a4mp::ChatRequest>>>,
) -> Router {
    let transport = Arc::new(a4mp::ReqwestTransport::new());
    let mut router = Router::new(transport, Arc::clone(&resolver));
    let adapter = Arc::new(StubAdapter {
        target: a4mp::ServiceTarget::new(
            "stub",
            a4mp::Protocol::Other("stub".to_owned()),
            url::Url::parse("https://stub.invalid/").expect("url"),
        ),
        resolver,
        requests,
        output: reply_output(),
    });
    router.register_adapter("ping-model", "upstream-ping", adapter);
    router
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
/// journal rather than racing it.
async fn run(service: &Service, input: &[u8]) -> Vec<serde_json::Value> {
    let mut output = Vec::new();
    service.serve(input, &mut output).await.expect("serve loop");
    service.flush_metering().await;
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

    let replies = run(
        &service,
        br#"{"id":1,"method":"models.list","params":{}}
{"id":2,"method":"chat.complete","params":{"model":"ping-model","agent":"caller","messages":[{"role":"user","text":"hi"}]}}
"#,
    )
    .await;

    let models = &replies[0]["result"]["models"][0];
    assert_eq!(models["id"], "ping-model");
    assert_eq!(models["provider"], "stub");
    assert_eq!(models["upstreamModel"], "upstream-ping");

    let result = &replies[1]["result"];
    assert_eq!(result["text"], "pong");
    assert_eq!(result["model"], "upstream-ping");
    assert_eq!(result["usage"]["inputTokens"], 3);
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
        br#"{"id":1,"method":"chat.complete","params":{"model":"ping-model","messages":[{"role":"user","text":"hi"}]}}
"#,
    )
    .await;
    assert_eq!(replies[0]["result"]["text"], "pong");
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
    let replies = run(
        &service,
        br#"{"id":1,"method":"chat.complete","params":{"model":"ping-model","messages":[{"role":"user","text":"hi"}]}}
{"id":2,"method":"chat.complete","params":{"model":"no-such-model","messages":[{"role":"user","text":"hi"}]}}
"#,
    )
    .await;
    assert!(
        replies[0]["error"]
            .as_str()
            .unwrap()
            .contains("credential_lease_unavailable")
    );
    assert!(
        replies[1]["error"]
            .as_str()
            .unwrap()
            .contains("unknown model")
    );
}

#[test]
fn a_rotated_epoch_refuses_the_lease_on_next_use() {
    let epoch = Arc::new(Epochs {
        current: Mutex::new(uuid::Uuid::new_v4().to_string()),
    });
    let leases = Leases::disconnected();
    let epoch_id = epoch.current.lock().unwrap().clone();
    leases
        .install_handoff(&handoff_bytes(&epoch_id), epoch.clone())
        .expect("install");
    leases
        .slot()
        .resolve(ProviderCredential::ApiKey)
        .expect("first resolve");
    *epoch.current.lock().unwrap() = uuid::Uuid::new_v4().to_string();
    // The slot consults the epoch source on every resolution: after the
    // rotation the same lease refuses as revoked.
    let error = leases
        .slot()
        .resolve(ProviderCredential::ApiKey)
        .expect_err("revoked");
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

    // The exposition request arrives on the same stream right behind
    // the forward — the answer must already carry the settled record,
    // not a mid-flight journal.
    let replies = run(
        &service,
        br#"{"id":1,"method":"chat.complete","params":{"model":"ping-model","agent":"caller","messages":[{"role":"user","text":"hi"}]}}
{"id":2,"method":"metrics.exposition"}
"#,
    )
    .await;
    assert_eq!(replies[0]["result"]["text"], "pong");
    let exposition = replies[1]["result"]["exposition"]
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

    let params = serde_json::json!({
        "model": "ping-model",
        "agent": "caller",
        "messages": [{"role": "user", "text": "hi"}]
    });
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

    let replies = run(
        &service,
        br#"{"id":1,"method":"chat.complete","params":{"model":"hang-model","messages":[{"role":"user","text":"hi"}]}}
{"id":2,"method":"models.list"}
"#,
    )
    .await;
    assert!(
        replies[0]["error"]
            .as_str()
            .expect("deadline error")
            .contains("upstream deadline"),
        "the hung call answers with the deadline error: {replies:?}"
    );
    // The hung call did not poison the loop — the next request answers.
    assert!(replies[1]["result"]["models"].is_array());
}

#[tokio::test]
async fn a_rejected_request_is_not_counted_as_forwarded() {
    let resolver: Arc<dyn a4mp::CredentialResolver> = Arc::new(Leases::disconnected());
    let service = Service::new(
        test_router(resolver, Arc::new(Mutex::new(Vec::new()))),
        Meter::unmetered(),
    );
    // `chat.complete` without `messages` is refused at the request parser
    // — the request was never admitted, so nothing counts it.
    let replies = run(
        &service,
        br#"{"id":1,"method":"chat.complete","params":{"model":"ping-model"}}
"#,
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

#[test]
fn a_rewritten_epoch_file_revokes_the_next_resolve() {
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
    leases
        .slot()
        .resolve(ProviderCredential::ApiKey)
        .expect("first resolve");
    // The custody owner rewrote the file: the next resolve consults the
    // file again and refuses as revoked.
    std::fs::write(&path, uuid::Uuid::new_v4().to_string()).expect("rotate");
    let error = leases
        .slot()
        .resolve(ProviderCredential::ApiKey)
        .expect_err("revoked");
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
    let route = Route {
        provider: a4mp::ProviderId::new("no-such-provider"),
        protocol: None,
        region: None,
        auth: a4mp::AuthKind::ApiKey,
        upstream_model: "x".to_owned(),
        vars: Default::default(),
    };
    let error = router.add_route("model", route).expect_err("closed");
    assert!(error.to_string().contains("unknown provider"));
    assert!(router.resolve("model").is_err());
}
