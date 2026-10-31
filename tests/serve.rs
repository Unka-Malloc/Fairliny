//! The outward face under test: the NDJSON loop, the route binding, the
//! metering composition, and the lease's epoch contract — all against a
//! stub adapter, so nothing here ever touches a real provider.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use credential_lease::{CredentialHandoff, LeaseEpochSource, LeasedCredential, SecretBytes};
use fairlead::leases::{Leases, ProviderCredential};
use fairlead::meter::Meter;
use fairlead::router::{Route, Router};
use fairlead::service::Service;

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
        Ok(reply_output())
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
    let exposition = fairlead::export::render(service.meter()).expect("render");
    assert!(exposition.contains("metera_gateway_agent_requests_total"));
    assert!(exposition.contains("metera_usage_tokens{kind=\"input\""));
    let facts = service.meter().facts();
    assert!(
        facts.iter().any(|fact| {
            fact.scope_ref == "gateway:forwarded"
                && fact.metric == "licoup.tokens.input"
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
    input.resize(fairlead::service::MAX_LINE_BYTES + 64, b'x');
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
    };
    let error = router.add_route("model", route).expect_err("closed");
    assert!(error.to_string().contains("unknown provider"));
    assert!(router.resolve("model").is_err());
}
