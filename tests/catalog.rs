//! Catalog sync and base-vendor discovery through the public surface:
//! the synchronized `*.model-catalog.v1` cache behind `catalog.read` /
//! `catalog.refresh`, and the 18-vendor directory behind
//! `providers.list` — every vendor binding locally through a4mp's own
//! adapters, Google on the Gemini-native protocol and Amazon Nova on
//! the Bedrock SigV4 path.

use std::collections::BTreeSet;
use std::sync::Arc;

use fairliny_gateway::catalog::{CatalogSource, CatalogSync};
use fairliny_gateway::leases::Leases;
use fairliny_gateway::meter::Meter;
use fairliny_gateway::router::{Route, Router};
use fairliny_gateway::service::Service;
use fairliny_gateway::vendors::BASE_VENDORS;
use serde_json::{Value, json};

/// A transport that never consults proxy settings — loopback traffic
/// stays on the loopback interface whatever the environment.
fn loopback_transport() -> Arc<dyn a4mp::Transport> {
    Arc::new(a4mp::ReqwestTransport::with_client(
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("client"),
    ))
}

/// One dispatch, unwrapped: the result value on success, `{"error": …}`
/// carrying the refusal text otherwise.
async fn dispatch(service: &Service, method: &str, params: Value) -> Value {
    let reply = service
        .dispatch(json!("req-1"), Some(method), &params)
        .await;
    match reply.get("error") {
        Some(error) => json!({"error": error.as_str().expect("error text")}),
        None => reply["result"].clone(),
    }
}

const REVISION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// The document the shared `<namespace>.model-catalog.v1` family
/// publishes — a reseller catalog, never credentials.
fn catalog_document() -> Value {
    json!({
        "schemaVersion": "vendor.model-catalog.v1",
        "revision": REVISION,
        "generatedAt": "2026-01-01T00:00:00Z",
        "providers": [{
            "id": "example-reseller",
            "name": "Example Reseller",
            "homepage": "https://reseller.example",
            "docs": "https://reseller.example/docs",
            "kind": "reseller",
            "endpoints": [{"protocol": "openai-chat-completions", "baseUrl": "https://reseller.example/v1"}],
            "auth": {"style": "bearer"},
            "models": [{"id": "vendor/model", "displayName": "Example Model"}],
            "modelsSource": "public-list",
            "modelsStatus": "fresh"
        }]
    })
}

/// The cache file's on-disk shape: the producing source plus the
/// validated document.
fn write_cache(dir: &std::path::Path, source: &str) {
    std::fs::create_dir_all(dir).expect("dir");
    std::fs::write(
        dir.join("model-catalog.json"),
        json!({"source": source, "catalog": catalog_document()}).to_string(),
    )
    .expect("cache");
}

fn service_with(sync: Option<CatalogSync>) -> Service {
    let router = Router::new(loopback_transport(), Arc::new(a4mp::NoCredentials));
    Service::new(router, Meter::unmetered()).with_catalog_sync(sync)
}

#[tokio::test]
async fn catalog_read_serves_the_cache_without_a_fetch() {
    // No sync configured: the method names the refusal.
    let reply = dispatch(&service_with(None), "catalog.read", json!({})).await;
    assert!(
        reply["error"]
            .as_str()
            .expect("error")
            .contains("catalog_not_configured"),
        "{reply}"
    );

    // A configured cache root with nothing written answers empty; a
    // cache written offline — no request ever reached the network —
    // answers the document back.
    let empty = tempfile::tempdir().expect("tempdir");
    let sync = CatalogSync::new(empty.path()).expect("sync");
    let reply = dispatch(&service_with(Some(sync)), "catalog.read", json!({})).await;
    assert_eq!(reply["status"], "empty", "{reply}");

    let dir = tempfile::tempdir().expect("tempdir");
    write_cache(dir.path(), "https://catalog.example/v1/catalog");
    let sync = CatalogSync::new(dir.path()).expect("sync").with_source(
        CatalogSource::from_document(&json!({
            "source": "https://catalog.example/v1/catalog"
        }))
        .expect("source"),
    );
    let reply = dispatch(&service_with(Some(sync)), "catalog.read", json!({})).await;
    assert_eq!(reply["status"], "cached", "{reply}");
    assert_eq!(reply["catalog"]["revision"], REVISION);
}

#[tokio::test]
async fn catalog_refresh_requires_a_configured_source() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sync = CatalogSync::new(dir.path()).expect("sync");
    let reply = dispatch(&service_with(Some(sync)), "catalog.refresh", json!({})).await;
    assert!(
        reply["error"]
            .as_str()
            .expect("error")
            .contains("catalog_source_not_configured"),
        "{reply}"
    );

    // The error surface never carries document or secret material —
    // only the refusal code.
    assert!(reply.get("catalog").is_none());
}

#[tokio::test]
async fn the_catalog_config_member_builds_the_sync() {
    // `{"catalog": {"cacheDir": …, "source": …}}` wires the sync;
    // a member without cacheDir refuses at startup.
    let dir = tempfile::tempdir().expect("tempdir");
    let config = json!({"catalog": {"cacheDir": dir.path(), "source": "https://catalog.example/v1/catalog"}});
    assert!(CatalogSync::from_config(&config).expect("config").is_some());
    assert!(
        CatalogSync::from_config(&json!({}))
            .expect("none")
            .is_none()
    );
    assert!(
        CatalogSync::from_config(&json!({"catalog": {"source": "https://x.example"}})).is_err()
    );
    assert!(
        CatalogSync::from_config(
            &json!({"catalog": {"cacheDir": dir.path(), "source": "http://insecure.example"}})
        )
        .is_err()
    );
}

#[tokio::test]
async fn providers_list_projects_all_eighteen_base_vendors() {
    let service = service_with(None);
    let reply = dispatch(&service, "providers.list", json!({})).await;
    let vendors = reply["vendors"].as_object().expect("vendors");
    assert_eq!(vendors.len(), 18, "{reply}");
    let ids: BTreeSet<_> = vendors.keys().map(String::as_str).collect();
    let expected: BTreeSet<_> = BASE_VENDORS.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, expected);

    // Every vendor declares at least one https endpoint, each on a
    // protocol the gateway's own vocabulary names.
    for (id, vendor) in vendors {
        let endpoints = vendor["endpoints"].as_array().expect("endpoints");
        assert!(!endpoints.is_empty(), "{id}");
        for endpoint in endpoints {
            assert!(
                endpoint["baseUrl"]
                    .as_str()
                    .expect("baseUrl")
                    .starts_with("https://"),
                "{id}"
            );
        }
    }

    // Google speaks the Gemini-native protocol — never a translation.
    let google = &vendors["google"]["endpoints"];
    assert!(
        google
            .as_array()
            .expect("endpoints")
            .iter()
            .any(|endpoint| endpoint["protocol"] == "gemini-generate-content"),
        "{google}"
    );

    // Every entry names its canonical route provider — the profile id a
    // routes document binds; discovery keys may be aliases.
    for (id, profile_id) in BASE_VENDORS {
        assert_eq!(vendors[*id]["provider"], *profile_id, "{id}");
    }

    // Amazon Nova binds through Bedrock's SigV4 surface: the converse
    // protocol, the canonical `amazon-bedrock` provider and the
    // `cloud:aws` mechanism marked as host-resolved — the lease port
    // cannot answer it.
    let nova = &vendors["amazon-nova"];
    assert!(
        nova["endpoints"]
            .as_array()
            .expect("endpoints")
            .iter()
            .any(|endpoint| endpoint["protocol"] == "bedrock-converse"),
        "{nova}"
    );
    assert_eq!(nova["provider"], "amazon-bedrock", "{nova}");
    let mechanisms: Vec<&str> = nova["auth"]
        .as_array()
        .expect("auth")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(mechanisms.contains(&"cloud:aws"), "{nova}");
    // Every emitted mechanism parses as a route `auth` value.
    for mechanism in &mechanisms {
        fairliny_gateway::router::parse_auth(mechanism).expect(mechanism);
    }
    let host_resolver: Vec<&str> = nova["hostResolver"]
        .as_array()
        .expect("hostResolver")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(host_resolver, ["cloud:aws"], "{nova}");

    // Kimi carries both regional choices.
    let regions: BTreeSet<_> = vendors["kimi"]["endpoints"]
        .as_array()
        .expect("endpoints")
        .iter()
        .filter_map(|endpoint| endpoint["region"].as_str())
        .collect();
    assert!(
        regions.contains("intl") && regions.contains("cn"),
        "{regions:?}"
    );
}

/// The `AuthKind` a route declares for the mechanism the profile lists
/// first — api-key where accepted (the common custody path), the
/// profile's own first spec otherwise.
fn declared_auth(profile: &a4mp::ProviderProfile) -> a4mp::AuthKind {
    let auth_kind_for = |spec: &a4mp::AuthSpec| match spec {
        a4mp::AuthSpec::ApiKey => a4mp::AuthKind::ApiKey,
        a4mp::AuthSpec::Bearer | a4mp::AuthSpec::OAuth => a4mp::AuthKind::Bearer,
        a4mp::AuthSpec::CloudIdentity => a4mp::AuthKind::CloudIdentity {
            service: "aws".to_owned(),
        },
        a4mp::AuthSpec::External { client } => a4mp::AuthKind::External {
            client: (*client).to_owned(),
        },
        _ => a4mp::AuthKind::None,
    };
    if profile.auth.contains(&a4mp::AuthSpec::ApiKey) {
        a4mp::AuthKind::ApiKey
    } else {
        auth_kind_for(profile.auth.first().expect("a mechanism"))
    }
}

#[test]
fn every_base_vendor_binds_a_local_route() {
    // For each vendor, every declared https endpoint on a protocol the
    // built-in adapters speak becomes a route: the catalog resolves the
    // profile, the adapter factory binds it, and the live adapter
    // reports the surface the profile declared — the same checks a
    // configured route would face. Profiles may also declare
    // provider-native `other:*` targets no built-in adapter binds —
    // discovery reports them, routing skips them.
    let bindable = |protocol: &a4mp::Protocol| {
        matches!(
            protocol,
            a4mp::Protocol::OpenAiChatCompletions
                | a4mp::Protocol::OpenAiResponses
                | a4mp::Protocol::AnthropicMessages
                | a4mp::Protocol::GeminiGenerateContent
                | a4mp::Protocol::BedrockConverse
        )
    };
    let catalog = a4mp::Catalog::with_builtin_adapters();
    for (vendor, profile_id) in BASE_VENDORS {
        let profile = catalog
            .resolve(profile_id)
            .unwrap_or_else(|| panic!("{vendor}: profile {profile_id}"));
        let auth = declared_auth(profile);
        let mut bound_routes = 0;
        for target in profile
            .targets
            .iter()
            .filter(|def| def.base_url.starts_with("https://") && bindable(&def.protocol))
        {
            let mut router = Router::with_catalog(
                a4mp::Catalog::with_builtin_adapters(),
                loopback_transport(),
                Arc::new(a4mp::NoCredentials),
            );
            let model = format!("{vendor}-{}", target.region.unwrap_or("primary"));
            router
                .add_route(
                    &model,
                    Route {
                        provider: profile.id.clone(),
                        protocol: Some(target.protocol.clone()),
                        region: target.region.map(str::to_owned),
                        auth: auth.clone(),
                        upstream_model: "upstream".to_owned(),
                        vars: Default::default(),
                    },
                )
                .unwrap_or_else(|error| panic!("{vendor} {model}: {error}"));
            let bound = router
                .resolve(&model)
                .unwrap_or_else(|error| panic!("{vendor} {model}: {error}"));
            assert_eq!(
                bound.adapter.target().base_url,
                url::Url::parse(target.base_url).expect("declared url"),
                "{vendor} {model}"
            );
            assert_eq!(bound.adapter.target().protocol, target.protocol, "{vendor}");
            bound_routes += 1;
        }
        assert!(
            bound_routes > 0,
            "{vendor}: no bindable https endpoint in profile {profile_id}"
        );
    }
}

#[test]
fn gemini_binds_its_native_protocol() {
    // Google's profile binds `gemini-generate-content` directly — the
    // adapter's target is the native surface, not an OpenAI-shaped one.
    let catalog = a4mp::Catalog::with_builtin_adapters();
    let profile = catalog.resolve("google").expect("google profile");
    let gemini = profile
        .targets
        .iter()
        .find(|def| matches!(def.protocol, a4mp::Protocol::GeminiGenerateContent))
        .expect("a gemini-generate-content target");
    assert_eq!(gemini.base_url, "https://generativelanguage.googleapis.com");
    let provider = profile.id.clone();
    let mut router =
        Router::with_catalog(catalog, loopback_transport(), Arc::new(a4mp::NoCredentials));
    router
        .add_route(
            "gemini",
            Route {
                provider,
                protocol: Some(a4mp::Protocol::GeminiGenerateContent),
                region: None,
                auth: a4mp::AuthKind::ApiKey,
                upstream_model: "gemini-2.5-pro".to_owned(),
                vars: Default::default(),
            },
        )
        .expect("declare");
    let bound = router.resolve("gemini").expect("bind");
    assert!(matches!(
        bound.adapter.target().protocol,
        a4mp::Protocol::GeminiGenerateContent
    ));
}

#[test]
fn amazon_nova_binds_the_sigv4_path() {
    // Nova routes through the Bedrock profile: the converse protocol
    // target binds under cloud identity — a4mp's SigV4 adapter — the
    // way the AWS surface requires.
    let catalog = a4mp::Catalog::with_builtin_adapters();
    let profile = catalog.resolve("amazon-bedrock").expect("bedrock profile");
    let converse = profile
        .targets
        .iter()
        .find(|def| matches!(def.protocol, a4mp::Protocol::BedrockConverse))
        .expect("a bedrock-converse target");
    let provider = profile.id.clone();
    let region = converse.region.map(str::to_owned);
    let converse_base = converse.base_url;
    let mut router =
        Router::with_catalog(catalog, loopback_transport(), Arc::new(a4mp::NoCredentials));
    router
        .add_route(
            "nova",
            Route {
                provider,
                protocol: Some(a4mp::Protocol::BedrockConverse),
                region,
                auth: a4mp::AuthKind::CloudIdentity {
                    service: "aws".to_owned(),
                },
                upstream_model: "amazon.nova-pro-v1:0".to_owned(),
                vars: Default::default(),
            },
        )
        .expect("declare");
    let bound = router.resolve("nova").expect("bind");
    assert!(matches!(
        bound.adapter.target().protocol,
        a4mp::Protocol::BedrockConverse
    ));
    assert_eq!(
        bound.adapter.target().base_url,
        url::Url::parse(converse_base).expect("declared url")
    );
}

#[tokio::test]
async fn catalog_refresh_runs_beside_the_serve_loop() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    // A source that stalls the TLS handshake parks the refresh task,
    // never the loop: an offline read still answers while the fetch is
    // in flight, and the refresh reply still lands once the fetch ends.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let held = std::thread::spawn(move || {
        let stream = listener.accept().expect("accept").0;
        // Hold the socket open so the handshake stalls until released —
        // a blocking join must never freeze the runtime thread.
        let _ = release_rx.recv();
        drop(stream);
    });

    let dir = tempfile::tempdir().expect("tempdir");
    let source_url = format!("https://{addr}/catalog");
    write_cache(dir.path(), &source_url);
    let source = CatalogSource::from_document(&json!({"source": source_url})).expect("source");
    let sync = CatalogSync::new(dir.path())
        .expect("sync")
        .with_source(source)
        .with_client(
            reqwest::Client::builder()
                .no_proxy()
                .build()
                .expect("client"),
        );
    let service = service_with(Some(sync));

    let (mut requests, input) = tokio::io::duplex(4096);
    let (output, mut replies) = tokio::io::duplex(64 * 1024);
    let serving = tokio::spawn(async move {
        service
            .serve(tokio::io::BufReader::new(input), output)
            .await
            .expect("serve loop");
    });
    requests
        .write_all(
            b"{\"id\":1,\"method\":\"catalog.refresh\",\"params\":{}}\n\
              {\"id\":2,\"method\":\"catalog.read\",\"params\":{}}\n",
        )
        .await
        .expect("requests");

    // The offline read replies while the refresh is still parked — the
    // loop never awaited the network.
    let mut replies = tokio::io::BufReader::new(&mut replies).lines();
    let first = tokio::time::timeout(std::time::Duration::from_secs(30), replies.next_line())
        .await
        .expect("the loop stays responsive")
        .expect("reply line")
        .expect("a reply");
    let first: Value = serde_json::from_str(&first).expect("reply json");
    assert_eq!(first["id"], 2, "{first}");
    assert_eq!(first["result"]["status"], "cached", "{first}");

    // Releasing the stalled socket ends the fetch; EOF then drains the
    // refresh task and its reply still reaches the wire.
    let _ = release_tx.send(());
    drop(requests);
    serving.await.expect("serving");
    held.join().expect("holder");
    let mut saw_refresh_reply = false;
    while let Some(line) = replies.next_line().await.expect("line") {
        let reply: Value = serde_json::from_str(&line).expect("reply json");
        if reply["id"] == 1 {
            assert_eq!(reply["result"]["status"], "stale", "{reply}");
            assert_eq!(reply["result"]["catalog"]["revision"], REVISION, "{reply}");
            saw_refresh_reply = true;
        }
    }
    assert!(saw_refresh_reply, "the refresh reply lands on the wire");
}

#[tokio::test]
async fn a_lost_refresh_reply_fails_the_serve() {
    // The refresh runs off the stdin loop, but its reply still belongs
    // on the wire: a write that cannot land fails the serve instead of
    // reporting a clean exit with the reply lost.
    let dir = tempfile::tempdir().expect("tempdir");
    let sync = CatalogSync::new(dir.path()).expect("sync");
    let service = service_with(Some(sync));
    let (writer, reader) = tokio::io::duplex(64 * 1024);
    drop(reader);
    let input = "{\"id\":1,\"method\":\"catalog.refresh\",\"params\":{}}\n";
    assert!(
        service.serve(input.as_bytes(), writer).await.is_err(),
        "a refresh reply that never lands is a serve failure"
    );
}

#[tokio::test]
async fn a_lost_reply_fails_the_serve_while_input_stays_open() {
    use tokio::io::AsyncWriteExt;

    // The request pipe stays open and silent — nothing more arrives —
    // but the refresh task's failed reply still surfaces: the host
    // sees the serve die instead of a sidecar waiting on stdin
    // forever.
    let dir = tempfile::tempdir().expect("tempdir");
    let sync = CatalogSync::new(dir.path()).expect("sync");
    let service = service_with(Some(sync));
    let (mut requests, input) = tokio::io::duplex(4096);
    let (output, reader) = tokio::io::duplex(64 * 1024);
    drop(reader);
    requests
        .write_all(b"{\"id\":1,\"method\":\"catalog.refresh\",\"params\":{}}\n")
        .await
        .expect("request");
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        service.serve(tokio::io::BufReader::new(input), output),
    )
    .await
    .expect("the serve fails while the request pipe stays open");
    assert!(result.is_err(), "a lost refresh reply is a serve failure");
    drop(requests);
}

#[tokio::test]
async fn a_lease_backed_service_serves_discovery_and_catalog_together() {
    // The sidecar's real shape — a lease-backed router plus a
    // configured sync — answers both projections on one dispatch
    // surface.
    let dir = tempfile::tempdir().expect("tempdir");
    write_cache(dir.path(), "https://catalog.example/v1/catalog");
    let sync = CatalogSync::new(dir.path()).expect("sync");
    let router = Router::with_leases(loopback_transport(), Arc::new(Leases::disconnected()));
    let service = Service::new(router, Meter::unmetered()).with_catalog_sync(Some(sync));
    let reply = dispatch(&service, "providers.list", json!({})).await;
    assert_eq!(reply["vendors"].as_object().expect("vendors").len(), 18);
    let reply = dispatch(&service, "catalog.read", json!({})).await;
    assert_eq!(reply["status"], "cached");
}
