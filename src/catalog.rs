//! Read-only cloud model-catalog synchronization.
//!
//! A host may point Fairliny at a public HTTPS document in the shared
//! `*.model-catalog.v1` family — the reseller/aggregator catalog shape
//! any conforming producer serves — and this module keeps a validated
//! local copy: an explicit refresh revalidates under the cached
//! revision's ETag, a `304` to that same-source revalidation confirms
//! freshness without rewriting the cache, and a document the producer
//! rejected, mangled or never sent leaves the last valid catalog in
//! place. Reads are local-only; the
//! document describes providers and models and never carries
//! credentials, so no lease, key or token ever enters the fetch, the
//! cache or the projections.
//!
//! Refresh is explicit — the sidecar answers `catalog.refresh` requests
//! and never polls on its own timer.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

use crate::{Error, Result};

/// The cache file inside the configured directory.
const CACHE_FILE: &str = "model-catalog.json";
/// The largest document or cache the sync accepts.
const MAX_BODY_BYTES: u64 = 4 * 1024 * 1024;
/// The document-family marker a source must name — the namespace prefix
/// is the producer's own, so the consumer never pins one deployment.
const SCHEMA_SUFFIX: &str = ".model-catalog.v1";

const INVALID: &str = "catalog_invalid";
const REFRESH_FAILED: &str = "catalog_refresh_failed";
const SOURCE_INVALID: &str = "catalog_source_invalid";

fn catalog_error(reason: &str) -> Error {
    Error::Catalog(reason.to_owned())
}

/// The configured read-only source: an HTTPS URL carrying no
/// credentials, query or fragment, and an optional exact schema marker
/// pinning the document family the host expects.
#[derive(Clone)]
pub struct CatalogSource {
    url: Url,
    schema: Option<String>,
}

impl CatalogSource {
    /// Parse `{"source": "https://…", "schema"?: "…"}` — the member a
    /// `catalog` config block carries. `None` or an absent `source`
    /// means offline-only: the cache still reads, refresh refuses.
    pub fn from_document(document: &Value) -> Result<Option<Self>> {
        let Some(source) = document.get("source") else {
            return Ok(None);
        };
        if source.is_null() {
            return Ok(None);
        }
        let source = source
            .as_str()
            .ok_or_else(|| catalog_error(SOURCE_INVALID))?;
        let url = https_url(source).ok_or_else(|| catalog_error(SOURCE_INVALID))?;
        Ok(Some(Self {
            url,
            schema: schema_pin(document)?,
        }))
    }

    /// The URL the refresh fetches.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The schema pin this source configured, if any — `None` accepts
    /// any `<namespace>.model-catalog.v1` family member.
    fn schema(&self) -> Option<&str> {
        self.schema.as_deref()
    }
}

/// The synchronized catalog: a validated cache rooted at `dir`, fed by
/// an optional configured source. The schema pin stands alone from the
/// source — an offline-only store still applies the host's pin to every
/// cache it reads and every document a refresh fetches.
pub struct CatalogSync {
    dir: PathBuf,
    source: Option<CatalogSource>,
    schema: Option<String>,
    client: reqwest::Client,
    /// One refresh at a time: the prior-cache read, the conditional
    /// fetch and the commit run under this lock so a delayed older
    /// response can never overwrite a newer revision another refresh
    /// already committed.
    refresh_lock: tokio::sync::Mutex<()>,
}

impl CatalogSync {
    /// A cache root without a source yet; `with_source` configures one.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self> {
        Ok(Self {
            dir: dir.into(),
            source: None,
            schema: None,
            client: crate::transport::upstream_client()?,
            refresh_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Build from a `catalog` config member `{"cacheDir": "…", "source"?:
    /// "https://…", "schema"?: "…"}` — `None` when no `catalog` member
    /// exists; a `cacheDir` is required when the member does.
    pub fn from_config(config: &Value) -> Result<Option<Self>> {
        let Some(member) = config.get("catalog") else {
            return Ok(None);
        };
        if member.is_null() {
            return Ok(None);
        }
        let dir = member
            .get("cacheDir")
            .and_then(Value::as_str)
            .filter(|dir| !dir.trim().is_empty())
            .ok_or_else(|| catalog_error("catalog config requires a cacheDir"))?;
        let source = CatalogSource::from_document(member)?;
        // A present source already carries the member's pin; only a
        // source-less member stores it on the sync itself.
        let schema = match source.is_some() {
            true => None,
            false => schema_pin(member)?,
        };
        Ok(Some(
            Self::new(dir)?.with_source(source).with_schema(schema),
        ))
    }

    /// Attach the configured source; an absent source keeps the store
    /// offline-only.
    pub fn with_source(mut self, source: Option<CatalogSource>) -> Self {
        self.source = source;
        self
    }

    /// Pin the exact `<namespace>.model-catalog.v1` marker the host
    /// expects — the source's own pin wins when set; this one governs
    /// every cache read and, for an unpinned source, refresh too.
    pub fn with_schema(mut self, schema: Option<String>) -> Self {
        self.schema = schema;
        self
    }

    /// The HTTP client the refresh fetches through, handed over as a
    /// builder the host pre-tunes (proxies, timeouts, pool limits).
    /// Redirect and TLS-verification policy stay under the sync's own
    /// control — the builder is finished with redirects disabled and
    /// certificate verification enforced, so an injected client can
    /// never carry the fetch off the configured HTTPS source or accept
    /// an unverified peer as if it were one.
    pub fn with_client_builder(mut self, builder: reqwest::ClientBuilder) -> Result<Self> {
        self.client = builder
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(false)
            .build()
            .map_err(|_| catalog_error("catalog_client_invalid"))?;
        Ok(self)
    }

    /// The schema pin the host expects: a configured source's own pin
    /// first, else the standalone one.
    fn pin(&self) -> Option<&str> {
        self.source
            .as_ref()
            .and_then(CatalogSource::schema)
            .or(self.schema.as_deref())
    }

    fn cache_path(&self) -> PathBuf {
        self.dir.join(CACHE_FILE)
    }

    /// Read only the local, validated catalog — never a network request.
    pub fn read(&self) -> Result<Value> {
        let Some(text) = read_cache_text(&self.cache_path())? else {
            return Ok(json!({"status": "empty", "catalog": null}));
        };
        let cache = decode_cache(&text, self.pin())?;
        Ok(json!({"status": "cached", "catalog": cache.catalog}))
    }

    /// Fetch the configured source once: an `If-None-Match`
    /// revalidation when the cache holds a revision this same source
    /// wrote, a `304` to that revalidation answering `unchanged` with
    /// no write, a `200` validating and replacing the cache atomically,
    /// and any other answer — a `304` to a request that carried no
    /// same-source revision included — failing the refresh and keeping,
    /// and reporting, the last valid catalog. Without a configured
    /// source, or with no valid catalog to keep, the refresh refuses.
    pub async fn refresh(&self) -> Result<Value> {
        self.refresh_with(async |url, revision| fetch(&self.client, url, revision).await)
            .await
    }

    /// `refresh` with the fetch swapped — the cache semantics live here
    /// so a synthetic fetch exercises them without a network peer.
    async fn refresh_with<F>(&self, fetch: F) -> Result<Value>
    where
        F: AsyncFnOnce(&Url, Option<&str>) -> Result<Option<Catalog>>,
    {
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| catalog_error("catalog_source_not_configured"))?;
        // Serialized per store: each refresh re-reads the committed
        // cache, revalidates from its revision and replaces the file
        // before the next refresh reads — a delayed older fetch can
        // never roll a newer commit back.
        let _refresh = self.refresh_lock.lock().await;
        let path = self.cache_path();
        // One effective pin governs the whole cycle: the prior cache
        // decodes under it and the fetched document validates under it,
        // exactly as `read` serves under it.
        let pin = self.pin();
        // An invalid cached document is replaceable; an unsafe
        // filesystem read is not. The last valid catalog falls back as
        // `stale` whatever source wrote it; only the conditional is
        // source-bound — a revision another URL issued never leaves in
        // `If-None-Match`.
        let cache = read_cache_text(&path)?
            .as_deref()
            .and_then(|text| decode_cache(text, pin).ok());
        let revision = cache
            .as_ref()
            .filter(|cache| cache.source == source.url.as_str())
            .map(|cache| cache.catalog.revision.as_str());
        // `unchanged` belongs to the revalidation that went out: a
        // `304` answering a request that carried no same-source
        // revision confirms nothing about this source and fails the
        // refresh like any other bad answer.
        let revalidated = revision.is_some();
        let updated = fetch(&source.url, revision).await.and_then(|catalog| {
            if let Some(catalog) = &catalog {
                validate(catalog, pin)?;
            }
            Ok(catalog)
        });
        let updated = match (updated, revalidated) {
            (Ok(None), false) => Err(catalog_error(REFRESH_FAILED)),
            (updated, _) => updated,
        };

        match (updated, cache) {
            (Ok(Some(catalog)), prior) => {
                let cache = CachedCatalog {
                    source: source.url.as_str().to_owned(),
                    catalog,
                };
                // The serialized file must stay readable back — a body
                // under the download bound can still overshoot it once
                // the source/catalog wrapper lands. A cache the sync
                // itself could never read again is a refresh failure:
                // keep — and report — the last valid catalog.
                let written = serde_json::to_string(&cache)
                    .map_err(|_| catalog_error(REFRESH_FAILED))
                    .and_then(|text| {
                        if text.len() as u64 > MAX_BODY_BYTES {
                            return Err(catalog_error(REFRESH_FAILED));
                        }
                        write_cache(&path, &text)
                    });
                match (written, prior) {
                    (Ok(()), _) => Ok(json!({"status": "fresh", "catalog": cache.catalog})),
                    (Err(_), Some(prior)) => Ok(json!({
                        "status": "stale",
                        "reasonCode": REFRESH_FAILED,
                        "catalog": prior.catalog,
                    })),
                    (Err(_), None) => Err(catalog_error(REFRESH_FAILED)),
                }
            }
            (Ok(None), Some(cache)) => Ok(json!({"status": "unchanged", "catalog": cache.catalog})),
            (Err(_), Some(cache)) => Ok(json!({
                "status": "stale",
                "reasonCode": REFRESH_FAILED,
                "catalog": cache.catalog,
            })),
            _ => Err(catalog_error(REFRESH_FAILED)),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Catalog {
    schema_version: String,
    revision: String,
    generated_at: String,
    providers: Vec<Provider>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Provider {
    id: String,
    name: String,
    homepage: String,
    docs: String,
    kind: String,
    endpoints: Vec<Endpoint>,
    auth: Auth,
    models: Vec<Model>,
    models_source: ModelsSource,
    models_status: ModelsStatus,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Endpoint {
    protocol: Protocol,
    base_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    region: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Model {
    id: String,
    display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    context_window: Option<u64>,
}

/// The endpoint protocol labels the document family names — the same
/// spellings the reseller schema enumerates.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Protocol {
    OpenaiChatCompletions,
    OpenaiResponses,
    AnthropicMessages,
    GeminiGenerate,
}

/// How the consumer attaches the caller's own credential — the document
/// names the mechanism, never the material.
#[derive(Deserialize, Serialize)]
#[serde(tag = "style", rename_all = "lowercase", deny_unknown_fields)]
enum Auth {
    // An internally tagged unit variant would silently accept unknown
    // fields in Serde, so Bearer carries an empty body.
    Bearer {},
    Header { header: String },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ModelsSource {
    PublicList,
    ClientLive,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum ModelsStatus {
    Fresh,
    Stale,
    None,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CachedCatalog {
    source: String,
    catalog: Catalog,
}

/// An HTTPS URL carrying no credentials, query or fragment — the only
/// shape the read-only source and the document's own links may take.
fn https_url(value: &str) -> Option<Url> {
    let parsed = Url::parse(value).ok()?;
    (parsed.scheme() == "https"
        && parsed.host().is_some()
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && !value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control()))
    .then_some(parsed)
}

fn nonblank(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

/// The kebab id the schema's `id`/`region` pattern requires.
fn id_valid(value: &str) -> bool {
    value.split('-').all(|part| {
        !part.is_empty()
            && part
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    })
}

/// Family membership: a non-empty namespace before the marker — the
/// one rule configured pins, fetched documents and cached documents
/// share. `.model-catalog.v1` alone names no namespace and is outside
/// the family.
fn in_schema_family(schema: &str) -> bool {
    schema.len() > SCHEMA_SUFFIX.len() && schema.ends_with(SCHEMA_SUFFIX)
}

/// Structural validation of one fetched document against the family's
/// published shape — the schema marker: a `<namespace>.model-catalog.v1`
/// member always, and exactly the configured pin when one is set —
/// then the content rules. A document failing any rule is discarded,
/// never cached.
fn validate(catalog: &Catalog, schema: Option<&str>) -> Result<()> {
    let schema_accepted = in_schema_family(&catalog.schema_version)
        && schema.is_none_or(|pin| catalog.schema_version == pin);
    if !(schema_accepted
        && catalog.revision.len() == 64
        && catalog
            .revision
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        && nonblank(&catalog.generated_at)
        && !catalog.providers.is_empty())
    {
        return Err(catalog_error(INVALID));
    }

    let mut provider_ids = BTreeSet::new();
    for provider in &catalog.providers {
        if !(provider.kind == "reseller"
            && id_valid(&provider.id)
            && provider_ids.insert(provider.id.as_str())
            && nonblank(&provider.name)
            && https_url(&provider.homepage).is_some()
            && https_url(&provider.docs).is_some()
            && !provider.endpoints.is_empty()
            && provider.endpoints.iter().all(|endpoint| {
                https_url(&endpoint.base_url).is_some()
                    && endpoint.region.as_deref().is_none_or(id_valid)
            }))
        {
            return Err(catalog_error(INVALID));
        }
        if let Auth::Header { header } = &provider.auth
            && (header.is_empty()
                || !header
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'))
        {
            return Err(catalog_error(INVALID));
        }
        let models_consistent = match (&provider.models_source, &provider.models_status) {
            (ModelsSource::ClientLive, ModelsStatus::None) => provider.models.is_empty(),
            (ModelsSource::PublicList, ModelsStatus::Fresh) => !provider.models.is_empty(),
            (ModelsSource::PublicList, ModelsStatus::Stale) => true,
            _ => false,
        };
        if !models_consistent {
            return Err(catalog_error(INVALID));
        }
        let mut model_ids = BTreeSet::new();
        if !provider.models.iter().all(|model| {
            nonblank(&model.id)
                && model_ids.insert(model.id.as_str())
                && nonblank(&model.display_name)
                && model.context_window != Some(0)
        }) {
            return Err(catalog_error(INVALID));
        }
    }
    Ok(())
}

/// The cache file's raw text — `None` when it does not exist, `Err`
/// when it cannot be read within the size bound.
fn read_cache_text(path: &Path) -> Result<Option<String>> {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.len() > MAX_BODY_BYTES => Err(catalog_error(INVALID)),
        Ok(_) => std::fs::read_to_string(path)
            .map(Some)
            .map_err(|_| catalog_error(INVALID)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(catalog_error(INVALID)),
    }
}

/// The `schema` member's value — a nonblank pin inside the
/// `<namespace>.model-catalog.v1` family or none; a mistyped or
/// off-family member is a source error whether a source exists or not.
fn schema_pin(document: &Value) -> Result<Option<String>> {
    match document.get("schema") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .filter(|schema| nonblank(schema) && in_schema_family(schema))
            .map(|schema| Some(schema.to_owned()))
            .ok_or_else(|| catalog_error(SOURCE_INVALID)),
    }
}

/// A cached document is the same validated shape a fetched one is — and
/// names the source that produced it.
fn decode_cache(text: &str, schema: Option<&str>) -> Result<CachedCatalog> {
    let cache: CachedCatalog = serde_json::from_str(text).map_err(|_| catalog_error(INVALID))?;
    if https_url(&cache.source).is_none_or(|url| url.as_str() != cache.source) {
        return Err(catalog_error(INVALID));
    }
    // The host's schema pin validates the cache when one exists;
    // without one the family check alone decides.
    validate(&cache.catalog, schema)?;
    Ok(cache)
}

/// One conditional GET: `Some(catalog)` on a valid `200`, `None` on a
/// `304` — every other answer is a refresh failure that keeps the last
/// valid catalog.
async fn fetch(
    client: &reqwest::Client,
    source: &Url,
    revision: Option<&str>,
) -> Result<Option<Catalog>> {
    let mut request = client
        .get(source.clone())
        .header(reqwest::header::ACCEPT, "application/json");
    if let Some(revision) = revision {
        request = request.header(reqwest::header::IF_NONE_MATCH, format!("\"{revision}\""));
    }
    let response = request
        .send()
        .await
        .map_err(|_| catalog_error(REFRESH_FAILED))?;
    match response.status() {
        reqwest::StatusCode::NOT_MODIFIED => Ok(None),
        reqwest::StatusCode::OK => decode_response(response, source).await.map(Some),
        _ => Err(catalog_error(REFRESH_FAILED)),
    }
}

/// A `200` is only fresh when it answers from the configured source —
/// the response URL is bound to the HTTPS URL the host configured, so a
/// client that followed a redirect or a downgrade has nothing accepted —
/// carries the revision ETag its body names — the pair the family
/// publishes — and the body stays within the bound.
async fn decode_response(mut response: reqwest::Response, source: &Url) -> Result<Catalog> {
    if response.url() != source {
        return Err(catalog_error(REFRESH_FAILED));
    }
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|tag| tag.to_str().ok())
        .and_then(|tag| tag.strip_prefix('"')?.strip_suffix('"'))
        .map(str::to_owned)
        .ok_or_else(|| catalog_error(REFRESH_FAILED))?;
    if response
        .content_length()
        .is_some_and(|len| len > MAX_BODY_BYTES)
    {
        return Err(catalog_error(REFRESH_FAILED));
    }
    // The Content-Length check is only a fast path: a response without
    // one — or one that lies — is capped chunk by chunk, and the chunk
    // that would take the retained body past the bound refuses the
    // refresh before a byte of it is kept.
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| catalog_error(REFRESH_FAILED))?
    {
        if body.len() as u64 + chunk.len() as u64 > MAX_BODY_BYTES {
            return Err(catalog_error(REFRESH_FAILED));
        }
        body.extend_from_slice(&chunk);
    }
    let catalog: Catalog =
        serde_json::from_slice(&body).map_err(|_| catalog_error(REFRESH_FAILED))?;
    if etag != catalog.revision {
        return Err(catalog_error(REFRESH_FAILED));
    }
    Ok(catalog)
}

/// Replace the cache atomically: write a per-refresh sibling temp file,
/// then rename over the old one, so a crash mid-write never halves the
/// document a later read validates. Each write gets its own temp name —
/// concurrent refreshes never share a writable handle, and one rename
/// can only land a complete file.
fn write_cache(path: &Path, text: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|_| catalog_error(REFRESH_FAILED))?;
    }
    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let temp = path.with_extension(format!(
        "{}.{}.tmp",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = std::fs::write(&temp, text).and_then(|()| std::fs::rename(&temp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result.map_err(|_| catalog_error(REFRESH_FAILED))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, Write};

    const REVISION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER_REVISION: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// A schema-family document with the given revision — the shape any
    /// `<namespace>.model-catalog.v1` producer serves.
    fn fixture(revision: &str) -> Value {
        json!({
            "schemaVersion": "vendor.model-catalog.v1",
            "revision": revision,
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

    fn catalog(revision: &str) -> Catalog {
        serde_json::from_value(fixture(revision)).expect("fixture")
    }

    /// The fixture under another family marker — a conforming document
    /// from a different namespace.
    fn catalog_as(revision: &str, schema: &str) -> Catalog {
        let mut doc = fixture(revision);
        doc["schemaVersion"] = schema.into();
        serde_json::from_value(doc).expect("fixture")
    }

    fn source(url: &str) -> CatalogSource {
        CatalogSource {
            url: https_url(url).expect("source url"),
            schema: None,
        }
    }

    /// A loopback peer answering one request with a canned status and
    /// body, recording what the client sent.
    fn mock_server(
        status: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> (Url, std::thread::JoinHandle<Vec<(String, String)>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("addr");
        let status = status.to_owned();
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let body = body.to_owned();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone"));
            let mut request_line = String::new();
            reader.read_line(&mut request_line).expect("request line");
            let mut request_headers = Vec::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).expect("header line");
                let line = line.trim_end();
                if line.is_empty() {
                    break;
                }
                let (key, value) = line.split_once(':').expect("header");
                request_headers.push((key.trim().to_owned(), value.trim().to_owned()));
            }
            let mut stream = stream;
            write!(stream, "HTTP/1.1 {status}\r\n").expect("status");
            for (key, value) in &headers {
                write!(stream, "{key}: {value}\r\n").expect("header");
            }
            write!(
                stream,
                "content-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
            .expect("reply");
            request_headers
        });
        (
            Url::parse(&format!("http://{addr}/catalog")).expect("url"),
            handle,
        )
    }

    fn fetch_client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("client")
    }

    #[tokio::test]
    async fn a_304_revalidates_without_a_body() {
        let (url, handle) = mock_server("304 Not Modified", &[], "");
        let answer = fetch(&fetch_client(), &url, Some(REVISION))
            .await
            .expect("a 304 is a successful revalidation");
        assert!(answer.is_none());
        let headers = handle.join().expect("server");
        let if_none_match = headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("if-none-match"))
            .map(|(_, value)| value.as_str());
        assert_eq!(if_none_match, Some(format!("\"{REVISION}\"")).as_deref());
    }

    #[tokio::test]
    async fn a_200_requires_the_revision_etag() {
        let body = fixture(REVISION).to_string();
        let (url, handle) = mock_server("200 OK", &[("etag", &format!("\"{REVISION}\""))], &body);
        let answer = fetch(&fetch_client(), &url, None)
            .await
            .expect("a matching etag yields the catalog")
            .expect("a 200 carries a catalog");
        assert_eq!(answer.revision, REVISION);
        handle.join().expect("server");

        // A mismatched or absent ETag is a refresh failure, not a
        // catalog — the body alone is never trusted.
        for headers in [vec![("etag", format!("\"{OTHER_REVISION}\""))], vec![]] {
            let (url, handle) = mock_server(
                "200 OK",
                &headers
                    .iter()
                    .map(|(k, v)| (*k, v.as_str()))
                    .collect::<Vec<_>>(),
                &body,
            );
            assert!(fetch(&fetch_client(), &url, None).await.is_err());
            handle.join().expect("server");
        }
    }

    #[tokio::test]
    async fn any_other_status_is_a_refresh_failure() {
        for status in [
            "500 Internal Server Error",
            "404 Not Found",
            "403 Forbidden",
        ] {
            let (url, handle) = mock_server(status, &[], "");
            assert!(fetch(&fetch_client(), &url, Some(REVISION)).await.is_err());
            handle.join().expect("server");
        }
    }

    fn store(dir: &std::path::Path, url: &str) -> CatalogSync {
        CatalogSync {
            dir: dir.to_owned(),
            source: Some(source(url)),
            schema: None,
            client: fetch_client(),
            refresh_lock: tokio::sync::Mutex::new(()),
        }
    }

    #[tokio::test]
    async fn a_fresh_fetch_writes_the_cache_and_304_keeps_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sync = store(dir.path(), "https://catalog.example/v1/catalog");
        let written = sync
            .refresh_with(async |_, revision| {
                assert!(revision.is_none());
                Ok(Some(catalog(REVISION)))
            })
            .await
            .expect("first refresh");
        assert_eq!(written["status"], "fresh");
        let cache_text = std::fs::read_to_string(dir.path().join(CACHE_FILE)).expect("cache");
        assert!(cache_text.contains(REVISION));

        // The cached revision goes out as the conditional tag; a 304
        // (None) answers unchanged and the file is untouched.
        let unchanged = sync
            .refresh_with(async |_, revision| {
                assert_eq!(revision, Some(REVISION));
                Ok(None)
            })
            .await
            .expect("revalidation");
        assert_eq!(unchanged["status"], "unchanged");
        assert_eq!(
            std::fs::read_to_string(dir.path().join(CACHE_FILE)).expect("cache"),
            cache_text,
            "a 304 never rewrites the cache"
        );
    }

    #[tokio::test]
    async fn a_failed_or_invalid_refresh_keeps_the_last_valid_catalog() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sync = store(dir.path(), "https://catalog.example/v1/catalog");
        sync.refresh_with(async |_, _| Ok(Some(catalog(REVISION))))
            .await
            .expect("seed");

        // A transport failure reports stale and keeps the catalog.
        let stale = sync
            .refresh_with(async |_, _| Err(catalog_error(REFRESH_FAILED)))
            .await
            .expect("a failed refresh still answers");
        assert_eq!(stale["status"], "stale");
        assert_eq!(stale["reasonCode"], REFRESH_FAILED);
        assert_eq!(stale["catalog"]["revision"], REVISION);

        // A malformed document the fetch produced is equally a stale
        // keep: validation runs before the cache decision.
        let malformed = catalog("not-hex");
        let stale = sync
            .refresh_with(async |_, _| Ok(Some(malformed)))
            .await
            .expect("an invalid document still answers stale");
        assert_eq!(stale["status"], "stale");
        assert_eq!(stale["catalog"]["revision"], REVISION);

        // With nothing valid to keep, a failure refuses outright.
        let empty_dir = tempfile::tempdir().expect("tempdir");
        let sync = store(empty_dir.path(), "https://catalog.example/v1/catalog");
        assert!(
            sync.refresh_with(async |_, _| Err(catalog_error(REFRESH_FAILED)))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_stray_304_after_a_source_change_is_a_stale_keep() {
        // The source moved: the retained cache's revision belongs to
        // the previous URL, so no `If-None-Match` goes out. A `304`
        // answering that unconditional request confirms nothing about
        // the new source — the refresh fails and the last valid catalog
        // stays as `stale`, never an `unchanged`.
        let dir = tempfile::tempdir().expect("tempdir");
        let seeded = store(dir.path(), "https://catalog.example/v1/catalog");
        seeded
            .refresh_with(async |_, _| Ok(Some(catalog(REVISION))))
            .await
            .expect("seed");

        let moved = store(dir.path(), "https://catalog-b.example/v1/catalog");
        let stale = moved
            .refresh_with(async |_, revision| {
                assert_eq!(revision, None, "another source's ETag never goes out");
                Ok(None)
            })
            .await
            .expect("a stray 304 still answers");
        assert_eq!(stale["status"], "stale");
        assert_eq!(stale["reasonCode"], REFRESH_FAILED);
        assert_eq!(stale["catalog"]["revision"], REVISION);
        assert_eq!(
            moved.read().expect("read")["catalog"]["revision"],
            REVISION,
            "the stray 304 never touched the cache"
        );
    }

    #[tokio::test]
    async fn an_offline_read_answers_the_cache_or_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sync = store(dir.path(), "https://catalog.example/v1/catalog");
        assert_eq!(sync.read().expect("read")["status"], "empty");
        sync.refresh_with(async |_, _| Ok(Some(catalog(REVISION))))
            .await
            .expect("seed");
        let read = sync.read().expect("read");
        assert_eq!(read["status"], "cached");
        assert_eq!(read["catalog"]["revision"], REVISION);
    }

    #[tokio::test]
    async fn an_offline_read_honors_the_schema_pin() {
        // A pin without a source still constrains the cache: a document
        // from another namespace is invalid, never silently served.
        let dir = tempfile::tempdir().expect("tempdir");
        let sync = store(dir.path(), "https://catalog.example/v1/catalog");
        sync.refresh_with(async |_, _| Ok(Some(catalog(REVISION))))
            .await
            .expect("seed");

        let pinned = CatalogSync::new(dir.path())
            .expect("sync")
            .with_schema(Some("acme.model-catalog.v1".to_owned()));
        assert!(pinned.read().is_err());
        let pinned = pinned.with_schema(Some("vendor.model-catalog.v1".to_owned()));
        assert_eq!(pinned.read().expect("read")["status"], "cached");
        assert_eq!(
            pinned.with_schema(None).read().expect("read")["status"],
            "cached"
        );

        // A source-less `catalog` member carrying `schema` pins the same
        // way — and a mistyped pin refuses at config.
        let config = json!({"catalog": {
            "cacheDir": dir.path(),
            "schema": "acme.model-catalog.v1",
        }});
        let sync = CatalogSync::from_config(&config)
            .expect("config")
            .expect("sync");
        assert!(sync.read().is_err());
        assert!(
            CatalogSync::from_config(&json!({"catalog": {
                "cacheDir": dir.path(),
                "schema": "   ",
            }}))
            .is_err()
        );
    }

    #[tokio::test]
    async fn the_standalone_pin_governs_refresh_and_read() {
        // An unpinned source with an SDK-set pin: the prior cache
        // decodes and the fetched document validates under the same
        // effective pin `read` serves — a different-namespace document
        // is a stale keep, never a fresh write the next read rejects.
        let dir = tempfile::tempdir().expect("tempdir");
        let sync = store(dir.path(), "https://catalog.example/v1/catalog")
            .with_schema(Some("acme.model-catalog.v1".to_owned()));
        sync.refresh_with(async |_, _| Ok(Some(catalog_as(REVISION, "acme.model-catalog.v1"))))
            .await
            .expect("seed under the pin");

        let stale = sync
            .refresh_with(async |_, revision| {
                assert_eq!(revision, Some(REVISION));
                Ok(Some(catalog(OTHER_REVISION)))
            })
            .await
            .expect("an off-pin document still answers stale");
        assert_eq!(stale["status"], "stale");
        assert_eq!(stale["catalog"]["revision"], REVISION);
        assert_eq!(
            sync.read().expect("read")["catalog"]["revision"],
            REVISION,
            "the pinned cache was never replaced"
        );

        // A cache written under another namespace is no revalidation
        // base either: the pinned decode rejects it, the fetch goes
        // out bare and the fresh write lands under the pin.
        let foreign = CachedCatalog {
            source: "https://catalog.example/v1/catalog".to_owned(),
            catalog: catalog(OTHER_REVISION),
        };
        std::fs::write(
            dir.path().join(CACHE_FILE),
            serde_json::to_string(&foreign).expect("serialize"),
        )
        .expect("cache");
        let fresh = sync
            .refresh_with(async |_, revision| {
                assert_eq!(revision, None, "an off-pin cache sends no ETag");
                Ok(Some(catalog_as(OTHER_REVISION, "acme.model-catalog.v1")))
            })
            .await
            .expect("refresh");
        assert_eq!(fresh["status"], "fresh");
        assert_eq!(
            sync.read().expect("read")["catalog"]["revision"],
            OTHER_REVISION
        );
    }

    #[tokio::test]
    async fn overlapping_refreshes_commit_in_order() {
        use std::sync::Arc;

        // The read/fetch/commit cycle is serialized per store: the
        // second refresh's fetch does not run until the first refresh
        // committed, so a delayed older response never rolls the cache
        // back.
        let dir = tempfile::tempdir().expect("tempdir");
        let sync = Arc::new(store(dir.path(), "https://catalog.example/v1/catalog"));
        let entered = Arc::new(tokio::sync::Notify::new());
        let committed = Arc::new(AtomicU64::new(0));
        let (gate_tx, gate_rx) = tokio::sync::oneshot::channel::<()>();
        let first = tokio::spawn({
            let sync = Arc::clone(&sync);
            let entered = Arc::clone(&entered);
            let committed = Arc::clone(&committed);
            async move {
                let result = sync
                    .refresh_with(async |_, _| {
                        entered.notify_one();
                        gate_rx.await.expect("gate");
                        Ok(Some(catalog(REVISION)))
                    })
                    .await;
                committed.store(1, Ordering::SeqCst);
                result
            }
        });
        let second = tokio::spawn({
            let sync = Arc::clone(&sync);
            async move {
                entered.notified().await;
                sync.refresh_with(async |_, _| {
                    assert_eq!(
                        committed.load(Ordering::SeqCst),
                        1,
                        "a second fetch waits for the first commit"
                    );
                    Ok(Some(catalog(OTHER_REVISION)))
                })
                .await
            }
        });
        tokio::task::yield_now().await;
        gate_tx.send(()).expect("release the first fetch");
        assert_eq!(
            first.await.expect("first task").expect("refresh")["status"],
            "fresh"
        );
        assert_eq!(
            second.await.expect("second task").expect("refresh")["status"],
            "fresh"
        );
        assert_eq!(
            sync.read().expect("read")["catalog"]["revision"],
            OTHER_REVISION,
            "the last commit is the last refresh's document"
        );
    }

    #[tokio::test]
    async fn a_schema_pin_must_be_a_family_member() {
        // The documented pin is an exact `<namespace>.model-catalog.v1`
        // marker — a pin naming another family refuses at configuration
        // instead of letting an off-family cache through on a match.
        for bad in [
            "unrelated.schema.v9",
            "vendor.model-catalog.v2",
            ".model-catalog.v1",
        ] {
            assert!(
                CatalogSource::from_document(&json!({
                    "source": "https://catalog.example/v1/catalog",
                    "schema": bad,
                }))
                .is_err(),
                "{bad}"
            );
            assert!(
                CatalogSync::from_config(&json!({"catalog": {
                    "cacheDir": "unused",
                    "schema": bad,
                }}))
                .is_err(),
                "{bad}"
            );
        }
        assert!(
            CatalogSource::from_document(&json!({
                "source": "https://catalog.example/v1/catalog",
                "schema": "acme.model-catalog.v1",
            }))
            .expect("a family pin")
            .is_some()
        );

        // And a directly-set off-family pin can never accept a
        // document: the family check stands beside the exact match.
        let doc = catalog_as(REVISION, "unrelated.schema.v9");
        assert!(validate(&doc, Some("unrelated.schema.v9")).is_err());
    }

    #[tokio::test]
    async fn an_empty_namespace_is_outside_the_family() {
        // The family is `<namespace>.model-catalog.v1` — the bare
        // suffix names no namespace, and document validation applies
        // the same rule the pin parser does.
        let bare = catalog_as(REVISION, ".model-catalog.v1");
        assert!(validate(&bare, None).is_err());
        assert!(validate(&bare, Some("vendor.model-catalog.v1")).is_err());

        // A fetched bare-suffix document never caches: the refused
        // refresh leaves the empty store empty.
        let dir = tempfile::tempdir().expect("tempdir");
        let sync = store(dir.path(), "https://catalog.example/v1/catalog");
        assert!(
            sync.refresh_with(async |_, _| Ok(Some(catalog_as(REVISION, ".model-catalog.v1"))))
                .await
                .is_err()
        );
        assert_eq!(sync.read().expect("read")["status"], "empty");

        // And one planted in the cache never serves: the cached path
        // validates the same way.
        let foreign = CachedCatalog {
            source: "https://catalog.example/v1/catalog".to_owned(),
            catalog: catalog_as(REVISION, ".model-catalog.v1"),
        };
        std::fs::write(
            dir.path().join(CACHE_FILE),
            serde_json::to_string(&foreign).expect("serialize"),
        )
        .expect("cache");
        assert!(sync.read().is_err());
    }

    #[tokio::test]
    async fn a_write_failure_keeps_and_reports_the_last_valid_catalog() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sync = store(dir.path(), "https://catalog.example/v1/catalog");
        sync.refresh_with(async |_, _| Ok(Some(catalog(REVISION))))
            .await
            .expect("seed");
        let before = std::fs::read_to_string(dir.path().join(CACHE_FILE)).expect("cache");

        // An unwritable cache directory makes the temp write fail: the
        // refresh still answers the prior catalog as stale, the file is
        // untouched and no temp litter remains.
        let mut permissions = std::fs::metadata(dir.path())
            .expect("metadata")
            .permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(dir.path(), permissions).expect("readonly");
        let stale = sync
            .refresh_with(async |_, _| Ok(Some(catalog(OTHER_REVISION))))
            .await
            .expect("a failed write still answers");
        let mut permissions = std::fs::metadata(dir.path())
            .expect("metadata")
            .permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        std::fs::set_permissions(dir.path(), permissions).expect("writable");
        assert_eq!(stale["status"], "stale");
        assert_eq!(stale["reasonCode"], REFRESH_FAILED);
        assert_eq!(stale["catalog"]["revision"], REVISION);
        assert_eq!(
            std::fs::read_to_string(dir.path().join(CACHE_FILE)).expect("cache"),
            before,
            "the prior file is preserved"
        );
        assert!(
            std::fs::read_dir(dir.path())
                .expect("dir")
                .all(|entry| !entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")),
            "no temp file survives a failed write"
        );
    }

    #[tokio::test]
    async fn an_unreadable_serialized_cache_keeps_the_prior_file() {
        // A document near the bound can serialize past it once the
        // source/catalog wrapper lands — such a cache could never be
        // read back, so the refresh is a stale keep, not a fresh write.
        let dir = tempfile::tempdir().expect("tempdir");
        let sync = store(dir.path(), "https://catalog.example/v1/catalog");
        sync.refresh_with(async |_, _| Ok(Some(catalog(REVISION))))
            .await
            .expect("seed");
        let before = std::fs::read_to_string(dir.path().join(CACHE_FILE)).expect("cache");

        let mut oversized = catalog(OTHER_REVISION);
        oversized.providers[0].name = "x".repeat(MAX_BODY_BYTES as usize);
        let stale = sync
            .refresh_with(async |_, _| Ok(Some(oversized)))
            .await
            .expect("an unreadable cache still answers stale");
        assert_eq!(stale["status"], "stale");
        assert_eq!(stale["catalog"]["revision"], REVISION);
        assert_eq!(
            std::fs::read_to_string(dir.path().join(CACHE_FILE)).expect("cache"),
            before,
            "the oversized cache never replaced the prior file"
        );
    }

    #[test]
    fn the_source_shape_is_https_without_credentials() {
        for bad in [
            "http://catalog.example/v1/catalog",
            "https://user:pass@catalog.example/v1/catalog",
            "https://catalog.example/v1/catalog?key=1",
            "https://catalog.example/v1/catalog#frag",
            "not-a-url",
        ] {
            assert!(
                CatalogSource::from_document(&json!({"source": bad})).is_err(),
                "{bad}"
            );
        }
        assert!(
            CatalogSource::from_document(&json!({"source": "https://catalog.example/v1/catalog"}))
                .expect("source")
                .is_some()
        );
        assert!(
            CatalogSource::from_document(&json!({}))
                .expect("none")
                .is_none()
        );
    }

    #[test]
    fn validation_enforces_the_family_shape() {
        let pinned = CatalogSource {
            url: https_url("https://catalog.example/v1/catalog").expect("url"),
            schema: Some("acme.model-catalog.v1".to_owned()),
        };
        // The family suffix passes unconfigured; a configured pin
        // requires an exact marker.
        validate(&catalog(REVISION), None).expect("family doc");
        assert!(validate(&catalog(REVISION), pinned.schema()).is_err());

        let mut wrong_schema = fixture(REVISION);
        wrong_schema["schemaVersion"] = "acme.model-catalog.v1".into();
        let doc: Catalog = serde_json::from_value(wrong_schema).expect("doc");
        validate(&doc, pinned.schema()).expect("the pinned schema");

        // A document outside the family fails structural validation.
        let mut wrong = fixture(REVISION);
        wrong["providers"][0]["kind"] = "not-a-reseller".into();
        let doc: Catalog = serde_json::from_value(wrong).expect("doc");
        assert!(validate(&doc, None).is_err());
    }
}
