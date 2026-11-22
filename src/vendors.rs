//! The base-vendor directory: the foundation-model providers Fairliny
//! routes natively through a4mp, projected for route discovery.
//!
//! Every vendor in the table names the a4mp catalog profile carrying
//! its declared endpoints — the profile owns the authoritative base
//! URLs, regional variants and protocols, so the projection can never
//! drift from what [`Router`](crate::router::Router) actually binds.
//! Google's profile carries the Gemini-native `gemini-generate-content`
//! protocol and Amazon Nova binds through the Bedrock profile's
//! SigV4/cloud-identity path — both are a4mp's own adapters, not
//! translations onto an OpenAI-shaped wire.

use serde_json::{Value, json};

use crate::router::protocol_label;
use crate::{Error, Result};

/// `(outward vendor id, a4mp profile id)` — the base-vendor set Fairliny
/// discovers natively. Aliases absorb the names that differ from their
/// profile: Kimi binds Moonshot AI, Zhipu's current and legacy regions
/// share one profile, and Amazon Nova rides the Bedrock profile's
/// SigV4 path.
pub const BASE_VENDORS: &[(&str, &str)] = &[
    ("openai", "openai"),
    ("anthropic", "anthropic"),
    ("google", "google"),
    ("xai", "xai"),
    ("mistral", "mistral"),
    ("cohere", "cohere"),
    ("deepseek", "deepseek"),
    ("kimi", "moonshotai"),
    ("zhipu", "zhipu"),
    ("minimax", "minimax"),
    ("alibaba", "alibaba"),
    ("volcengine", "volcengine"),
    ("baidu-qianfan", "baidu-qianfan"),
    ("tencent-tokenhub", "tencent-tokenhub"),
    ("stepfun", "stepfun"),
    ("xiaomi", "xiaomi"),
    ("meta", "meta"),
    ("amazon-nova", "amazon-bedrock"),
];

/// The mechanism labels a vendor profile accepts — a projection of
/// `AuthSpec` in the same spelling a routes document and `models.list`
/// use for `AuthKind` (OAuth rides the bearer channel at bind time, and
/// the table's one cloud-identity profile is Bedrock's SigV4 path,
/// `cloud:aws`). Every label emitted is one the route parser accepts.
fn auth_spec_label(spec: &a4mp::AuthSpec) -> String {
    match spec {
        a4mp::AuthSpec::None => "none".to_owned(),
        a4mp::AuthSpec::ApiKey => "api-key".to_owned(),
        a4mp::AuthSpec::Bearer | a4mp::AuthSpec::OAuth => "bearer".to_owned(),
        a4mp::AuthSpec::CloudIdentity => "cloud:aws".to_owned(),
        a4mp::AuthSpec::External { client } => format!("external:{client}"),
        other => format!("other:{other:?}"),
    }
}

/// Whether the sidecar's lease port can answer a mechanism — the leased
/// kinds only. `cloud:*` and `external:*`/`other:*` mechanisms resolve
/// through a host-supplied SDK resolver instead.
fn leased(label: &str) -> bool {
    matches!(label, "none" | "api-key" | "bearer")
}

/// A static https base URL — the only declared endpoint shape the
/// directory reports; templated or cleartext surfaces stay out.
fn static_https(base_url: &str) -> bool {
    url::Url::parse(base_url).is_ok_and(|url| {
        url.scheme() == "https" && url.username().is_empty() && url.password().is_none()
    })
}

/// Project one profile for the directory: `provider` is the canonical
/// profile id a routes document names — the discovery key may be an
/// alias the catalog resolves elsewhere (`amazon-nova` also resolves
/// the distinct `nova` profile, so the key alone cannot name the
/// route). `auth` lists the accepted mechanisms in route spelling, and
/// `hostResolver` marks the subset the sidecar's lease port cannot
/// answer — Bedrock SigV4 needs the host's own SDK resolver.
fn vendor_entry(profile: &a4mp::ProviderProfile) -> Value {
    let endpoints: Vec<Value> = profile
        .targets
        .iter()
        .filter(|def| static_https(def.base_url))
        .map(|def| {
            let mut endpoint = json!({
                "baseUrl": def.base_url,
                "protocol": protocol_label(&def.protocol),
            });
            if let Some(region) = def.region {
                endpoint["region"] = region.into();
            }
            endpoint
        })
        .collect();
    let auth: Vec<String> = profile.auth.iter().map(auth_spec_label).collect();
    let host_resolver: Vec<&str> = auth
        .iter()
        .filter(|label| !leased(label))
        .map(String::as_str)
        .collect();
    let mut entry = json!({
        "name": profile.name,
        "provider": profile.id.as_str(),
        "auth": auth,
        "endpoints": endpoints,
    });
    if !host_resolver.is_empty() {
        entry["hostResolver"] = host_resolver.into();
    }
    entry
}

/// The vendor directory over a4mp's catalog: `{vendors: {id: {name,
/// provider, auth, hostResolver?, endpoints}}}` in [`BASE_VENDORS`]
/// order. Any profile the
/// dependency dropped is an error rather than a silently shorter
/// table — the declared set is a contract.
pub fn directory(catalog: &a4mp::Catalog) -> Result<Value> {
    let mut vendors = serde_json::Map::new();
    for (id, profile_id) in BASE_VENDORS {
        let profile = catalog.resolve(profile_id).ok_or_else(|| Error::Route {
            model: (*id).to_owned(),
            reason: format!("a4mp catalog carries no profile {profile_id:?}"),
        })?;
        vendors.insert((*id).to_owned(), vendor_entry(profile));
    }
    Ok(json!({ "vendors": vendors }))
}
