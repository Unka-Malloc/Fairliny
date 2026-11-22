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
/// `AuthSpec` in the same spelling `models.list` emits for `AuthKind`
/// (OAuth rides the bearer channel at bind time).
fn auth_spec_label(spec: &a4mp::AuthSpec) -> String {
    match spec {
        a4mp::AuthSpec::None => "none".to_owned(),
        a4mp::AuthSpec::ApiKey => "api-key".to_owned(),
        a4mp::AuthSpec::Bearer | a4mp::AuthSpec::OAuth => "bearer".to_owned(),
        a4mp::AuthSpec::CloudIdentity => "cloud-identity".to_owned(),
        a4mp::AuthSpec::External { client } => format!("external:{client}"),
        other => format!("other:{other:?}"),
    }
}

/// A static https base URL — the only declared endpoint shape the
/// directory reports; templated or cleartext surfaces stay out.
fn static_https(base_url: &str) -> bool {
    url::Url::parse(base_url).is_ok_and(|url| {
        url.scheme() == "https" && url.username().is_empty() && url.password().is_none()
    })
}

/// Project one profile's declared endpoints for the directory.
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
    json!({
        "name": profile.name,
        "auth": profile.auth.iter().map(auth_spec_label).collect::<Vec<_>>(),
        "endpoints": endpoints,
    })
}

/// The vendor directory over a4mp's catalog: `{vendors: {id: {name,
/// auth, endpoints}}}` in [`BASE_VENDORS`] order. Any profile the
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
