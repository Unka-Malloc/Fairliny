//! Model routing onto bound a4mp adapters.
//!
//! The router owns the outward face's one indirection: the model name a
//! caller sends is never the name the upstream sees. A [`Route`] binds an
//! outward name to one provider access surface — catalog profile,
//! optional protocol and region pins, the auth mechanism the host will
//! answer, and the upstream model id — and [`Router::resolve`] turns the
//! binding into a live a4mp [`Adapter`].
//!
//! Failure is closed by construction: an unknown model is refused before
//! any provider is touched, a route can only name a provider the catalog
//! carries and an auth mechanism its profile accepts, and an adapter the
//! host bound itself arrives already live through
//! [`Router::register_adapter`]. The router holds no credential material —
//! it hands a4mp the resolver and the lease port answers per call.

use std::collections::BTreeMap;
use std::sync::Arc;

use a4mp::{Adapter, AuthKind, AuthSpec, CredentialResolver, Protocol, ProviderId, Transport};
use serde_json::Value;

use crate::{Error, Result};

/// One outward model name bound to a provider access surface.
#[derive(Clone, Debug)]
pub struct Route {
    /// The catalog profile this model forwards to.
    pub provider: ProviderId,
    /// The protocol family to bind, or the profile's primary target.
    pub protocol: Option<Protocol>,
    /// A regional plan the profile declares, when the route pins one.
    pub region: Option<String>,
    /// The mechanism the adapter asks the resolver for. The profile must
    /// accept it — a route cannot widen a profile's access surface.
    pub auth: AuthKind,
    /// The identifier the upstream call receives. May differ from the
    /// outward name so aliases never leak deployment naming upstream.
    pub upstream_model: String,
    /// Endpoint variables the profile's target template requires —
    /// `{endpoint}` for runtime-supplied base URLs, `{resource}`-class
    /// atoms for per-resource clouds. Supplied per route so no address is
    /// ever built into the catalog.
    pub vars: BTreeMap<String, String>,
}

impl Route {
    /// Parse one routes-document entry `{model, provider, upstreamModel?,
    /// protocol?, region?, auth?}` into the outward name and its route.
    /// The protocol and auth vocabulary is the same table `models.list`
    /// renders and errors quote: every label the gateway emits is a label
    /// the document accepts.
    pub fn from_document(entry: &Value) -> Result<(String, Self)> {
        let invalid = |field: &str| Error::Request(format!("route entry requires a valid {field}"));
        let model = entry
            .get("model")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("model"))?
            .to_owned();
        let provider = entry
            .get("provider")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("provider"))?;
        let protocol = entry
            .get("protocol")
            .and_then(Value::as_str)
            .map(parse_protocol)
            .transpose()?;
        let auth = parse_auth(entry.get("auth").and_then(Value::as_str).unwrap_or("none"))?;
        let upstream_model = entry
            .get("upstreamModel")
            .and_then(Value::as_str)
            .unwrap_or(&model)
            .to_owned();
        let vars = entry
            .get("vars")
            .map(|v| {
                v.as_object()
                    .map(|m| {
                        m.iter()
                            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_owned()))
                            .collect()
                    })
                    .ok_or_else(|| invalid("vars"))
            })
            .transpose()?
            .unwrap_or_default();
        Ok((
            model,
            Self {
                provider: ProviderId::new(provider),
                protocol,
                region: entry
                    .get("region")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                auth,
                upstream_model,
                vars,
            },
        ))
    }
}

/// A resolved route: the bound adapter and what the upstream call is for.
pub struct BoundRoute {
    /// The live adapter a4mp bound for this target.
    pub adapter: Arc<dyn Adapter>,
    /// The model id placed on the outgoing request.
    pub upstream_model: String,
    /// The profile the request forwards through.
    pub provider: ProviderId,
}

/// The outward name table plus the a4mp composition underneath it.
///
/// Binding is per call: adapters are cheap to construct over the shared
/// transport and the credential resolver answers per request, so a
/// rotated lease takes effect on the very next forward — there is no
/// adapter-side credential cache to go stale.
pub struct Router {
    client: a4mp::Client,
    routes: BTreeMap<String, Route>,
    /// Adapters the host bound itself — custom surfaces and test stubs.
    /// They skip profile checks because the host already owns the binding.
    prebound: BTreeMap<String, (Arc<dyn Adapter>, String)>,
}

impl Router {
    /// A router over the catalog's built-in provider profiles and adapter
    /// factories: one shared transport, one credential resolver.
    pub fn new(transport: Arc<dyn Transport>, resolver: Arc<dyn CredentialResolver>) -> Self {
        Self::with_catalog(a4mp::Catalog::with_builtin_adapters(), transport, resolver)
    }

    /// A router over an explicit catalog — the shape a host uses when it
    /// carries its own profile set or adapter factories.
    pub fn with_catalog(
        catalog: a4mp::Catalog,
        transport: Arc<dyn Transport>,
        resolver: Arc<dyn CredentialResolver>,
    ) -> Self {
        Self {
            client: a4mp::Client::new(catalog, transport, resolver),
            routes: BTreeMap::new(),
            prebound: BTreeMap::new(),
        }
    }

    /// Bind an outward model name to a catalog provider surface.
    ///
    /// Fails closed at declaration time: the provider must resolve through
    /// the catalog and the profile must accept the declared auth mechanism,
    /// so a typo'd route is refused before traffic ever reaches it.
    pub fn add_route(&mut self, model: impl Into<String>, route: Route) -> Result<()> {
        let model = model.into();
        let profile = self
            .client
            .catalog()
            .resolve(route.provider.as_str())
            .ok_or_else(|| Error::Route {
                model: model.clone(),
                reason: format!("unknown provider {}", route.provider),
            })?;
        if !accepts(&profile.auth, &route.auth) {
            return Err(Error::Route {
                model,
                reason: format!(
                    "profile {} does not accept {}",
                    profile.id,
                    auth_label(&route.auth)
                ),
            });
        }
        self.routes.insert(model, route);
        Ok(())
    }

    /// Load a routes document `{"routes":[{model,provider,...}]}`.
    /// A malformed entry refuses the whole table — the gateway never
    /// silently runs half a route table.
    pub fn load_routes(&mut self, document: &Value) -> Result<()> {
        let empty = Vec::new();
        let routes = document
            .get("routes")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        for entry in routes {
            let (model, route) = Route::from_document(entry)?;
            self.add_route(model, route)?;
        }
        Ok(())
    }

    /// Register an adapter the host bound itself under an outward name.
    /// The host owns the binding — no profile check applies.
    pub fn register_adapter(
        &mut self,
        model: impl Into<String>,
        upstream_model: impl Into<String>,
        adapter: Arc<dyn Adapter>,
    ) {
        self.prebound
            .insert(model.into(), (adapter, upstream_model.into()));
    }

    /// The declared routes, for read-only projections.
    pub fn routes(&self) -> impl Iterator<Item = (&String, &Route)> {
        self.routes.iter()
    }

    /// The host-bound adapters, for read-only projections.
    pub fn prebound(&self) -> impl Iterator<Item = (&String, &Arc<dyn Adapter>, &String)> {
        self.prebound
            .iter()
            .map(|(model, (adapter, upstream))| (model, adapter, upstream))
    }

    /// Resolve an outward model name to a live adapter.
    ///
    /// Unknown names are refused before the catalog is touched; binding
    /// failures relay the adapter's own refusal — an auth kind the profile
    /// does not carry, a protocol with no adapter factory, a target the
    /// profile cannot materialize.
    pub fn resolve(&self, model: &str) -> Result<BoundRoute> {
        if let Some((adapter, upstream_model)) = self.prebound.get(model) {
            return Ok(BoundRoute {
                adapter: adapter.clone(),
                upstream_model: upstream_model.clone(),
                provider: adapter.target().provider.clone(),
            });
        }
        let route = self
            .routes
            .get(model)
            .ok_or_else(|| Error::UnknownModel(model.to_owned()))?;
        let vars = route
            .vars
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let adapter = self
            .client
            .bind_provider_with(
                route.provider.as_str(),
                route.protocol.clone(),
                route.region.as_deref(),
                route.auth.clone(),
                &vars,
            )
            .map_err(|error| Error::Route {
                model: model.to_owned(),
                reason: error.to_string(),
            })?;
        Ok(BoundRoute {
            adapter,
            upstream_model: route.upstream_model.clone(),
            provider: route.provider.clone(),
        })
    }
}

/// Whether a profile's accepted mechanisms cover the mechanism the route
/// declares. An `OAuth` profile accepts `Bearer` — the issued token *is*
/// the bearer credential the flow produces; `External` must name the same
/// client so a route cannot ride another application's login.
fn accepts(specs: &[AuthSpec], auth: &AuthKind) -> bool {
    specs.iter().any(|spec| match (spec, auth) {
        (AuthSpec::None, AuthKind::None)
        | (AuthSpec::ApiKey, AuthKind::ApiKey)
        | (AuthSpec::Bearer | AuthSpec::OAuth, AuthKind::Bearer)
        | (AuthSpec::CloudIdentity, AuthKind::CloudIdentity { .. }) => true,
        (AuthSpec::External { client }, AuthKind::External { client: named }) => {
            *client == named.as_str()
        }
        _ => false,
    })
}

/// The protocol labels `models.list` renders, back to the enum — one
/// table both directions share. Named variants carry a stable label; a
/// provider-native protocol and any variant the table does not name emit
/// `other:<name>`, a spelling [`parse_protocol`] always accepts — every
/// label the gateway emits is a label the routes document parses.
const PROTOCOL_VOCABULARY: &[(&str, Protocol)] = &[
    ("openai-chat-completions", Protocol::OpenAiChatCompletions),
    ("openai-responses", Protocol::OpenAiResponses),
    ("anthropic-messages", Protocol::AnthropicMessages),
    ("gemini-generate-content", Protocol::GeminiGenerateContent),
    ("bedrock-converse", Protocol::BedrockConverse),
];

/// The protocol name `models.list` reports — a stable label, not the enum.
pub fn protocol_label(protocol: &Protocol) -> String {
    if let Some((label, _)) = PROTOCOL_VOCABULARY
        .iter()
        .find(|(_, known)| known == protocol)
    {
        return (*label).to_owned();
    }
    match protocol {
        Protocol::Other(name) => format!("other:{name}"),
        other => format!("other:{other:?}"),
    }
}

/// The protocol labels `models.list` reports, back to the enum. `other:x`
/// declares the provider-native protocol `x` — the same spelling
/// [`protocol_label`] emits for `Protocol::Other`.
pub fn parse_protocol(label: &str) -> Result<Protocol> {
    if let Some((_, protocol)) = PROTOCOL_VOCABULARY
        .iter()
        .find(|(known, _)| *known == label)
    {
        return Ok(protocol.clone());
    }
    match label.strip_prefix("other:") {
        Some(name) => Ok(Protocol::Other(name.to_owned())),
        None => Err(Error::Request(format!("unknown protocol {label:?}"))),
    }
}

/// The mechanism name projections and errors may show.
///
/// A mechanism the table does not name emits `other:<name>` — the same
/// spelling [`parse_auth`] reads back, so the label never describes a
/// route the document could not declare.
pub fn auth_label(auth: &AuthKind) -> String {
    match auth {
        AuthKind::None => "none".to_owned(),
        AuthKind::ApiKey => "api-key".to_owned(),
        AuthKind::Bearer => "bearer".to_owned(),
        AuthKind::CloudIdentity { service } => format!("cloud:{service}"),
        AuthKind::External { client } => format!("external:{client}"),
        other => format!("other:{other:?}"),
    }
}

/// The auth labels `models.list` reports, back to the kind. `other:x`
/// declares a mechanism outside the named kinds; the only way to bind
/// one is the named external client the profile must still accept.
pub fn parse_auth(label: &str) -> Result<AuthKind> {
    match label {
        "none" => Ok(AuthKind::None),
        "api-key" => Ok(AuthKind::ApiKey),
        "bearer" => Ok(AuthKind::Bearer),
        _ => match label.split_once(':') {
            Some(("cloud", service)) => Ok(AuthKind::CloudIdentity {
                service: service.to_owned(),
            }),
            Some(("external" | "other", client)) => Ok(AuthKind::External {
                client: client.to_owned(),
            }),
            _ => Err(Error::Request(format!("unknown auth {label:?}"))),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_acceptance_is_exact_or_the_flows_own_shape() {
        assert!(accepts(&[AuthSpec::ApiKey], &AuthKind::ApiKey));
        assert!(accepts(&[AuthSpec::Bearer], &AuthKind::Bearer));
        assert!(accepts(&[AuthSpec::OAuth], &AuthKind::Bearer));
        assert!(!accepts(&[AuthSpec::ApiKey], &AuthKind::Bearer));
        assert!(!accepts(&[AuthSpec::Bearer], &AuthKind::ApiKey));
        assert!(accepts(&[AuthSpec::None], &AuthKind::None));
        assert!(accepts(
            &[AuthSpec::External { client: "a" }],
            &AuthKind::External {
                client: "a".to_owned()
            }
        ));
        assert!(!accepts(
            &[AuthSpec::External { client: "a" }],
            &AuthKind::External {
                client: "b".to_owned()
            }
        ));
    }

    #[test]
    fn the_vocabulary_round_trips_every_label_it_emits() {
        // Named variants carry stable labels in both directions.
        for (label, protocol) in PROTOCOL_VOCABULARY {
            assert_eq!(protocol_label(protocol), *label);
            assert_eq!(parse_protocol(label).ok().as_ref(), Some(protocol));
        }
        for (label, auth) in [
            ("none", AuthKind::None),
            ("api-key", AuthKind::ApiKey),
            ("bearer", AuthKind::Bearer),
            (
                "cloud:services:govcloud",
                AuthKind::CloudIdentity {
                    service: "services:govcloud".to_owned(),
                },
            ),
            (
                "external:acme.sso",
                AuthKind::External {
                    client: "acme.sso".to_owned(),
                },
            ),
        ] {
            assert_eq!(auth_label(&auth), label);
            // Parsed kinds have no `PartialEq`; the label read back from
            // the parse is the total-mapped check.
            assert_eq!(auth_label(&parse_auth(label).expect(label)), label);
        }
        // `other:` spellings emit and parse under the same rule — a
        // provider-native protocol keeps its name; an unnamed auth
        // mechanism binds as the named external client it declares.
        assert_eq!(
            parse_protocol(&protocol_label(&Protocol::Other("ollama".to_owned()))).expect("other"),
            Protocol::Other("ollama".to_owned())
        );
        assert_eq!(
            auth_label(&parse_auth("other:acme").expect("auth")),
            "external:acme"
        );
        assert!(parse_protocol("made-up-protocol").is_err());
        assert!(parse_auth("made-up-auth").is_err());
    }

    #[test]
    fn a_document_entry_parses_or_refuses_as_one_piece() {
        let (model, route) = Route::from_document(&serde_json::json!({
            "model": "chat",
            "provider": "ollama",
            "upstreamModel": "llama3.1",
            "protocol": "other:ollama",
            "auth": "none"
        }))
        .expect("entry");
        assert_eq!(model, "chat");
        assert_eq!(route.upstream_model, "llama3.1");
        assert_eq!(route.protocol, Some(Protocol::Other("ollama".to_owned())));

        // A missing required field or an unknown vocabulary word refuses
        // the entry — never a half-parsed route.
        for entry in [
            serde_json::json!({"provider": "ollama"}),
            serde_json::json!({"model": "m", "provider": "ollama", "auth": "oauth-magic"}),
            serde_json::json!({"model": "m", "provider": "ollama", "protocol": "grpc"}),
        ] {
            assert!(Route::from_document(&entry).is_err(), "{entry}");
        }
    }
}
