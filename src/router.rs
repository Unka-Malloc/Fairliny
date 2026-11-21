//! Model routing onto bound a4mp adapters.
//!
//! The router owns the outward face's one indirection: the model name a
//! caller sends is never the name the upstream sees. A [`Route`] binds an
//! outward name to one provider access surface — a catalog profile with
//! optional protocol and region pins, or an explicit endpoint the host
//! declares outside the catalog — plus the auth mechanism the host will
//! answer and the upstream model id, and [`Router::resolve`] turns the
//! binding into a live a4mp [`Adapter`].
//!
//! Failure is closed by construction: an unknown model is refused before
//! any provider is touched, a profile route can only name a provider the
//! catalog carries and an auth mechanism its profile accepts, an endpoint
//! route can only reach its URL under the cleartext-credential policy
//! a4mp applies to profile endpoints, and an adapter the host bound
//! itself arrives already live through [`Router::register_adapter`]. The
//! router holds no credential material — it hands a4mp the resolver and
//! the lease port answers per call.

use std::collections::BTreeMap;
use std::sync::Arc;

use a4mp::{
    Adapter, AuthKind, AuthSpec, CredentialResolver, Protocol, ProviderId, ServiceTarget, Transport,
};
use serde_json::Value;
use url::Url;

use crate::{Error, Result};

/// The provider id endpoint routes bind under. An endpoint route names no
/// catalog profile; its adapter and its metering namespace
/// (`custom.usage`) carry this id instead.
pub const CUSTOM_PROVIDER: &str = "custom";

/// Where a route forwards: a catalog profile or an explicit endpoint.
#[derive(Clone, Debug)]
pub enum Access {
    /// A provider profile the a4mp catalog carries.
    Profile {
        /// The catalog profile this model forwards to.
        provider: ProviderId,
        /// The protocol family to bind, or the profile's primary target.
        protocol: Option<Protocol>,
        /// A regional plan the profile declares, when the route pins one.
        region: Option<String>,
        /// Endpoint variables the profile's target template requires —
        /// `{endpoint}` for runtime-supplied base URLs, `{resource}`-class
        /// atoms for per-resource clouds. Supplied per route so no address
        /// is ever built into the catalog.
        vars: BTreeMap<String, String>,
    },
    /// A service the catalog does not carry, declared entirely by the
    /// host: base URL plus the wire protocol it speaks.
    Endpoint {
        /// The base URL protocol paths join onto. `http(s)` only, with no
        /// embedded credentials, query or fragment.
        base_url: Url,
        /// The wire protocol family the endpoint speaks.
        protocol: Protocol,
        /// The header the host expects the credential in. a4mp's adapter
        /// for `protocol` owns credential placement, so this is a declared
        /// expectation checked against that placement, never a new one.
        auth_header: Option<String>,
    },
}

/// One outward model name bound to a provider access surface.
#[derive(Clone, Debug)]
pub struct Route {
    /// The surface this model forwards to.
    pub access: Access,
    /// The mechanism the adapter asks the resolver for. A profile must
    /// accept it — a route cannot widen a profile's access surface.
    pub auth: AuthKind,
    /// The identifier the upstream call receives. May differ from the
    /// outward name so aliases never leak deployment naming upstream.
    pub upstream_model: String,
}

impl Route {
    /// Parse one routes-document entry into the outward name and its
    /// route. An entry names exactly one surface: `{model, provider,
    /// protocol?, region?, vars?, auth?, upstreamModel?}` for a catalog
    /// profile, or `{model, endpoint: {baseUrl, protocol}, auth?,
    /// authHeader?, upstreamModel?}` for an explicit endpoint.
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
        let auth = parse_auth(entry.get("auth").and_then(Value::as_str).unwrap_or("none"))?;
        let upstream_model = entry
            .get("upstreamModel")
            .and_then(Value::as_str)
            .unwrap_or(&model)
            .to_owned();
        let protocol = |value: Option<&Value>| {
            value
                .map(|v| v.as_str().ok_or_else(|| invalid("protocol")))
                .transpose()?
                .map(parse_protocol)
                .transpose()
        };
        let access = match (entry.get("provider"), entry.get("endpoint")) {
            (Some(_), Some(_)) => {
                return Err(Error::Request(
                    "route entry names both a provider and an endpoint".to_owned(),
                ));
            }
            (None, None) => {
                return Err(Error::Request(
                    "route entry requires a provider or an endpoint".to_owned(),
                ));
            }
            (Some(provider), None) => {
                let provider = provider.as_str().ok_or_else(|| invalid("provider"))?;
                if entry.get("authHeader").is_some() {
                    return Err(Error::Request(
                        "authHeader applies to endpoint routes; a profile's adapter \
                         places its own credential"
                            .to_owned(),
                    ));
                }
                Access::Profile {
                    provider: ProviderId::new(provider),
                    protocol: protocol(entry.get("protocol"))?,
                    region: entry
                        .get("region")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    vars: parse_vars(entry.get("vars"))?,
                }
            }
            (None, Some(endpoint)) => {
                if let Some(field) = ["protocol", "region", "vars"]
                    .into_iter()
                    .find(|field| entry.get(field).is_some())
                {
                    return Err(Error::Request(format!(
                        "an endpoint route declares no top-level {field}: the \
                         protocol belongs inside endpoint"
                    )));
                }
                let base_url = endpoint
                    .get("baseUrl")
                    .and_then(Value::as_str)
                    .and_then(|url| Url::parse(url).ok())
                    .ok_or_else(|| invalid("endpoint.baseUrl"))?;
                Access::Endpoint {
                    base_url,
                    protocol: protocol(endpoint.get("protocol"))?
                        .ok_or_else(|| invalid("endpoint.protocol"))?,
                    auth_header: entry
                        .get("authHeader")
                        .map(|v| v.as_str().ok_or_else(|| invalid("authHeader")))
                        .transpose()?
                        .map(str::to_owned),
                }
            }
        };
        Ok((
            model,
            Self {
                access,
                auth,
                upstream_model,
            },
        ))
    }
}

/// `vars` fails closed: a non-object or a non-string value refuses the
/// entry — a supplied variable is never silently bound to "".
fn parse_vars(vars: Option<&Value>) -> Result<BTreeMap<String, String>> {
    let invalid = |field: &str| Error::Request(format!("route entry requires a valid {field}"));
    let Some(vars) = vars else {
        return Ok(BTreeMap::new());
    };
    vars.as_object()
        .ok_or_else(|| invalid("vars"))?
        .iter()
        .map(|(k, v)| {
            v.as_str()
                .map(|value| (k.clone(), value.to_owned()))
                .ok_or_else(|| invalid(&format!("vars.{k}")))
        })
        .collect()
}

/// A resolved route: the bound adapter and what the upstream call is for.
pub struct BoundRoute {
    /// The live adapter a4mp bound for this target.
    pub adapter: Arc<dyn Adapter>,
    /// The model id placed on the outgoing request.
    pub upstream_model: String,
    /// The profile the request forwards through — [`CUSTOM_PROVIDER`]
    /// for an endpoint route.
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

    /// Bind an outward model name to a provider surface.
    ///
    /// Fails closed at declaration time. A profile route's provider must
    /// resolve through the catalog, the profile must accept the declared
    /// auth mechanism, and the declared variables must materialize the
    /// profile's target template. An endpoint route's URL must be a bare
    /// `http(s)` base under the cleartext-credential policy, and a
    /// declared `auth_header` must be where a4mp places the credential.
    /// The same bind `resolve` performs is run once here, so a typo'd
    /// provider, mechanism, variable key or protocol is refused before
    /// traffic ever reaches the route, not at first `chat.complete`.
    pub fn add_route(&mut self, model: impl Into<String>, route: Route) -> Result<()> {
        let model = model.into();
        let refuse = |reason: String| Error::Route {
            model: model.clone(),
            reason,
        };
        match &route.access {
            Access::Profile { provider, .. } => {
                let profile = self
                    .client
                    .catalog()
                    .resolve(provider.as_str())
                    .ok_or_else(|| refuse(format!("unknown provider {provider}")))?;
                if !accepts(&profile.auth, &route.auth) {
                    return Err(refuse(format!(
                        "profile {} does not accept {}",
                        profile.id,
                        auth_label(&route.auth)
                    )));
                }
            }
            Access::Endpoint {
                base_url,
                protocol,
                auth_header,
            } => {
                check_base_url(base_url).map_err(refuse)?;
                if let Some(header) = auth_header {
                    check_auth_header(protocol, &route.auth, header).map_err(refuse)?;
                }
            }
        }
        // Declaration binds once and drops the adapter — resolve binds
        // its own per call. Running the bind here is what refuses a
        // missing or misspelled endpoint variable, an unbound protocol or
        // a cleartext credential path at startup.
        self.bind(&route).map_err(refuse)?;
        self.routes.insert(model, route);
        Ok(())
    }

    /// Load a routes document `{"routes":[{model,provider|endpoint,...}]}`.
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
        let adapter = self.bind(route).map_err(|reason| Error::Route {
            model: model.to_owned(),
            reason,
        })?;
        Ok(BoundRoute {
            adapter,
            upstream_model: route.upstream_model.clone(),
            provider: match &route.access {
                Access::Profile { provider, .. } => provider.clone(),
                Access::Endpoint { .. } => ProviderId::new(CUSTOM_PROVIDER),
            },
        })
    }

    /// The one bind both declaration and resolution run.
    fn bind(&self, route: &Route) -> std::result::Result<Arc<dyn Adapter>, String> {
        match &route.access {
            Access::Profile {
                provider,
                protocol,
                region,
                vars,
            } => self.client.bind_provider_with(
                provider.as_str(),
                protocol.clone(),
                region.as_deref(),
                route.auth.clone(),
                &bind_vars(vars),
            ),
            Access::Endpoint {
                base_url, protocol, ..
            } => {
                check_cleartext_policy(base_url, &route.auth)?;
                self.client.bind_target(
                    ServiceTarget::new(CUSTOM_PROVIDER, protocol.clone(), base_url.clone()),
                    route.auth.clone(),
                )
            }
        }
        .map_err(|error| error.to_string())
    }
}

/// The endpoint authority `models.list` may show: host and explicit
/// port. The base URL never carries credentials ([`check_base_url`]), and
/// its path stays out of projections.
pub fn endpoint_authority(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    }
}

/// An endpoint base URL is a bare `http(s)` base: a host, no embedded
/// credentials (secret bytes would ride every projection of the route),
/// and no query or fragment (protocol path joins would silently drop
/// them). The refusal never quotes the URL.
fn check_base_url(url: &Url) -> std::result::Result<(), String> {
    let bare = matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some_and(|host| !host.is_empty())
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none();
    if bare {
        Ok(())
    } else {
        Err(
            "endpoint.baseUrl must be an http(s) URL with a host and no \
             credentials, query or fragment"
                .to_owned(),
        )
    }
}

/// The cleartext policy a4mp 0.4.0 applies to every profile endpoint
/// (`a4mp::catalog::check_endpoint_url` and
/// `check_cleartext_credential_policy`, both private, enforced inside
/// `Client::bind_provider_with` but not `Client::bind_target`), restated
/// once for endpoint routes:
///
/// - `https` binds anywhere;
/// - `http` binds only toward a private or loopback authority —
///   `localhost`, `*.localhost`, `*.internal`, or a loopback, private,
///   link-local or CGNAT IP literal;
/// - a credential-bearing `http` bind (every auth kind but `None`) is
///   further confined to a literal authority — a private/loopback IP
///   literal or `localhost`/`*.localhost` — because a named private host
///   resolves through DNS and can answer a public address;
/// - any other scheme is refused.
fn check_cleartext_policy(url: &Url, auth: &AuthKind) -> std::result::Result<(), String> {
    let literal = |domain: &str| domain == "localhost" || domain.ends_with(".localhost");
    let (private, literal_private) = match url.host() {
        Some(url::Host::Domain(domain)) => (
            literal(domain) || domain.ends_with(".internal"),
            literal(domain),
        ),
        Some(url::Host::Ipv4(ip)) => {
            let private = ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 0x40);
            (private, private)
        }
        Some(url::Host::Ipv6(ip)) => {
            let private = ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local();
            (private, private)
        }
        None => (false, false),
    };
    match url.scheme() {
        "https" => Ok(()),
        "http" if !private => Err("endpoint uses cleartext http to a public host — the \
             endpoint must be https or a private/loopback authority \
             (localhost, a loopback/private/link-local IP, or an .internal name)"
            .to_owned()),
        "http" if !literal_private && !matches!(auth, AuthKind::None) => {
            Err("endpoint is cleartext http to a resolved name — a \
                 credential-bearing bind requires https or a literal \
                 private/loopback authority (an IP literal or localhost)"
                .to_owned())
        }
        "http" => Ok(()),
        _ => Err("endpoint must be an http(s) URL".to_owned()),
    }
}

/// The header a4mp 0.4.0's built-in adapter for `protocol` places a
/// leased credential in (each adapter's `authenticate`): OpenAI-family,
/// Ollama, Cohere and Bedrock send `Authorization: Bearer` for both API
/// keys and bearer material; Anthropic sends an API key as `x-api-key`
/// and Gemini as `x-goog-api-key`, bearer material as `Authorization`.
/// `None` when no leased credential rides the request or the protocol's
/// adapter is not one of the built-ins this table describes.
fn credential_header(protocol: &Protocol, auth: &AuthKind) -> Option<&'static str> {
    let api_key = match auth {
        AuthKind::ApiKey => true,
        AuthKind::Bearer => false,
        _ => return None,
    };
    match protocol {
        Protocol::AnthropicMessages if api_key => Some("x-api-key"),
        Protocol::GeminiGenerateContent if api_key => Some("x-goog-api-key"),
        Protocol::OpenAiChatCompletions
        | Protocol::OpenAiResponses
        | Protocol::AnthropicMessages
        | Protocol::GeminiGenerateContent
        | Protocol::BedrockConverse => Some("authorization"),
        Protocol::Other(name) if name == "ollama" || name == "cohere" => Some("authorization"),
        _ => None,
    }
}

/// A declared `authHeader` must name the header a4mp already places the
/// credential in. a4mp's `AuthKind` carries no header name and its
/// adapters fix placement per protocol, so a different header cannot be
/// expressed — the route is refused rather than sending the credential
/// somewhere the host did not expect.
fn check_auth_header(
    protocol: &Protocol,
    auth: &AuthKind,
    header: &str,
) -> std::result::Result<(), String> {
    match credential_header(protocol, auth) {
        Some(placed) if placed.eq_ignore_ascii_case(header) => Ok(()),
        Some(placed) => Err(format!(
            "authHeader {header:?} is not expressible: a4mp sends {} for {} in {placed:?}",
            auth_label(auth),
            protocol_label(protocol),
        )),
        None => Err(format!(
            "authHeader {header:?} is not expressible: no leased credential header \
             is placed for {} over {}",
            auth_label(auth),
            protocol_label(protocol),
        )),
    }
}

/// The endpoint variables in the shape `bind_provider_with` takes.
fn bind_vars(vars: &BTreeMap<String, String>) -> BTreeMap<&str, &str> {
    vars.iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect()
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
            "auth": "none",
            "vars": {"endpoint": "http://localhost:11434"}
        }))
        .expect("entry");
        assert_eq!(model, "chat");
        assert_eq!(route.upstream_model, "llama3.1");
        let Access::Profile { protocol, vars, .. } = &route.access else {
            panic!("a provider entry is a profile route");
        };
        assert_eq!(protocol, &Some(Protocol::Other("ollama".to_owned())));
        assert_eq!(vars["endpoint"], "http://localhost:11434");

        // A missing required field or an unknown vocabulary word refuses
        // the entry — never a half-parsed route.
        for entry in [
            serde_json::json!({"provider": "ollama"}),
            serde_json::json!({"model": "m", "provider": "ollama", "auth": "oauth-magic"}),
            serde_json::json!({"model": "m", "provider": "ollama", "protocol": "grpc"}),
        ] {
            assert!(Route::from_document(&entry).is_err(), "{entry}");
        }

        // `vars` fails closed the same way: a non-object or a non-string
        // value refuses the entry — a supplied variable is never
        // silently bound to "".
        for entry in [
            serde_json::json!({"model": "m", "provider": "ollama", "vars": "notanobject"}),
            serde_json::json!({"model": "m", "provider": "ollama", "vars": {"endpoint": 42}}),
            serde_json::json!({"model": "m", "provider": "ollama", "vars": {"endpoint": null}}),
        ] {
            let error = Route::from_document(&entry).expect_err("malformed vars refuse");
            assert!(error.to_string().contains("vars"), "{entry}: {error}");
        }
    }

    /// A router over the built-in catalog whose transport is never
    /// invoked — declaration binds adapters but sends nothing.
    fn declaring_router() -> Router {
        Router::new(
            Arc::new(a4mp::ReqwestTransport::new()),
            Arc::new(a4mp::NoCredentials),
        )
    }

    fn declare(entry: Value) -> Result<()> {
        declaring_router().load_routes(&serde_json::json!({ "routes": [entry] }))
    }

    #[test]
    fn an_endpoint_entry_parses_into_a_custom_surface() {
        let (model, route) = Route::from_document(&serde_json::json!({
            "model": "vendor-chat",
            "endpoint": {"baseUrl": "https://api.vendor.example/v1", "protocol": "anthropic-messages"},
            "auth": "api-key",
            "authHeader": "x-api-key",
            "upstreamModel": "vendor-large"
        }))
        .expect("entry");
        assert_eq!(model, "vendor-chat");
        assert_eq!(route.upstream_model, "vendor-large");
        assert_eq!(auth_label(&route.auth), "api-key");
        let Access::Endpoint {
            base_url,
            protocol,
            auth_header,
        } = &route.access
        else {
            panic!("an endpoint entry is an endpoint route");
        };
        assert_eq!(base_url.as_str(), "https://api.vendor.example/v1");
        assert_eq!(protocol, &Protocol::AnthropicMessages);
        assert_eq!(auth_header.as_deref(), Some("x-api-key"));
        assert_eq!(endpoint_authority(base_url), "api.vendor.example");

        // Every protocol label the vocabulary names declares an endpoint.
        for (label, _) in PROTOCOL_VOCABULARY {
            let (_, route) = Route::from_document(&serde_json::json!({
                "model": "m",
                "endpoint": {"baseUrl": "https://api.vendor.example", "protocol": label}
            }))
            .expect(label);
            assert!(matches!(route.access, Access::Endpoint { .. }), "{label}");
        }

        let mut router = declaring_router();
        router.add_route(model, route).expect("declared");
        let bound = router.resolve("vendor-chat").expect("bound");
        assert_eq!(bound.provider.as_str(), CUSTOM_PROVIDER);
        assert_eq!(bound.upstream_model, "vendor-large");
        assert_eq!(bound.adapter.target().protocol, Protocol::AnthropicMessages);
    }

    #[test]
    fn an_entry_names_exactly_one_surface() {
        let endpoint = serde_json::json!({"baseUrl": "https://api.vendor.example", "protocol": "openai-responses"});
        for (entry, needle) in [
            (
                serde_json::json!({"model": "m", "provider": "openai", "endpoint": endpoint}),
                "both",
            ),
            (serde_json::json!({"model": "m"}), "provider or an endpoint"),
            (
                serde_json::json!({"model": "m", "endpoint": endpoint, "protocol": "openai-responses"}),
                "top-level protocol",
            ),
            (
                serde_json::json!({"model": "m", "endpoint": endpoint, "vars": {}}),
                "top-level vars",
            ),
            (
                serde_json::json!({"model": "m", "provider": "openai", "authHeader": "authorization"}),
                "authHeader",
            ),
        ] {
            let error = Route::from_document(&entry).expect_err("refused");
            assert!(error.to_string().contains(needle), "{entry}: {error}");
        }
    }

    #[test]
    fn an_endpoint_refuses_unknown_protocols_and_bad_urls() {
        let entry = |url: &str, protocol: &str| serde_json::json!({"model": "m", "endpoint": {"baseUrl": url, "protocol": protocol}});
        // An unnamed label fails parsing; an `other:` protocol with no
        // adapter factory fails the declaration bind.
        assert!(Route::from_document(&entry("https://a.example", "grpc")).is_err());
        assert!(
            Route::from_document(
                &serde_json::json!({"model": "m", "endpoint": {"baseUrl": "https://a.example"}})
            )
            .is_err()
        );
        let error = declare(entry("https://a.example", "other:no-such-wire")).expect_err("unbound");
        assert!(error.to_string().contains("no adapter"), "{error}");

        // Unparseable, non-http, credential-bearing, query or fragment
        // URLs refuse — and the refusal never quotes the URL.
        assert!(Route::from_document(&entry("not a url", "openai-chat-completions")).is_err());
        for url in [
            "ftp://a.example/v1",
            "https://user:hunter2@a.example/v1",
            "https://a.example/v1?key=hunter2",
            "https://a.example/v1#frag",
        ] {
            let error = declare(entry(url, "openai-chat-completions")).expect_err(url);
            assert!(error.to_string().contains("baseUrl"), "{url}: {error}");
            assert!(!error.to_string().contains("hunter2"), "{url}: {error}");
        }
    }

    #[test]
    fn the_auth_header_must_be_where_a4mp_places_the_credential() {
        let entry = |protocol: &str, auth: &str, header: &str| {
            serde_json::json!({
                "model": "m",
                "endpoint": {"baseUrl": "https://api.vendor.example", "protocol": protocol},
                "auth": auth,
                "authHeader": header
            })
        };
        for (protocol, auth, header) in [
            ("anthropic-messages", "api-key", "x-api-key"),
            ("anthropic-messages", "bearer", "Authorization"),
            ("openai-chat-completions", "api-key", "authorization"),
            ("openai-responses", "bearer", "authorization"),
            ("gemini-generate-content", "api-key", "x-goog-api-key"),
        ] {
            declare(entry(protocol, auth, header)).expect(header);
        }
        // a4mp carries no header name in `AuthKind`: a header its adapter
        // does not use is refused, naming the placement it does use.
        let error = declare(entry("openai-chat-completions", "api-key", "x-api-key"))
            .expect_err("openai sends authorization");
        assert!(error.to_string().contains("\"authorization\""), "{error}");
        let error = declare(entry("openai-chat-completions", "none", "authorization"))
            .expect_err("no credential, no header");
        assert!(error.to_string().contains("not expressible"), "{error}");
        assert!(
            Route::from_document(&serde_json::json!({
                "model": "m",
                "endpoint": {"baseUrl": "https://a.example", "protocol": "openai-responses"},
                "authHeader": 7
            }))
            .is_err()
        );
    }

    #[test]
    fn endpoint_routes_keep_a4mps_cleartext_credential_policy() {
        let check =
            |url: &str, auth: AuthKind| check_cleartext_policy(&Url::parse(url).expect(url), &auth);
        // https binds anywhere, with or without credentials.
        assert!(check("https://api.vendor.example/v1", AuthKind::ApiKey).is_ok());
        // Cleartext to a public host is refused whatever the auth.
        assert!(check("http://api.vendor.example/v1", AuthKind::ApiKey).is_err());
        assert!(check("http://api.vendor.example/v1", AuthKind::None).is_err());
        assert!(check("http://8.8.8.8/v1", AuthKind::None).is_err());
        // Credentials may cross cleartext only to a literal authority.
        assert!(check("http://127.0.0.1:8080/v1", AuthKind::ApiKey).is_ok());
        assert!(check("http://[::1]:8080/v1", AuthKind::Bearer).is_ok());
        assert!(check("http://10.0.0.7/v1", AuthKind::Bearer).is_ok());
        assert!(check("http://localhost:11434", AuthKind::ApiKey).is_ok());
        assert!(check("http://gpu.localhost:11434", AuthKind::ApiKey).is_ok());
        // A named private host resolves through DNS: no cleartext
        // credentials, but a credential-free bind is fine.
        assert!(check("http://models.internal:11434", AuthKind::ApiKey).is_err());
        assert!(check("http://models.internal:11434", AuthKind::None).is_ok());
        // The policy runs in the declaration bind.
        let error = declare(serde_json::json!({
            "model": "m",
            "endpoint": {"baseUrl": "http://models.internal:8000/v1", "protocol": "openai-chat-completions"},
            "auth": "api-key"
        }))
        .expect_err("cleartext credentials to a resolved name");
        assert!(error.to_string().contains("cleartext"), "{error}");
    }
}
