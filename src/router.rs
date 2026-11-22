//! Model routing onto bound a4mp adapters.
//!
//! The router owns the outward face's one indirection: the model name a
//! caller sends is never the name the upstream sees. A [`Route`] binds an
//! outward name to a catalog profile with optional protocol and region
//! pins, an [`EndpointRoute`] binds one to an explicit endpoint the host
//! declares outside the catalog, and [`Router::resolve`] turns either
//! binding into a live a4mp [`Adapter`].
//!
//! Failure is closed by construction: an unknown model is refused before
//! any provider is touched, a profile route can only name a provider the
//! catalog carries and an auth mechanism its profile accepts, an endpoint
//! route can only reach its URL under the cleartext-credential policy
//! a4mp applies to profile endpoints and only through the leased auth
//! mechanisms, and an adapter the host bound itself arrives already live
//! through [`Router::register_adapter`]. The router holds no credential
//! material — it hands a4mp the resolver, and a scoped route's surface is
//! registered against its declared credential scope so the lease port
//! answers only what the host authorized for it.

use std::collections::BTreeMap;
use std::sync::Arc;

use a4mp::{
    Adapter, AuthKind, AuthSpec, CredentialResolver, Protocol, ProviderId, ServiceTarget, Transport,
};
use serde_json::Value;
use url::Url;

use crate::leases::{Leases, ProviderCredential};
use crate::{Error, Result};

/// The provider id endpoint routes bind under. An endpoint route names no
/// catalog profile; its adapter and its metering namespace
/// (`custom.usage`) carry this id instead.
pub const CUSTOM_PROVIDER: &str = "custom";

/// One outward model name bound to a catalog provider profile.
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

/// One outward model name bound to an explicit endpoint — a service the
/// catalog does not carry, declared entirely by the host: base URL plus
/// the wire protocol it speaks.
#[derive(Clone, Debug)]
pub struct EndpointRoute {
    /// The base URL protocol paths join onto. `http(s)` only, with no
    /// embedded credentials, query or fragment.
    pub base_url: Url,
    /// The wire protocol family the endpoint speaks.
    pub protocol: Protocol,
    /// The header the host expects the credential in. a4mp's adapter for
    /// `protocol` owns credential placement, so this is a declared
    /// expectation checked against that placement, never a new one.
    pub auth_header: Option<String>,
    /// The mechanism the adapter asks the resolver for. An endpoint route
    /// can only name a leased mechanism — `none`, `api-key`, `bearer` —
    /// because the custody port cannot answer cloud identity or an
    /// external client's access.
    pub auth: AuthKind,
    /// The identifier the upstream call receives. May differ from the
    /// outward name so aliases never leak deployment naming upstream.
    pub upstream_model: String,
}

/// `route entry requires a valid {field}` — the shared refusal every
/// document parser produces for a missing or mistyped member.
fn invalid(field: &str) -> Error {
    Error::Request(format!("route entry requires a valid {field}"))
}

/// The entry fields both route shapes share, parsed once each: `model`
/// (required), `auth` (default `none`), `upstreamModel` (default
/// `model`). A present-but-mistyped member refuses — a supplied `auth`,
/// `region` or `upstreamModel` is never silently degraded into a default
/// the document did not declare.
fn entry_fields(entry: &Value) -> Result<(String, AuthKind, String)> {
    let model = entry
        .get("model")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("model"))?
        .to_owned();
    let auth = match entry.get("auth") {
        None => AuthKind::None,
        Some(value) => parse_auth(value.as_str().ok_or_else(|| invalid("auth"))?)?,
    };
    let upstream_model = match entry.get("upstreamModel") {
        None => model.clone(),
        Some(value) => value
            .as_str()
            .ok_or_else(|| invalid("upstreamModel"))?
            .to_owned(),
    };
    Ok((model, auth, upstream_model))
}

/// An entry's declared credential scope: `credentialScope` must be a
/// non-empty string when present. The scope-to-credential authorization
/// lives in the document's `credentialScopes` table, not on the entry.
fn entry_credential_scope(entry: &Value) -> Result<Option<String>> {
    entry
        .get("credentialScope")
        .map(|value| {
            value
                .as_str()
                .filter(|scope| !scope.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| invalid("credentialScope"))
        })
        .transpose()
}

impl Route {
    /// Parse one routes-document entry `{model, provider, upstreamModel?,
    /// protocol?, region?, auth?, vars?, credentialScope?}` into the
    /// outward name and its profile route. The protocol and auth
    /// vocabulary is the same table `models.list` renders and errors
    /// quote: every label the gateway emits is a label the document
    /// accepts.
    pub fn from_document(entry: &Value) -> Result<(String, Self)> {
        let (model, auth, upstream_model) = entry_fields(entry)?;
        if entry.get("endpoint").is_some() {
            return Err(if entry.get("provider").is_some() {
                Error::Request("route entry names both a provider and an endpoint".to_owned())
            } else {
                invalid("provider")
            });
        }
        if entry.get("authHeader").is_some() {
            return Err(Error::Request(
                "authHeader applies to endpoint routes; a profile's adapter \
                 places its own credential"
                    .to_owned(),
            ));
        }
        let provider = entry
            .get("provider")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("provider"))?;
        let protocol = entry
            .get("protocol")
            .map(|v| v.as_str().ok_or_else(|| invalid("protocol")))
            .transpose()?
            .map(parse_protocol)
            .transpose()?;
        let region = entry
            .get("region")
            .map(|v| v.as_str().ok_or_else(|| invalid("region")))
            .transpose()?;
        Ok((
            model,
            Self {
                provider: ProviderId::new(provider),
                protocol,
                region: region.map(str::to_owned),
                auth,
                upstream_model,
                vars: parse_vars(entry.get("vars"))?,
            },
        ))
    }
}

impl EndpointRoute {
    /// Parse one routes-document entry `{model, endpoint: {baseUrl,
    /// protocol}, auth?, authHeader?, upstreamModel?, credentialScope?}`
    /// into the outward name and its endpoint route. An endpoint entry
    /// declares no top-level `protocol`, `region` or `vars` — the
    /// protocol belongs inside `endpoint`, and a service outside the
    /// catalog has no profile surface to pin.
    pub fn from_document(entry: &Value) -> Result<(String, Self)> {
        let (model, auth, upstream_model) = entry_fields(entry)?;
        if entry.get("provider").is_some() {
            return Err(Error::Request(
                "route entry names both a provider and an endpoint".to_owned(),
            ));
        }
        if let Some(field) = ["protocol", "region", "vars"]
            .into_iter()
            .find(|field| entry.get(field).is_some())
        {
            return Err(Error::Request(format!(
                "an endpoint route declares no top-level {field}: the \
                 protocol belongs inside endpoint"
            )));
        }
        let endpoint = entry.get("endpoint").ok_or_else(|| invalid("endpoint"))?;
        let base_url = endpoint
            .get("baseUrl")
            .and_then(Value::as_str)
            .and_then(|url| Url::parse(url).ok())
            .ok_or_else(|| invalid("endpoint.baseUrl"))?;
        let protocol = endpoint
            .get("protocol")
            .map(|v| v.as_str().ok_or_else(|| invalid("endpoint.protocol")))
            .transpose()?
            .map(parse_protocol)
            .transpose()?
            .ok_or_else(|| invalid("endpoint.protocol"))?;
        let auth_header = entry
            .get("authHeader")
            .map(|v| v.as_str().ok_or_else(|| invalid("authHeader")))
            .transpose()?
            .map(str::to_owned);
        Ok((
            model,
            Self {
                base_url,
                protocol,
                auth_header,
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

/// A parsed route declaration awaiting its checks — the staging shape
/// `load_routes` validates before anything commits and `add_*` commits
/// once its checks pass.
enum Declaration {
    Profile(Route),
    Endpoint(EndpointRoute),
}

/// The credential-scope registration one declared route produced: the
/// scope name plus the surface it was bound against — kept so a
/// replacement drops the obsolete binding while a surface shared with
/// another route keeps the binding that route still needs.
#[derive(Clone)]
struct ScopedBinding {
    scope: String,
    target: ServiceTarget,
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
    /// Vendors the catalog does not carry, bound by explicit endpoint.
    endpoint_routes: BTreeMap<String, EndpointRoute>,
    /// The credential scope each declared route named — a
    /// host-authorized entry in the lease port's scope table — plus the
    /// surface it was registered against.
    scopes: BTreeMap<String, ScopedBinding>,
    /// Adapters the host bound itself — custom surfaces and test stubs.
    /// They skip profile checks because the host already owns the binding.
    prebound: BTreeMap<String, (Arc<dyn Adapter>, String)>,
    /// The lease port scoped surfaces register against. Present only
    /// when the router's resolver is the crate's own custody port —
    /// [`Router::with_leases`] wires both from one `Arc`.
    leases: Option<Arc<Leases>>,
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
            endpoint_routes: BTreeMap::new(),
            scopes: BTreeMap::new(),
            prebound: BTreeMap::new(),
            leases: None,
        }
    }

    /// A router over the built-in catalog whose resolver is the crate's
    /// lease port. Scoped routes register their bound surfaces against
    /// it at declaration, so each authenticated surface resolves only
    /// the credentials the host authorized for its scope.
    pub fn with_leases(transport: Arc<dyn Transport>, leases: Arc<Leases>) -> Self {
        Self::with_catalog_leases(a4mp::Catalog::with_builtin_adapters(), transport, leases)
    }

    /// [`Self::with_leases`] over an explicit catalog.
    pub fn with_catalog_leases(
        catalog: a4mp::Catalog,
        transport: Arc<dyn Transport>,
        leases: Arc<Leases>,
    ) -> Self {
        let mut router = Self::with_catalog(catalog, transport, leases.clone());
        router.leases = Some(leases);
        router
    }

    /// Bind an outward model name to a catalog provider profile.
    ///
    /// Fails closed at declaration time: the provider must resolve
    /// through the catalog, the profile must accept the declared auth
    /// mechanism, and the declared variables must materialize the
    /// profile's target template — the same bind `resolve` performs is
    /// run once here, so a typo'd provider, mechanism, variable key or
    /// protocol is refused before traffic ever reaches the route, not at
    /// first `chat.complete`.
    ///
    /// An `api-key`/`bearer` route must name its credential scope —
    /// [`Router::add_route_scoped`] — so a leased credential can never
    /// ride a surface the host did not authorize for it.
    pub fn add_route(&mut self, model: impl Into<String>, route: Route) -> Result<()> {
        self.add_profile(model.into(), route, None)
    }

    /// [`Self::add_route`] plus the credential scope the host authorized
    /// for the route's bound surface. The scope names an authorization in
    /// the lease port's scope table; a scope holding no credential fails
    /// closed at resolution rather than borrowing another's.
    pub fn add_route_scoped(
        &mut self,
        model: impl Into<String>,
        route: Route,
        credential_scope: impl Into<String>,
    ) -> Result<()> {
        self.add_profile(model.into(), route, Some(credential_scope.into()))
    }

    /// Bind an outward model name to an explicit endpoint — a vendor the
    /// catalog does not carry, declared purely by configuration.
    ///
    /// Fails closed at declaration time: the URL must be a bare `http(s)`
    /// base under the same cleartext-credential policy a4mp applies to
    /// profile endpoints, the auth mechanism must be a leased kind —
    /// `none`, `api-key` or `bearer`, never cloud identity or external
    /// access the custody port cannot answer — and a declared
    /// `auth_header` must be where a4mp places the credential.
    ///
    /// An `api-key`/`bearer` route must name its credential scope —
    /// [`Router::add_endpoint_route_scoped`].
    pub fn add_endpoint_route(
        &mut self,
        model: impl Into<String>,
        route: EndpointRoute,
    ) -> Result<()> {
        self.add_endpoint(model.into(), route, None)
    }

    /// [`Self::add_endpoint_route`] plus the credential scope the host
    /// authorized for the route's bound surface.
    pub fn add_endpoint_route_scoped(
        &mut self,
        model: impl Into<String>,
        route: EndpointRoute,
        credential_scope: impl Into<String>,
    ) -> Result<()> {
        self.add_endpoint(model.into(), route, Some(credential_scope.into()))
    }

    /// The shared declaration path for profile routes: scope contract,
    /// catalog checks, one declaration bind, then the commit.
    fn add_profile(&mut self, model: String, route: Route, scope: Option<String>) -> Result<()> {
        if self.endpoint_routes.contains_key(&model) {
            return Err(Error::Route {
                model,
                reason: "model is already bound to an endpoint route".to_owned(),
            });
        }
        let target = self.check_profile(&model, &route, &scope)?;
        self.commit(model, Declaration::Profile(route), target, scope)
    }

    /// The endpoint counterpart of [`Self::add_profile`].
    fn add_endpoint(
        &mut self,
        model: String,
        route: EndpointRoute,
        scope: Option<String>,
    ) -> Result<()> {
        if self.routes.contains_key(&model) {
            return Err(Error::Route {
                model,
                reason: "model is already bound to a profile route".to_owned(),
            });
        }
        let target = self.check_endpoint(&model, &route, &scope)?;
        self.commit(model, Declaration::Endpoint(route), target, scope)
    }

    /// Every fallible check a profile-route declaration runs — the
    /// credential-scope contract, the catalog lookup, the mechanism the
    /// profile must accept, and one declaration bind that refuses a
    /// missing or misspelled endpoint variable, an unbound protocol or a
    /// cleartext credential path — producing the surface the route binds
    /// to. Nothing commits here; `load_routes` runs the same checks
    /// against its staged table so a bad entry anywhere refuses the
    /// whole document.
    fn check_profile(
        &self,
        model: &str,
        route: &Route,
        scope: &Option<String>,
    ) -> Result<ServiceTarget> {
        let refuse = |reason: String| Error::Route {
            model: model.to_owned(),
            reason,
        };
        check_credential_scope(&route.auth, scope).map_err(refuse)?;
        let profile = self
            .client
            .catalog()
            .resolve(route.provider.as_str())
            .ok_or_else(|| refuse(format!("unknown provider {}", route.provider)))?;
        if !accepts(&profile.auth, &route.auth) {
            return Err(refuse(format!(
                "profile {} does not accept {}",
                profile.id,
                auth_label(&route.auth)
            )));
        }
        let adapter = self.bind_profile(route).map_err(refuse)?;
        self.check_scope_resolver(scope).map_err(refuse)?;
        Ok(adapter.target().clone())
    }

    /// The endpoint counterpart of [`Self::check_profile`].
    fn check_endpoint(
        &self,
        model: &str,
        route: &EndpointRoute,
        scope: &Option<String>,
    ) -> Result<ServiceTarget> {
        let refuse = |reason: String| Error::Route {
            model: model.to_owned(),
            reason,
        };
        check_credential_scope(&route.auth, scope).map_err(refuse)?;
        if !matches!(route.auth, AuthKind::None)
            && ProviderCredential::for_auth(&route.auth).is_none()
        {
            return Err(refuse(format!(
                "endpoint auth {} is not leased: an endpoint resolves \
                 api-key, bearer or none — cloud identity and external \
                 access stay with the host's own custody",
                auth_label(&route.auth)
            )));
        }
        check_base_url(&route.base_url).map_err(refuse)?;
        if let Some(header) = &route.auth_header {
            check_auth_header(&route.protocol, &route.auth, header).map_err(refuse)?;
        }
        let adapter = self.bind_endpoint(route).map_err(refuse)?;
        self.check_scope_resolver(scope).map_err(refuse)?;
        Ok(adapter.target().clone())
    }

    /// The resolver check a scoped declaration needs: a credential scope
    /// is only as real as the port enforcing it, so a scope may only be
    /// declared when the router's resolver is the crate's lease port —
    /// `Router::with_leases` — and the scope is one the host authorized.
    /// A host-supplied resolver owns its credential dispatch and cannot
    /// honor the declaration; accepting it would project a scope in
    /// `models.list` that resolution silently ignores.
    fn check_scope_resolver(&self, scope: &Option<String>) -> std::result::Result<(), String> {
        let Some(scope) = scope else {
            return Ok(());
        };
        let Some(leases) = &self.leases else {
            return Err("credential scope requires the lease port: declare through \
                 Router::with_leases so the declared scope is enforced at \
                 resolution"
                .to_owned());
        };
        if !leases.scope_authorized(scope) {
            return Err("credential_scope_unauthorized".to_owned());
        }
        Ok(())
    }

    /// Commit one fully checked declaration: republish the whole scope
    /// table — the lease port swaps bindings atomically, so the route's
    /// new binding lands and the one a replaced route leaves dies in the
    /// same publish — then land the route itself. A refused publish
    /// leaves every table untouched.
    fn commit(
        &mut self,
        model: String,
        declaration: Declaration,
        target: ServiceTarget,
        scope: Option<String>,
    ) -> Result<()> {
        let mut scopes = self.scopes.clone();
        match scope {
            Some(scope) => {
                scopes.insert(model.clone(), ScopedBinding { scope, target });
            }
            None => {
                scopes.remove(&model);
            }
        }
        self.publish_scopes(&scopes)
            .map_err(|reason| Error::Route {
                model: model.clone(),
                reason,
            })?;
        self.scopes = scopes;
        match declaration {
            Declaration::Profile(route) => {
                self.routes.insert(model, route);
            }
            Declaration::Endpoint(route) => {
                self.endpoint_routes.insert(model, route);
            }
        }
        Ok(())
    }

    /// Republish every live scope binding to the lease port in one swap.
    /// The declared set is the whole table, so a route that stopped
    /// declaring a scope releases its old binding, a route rebound to
    /// another surface frees the original target, and a surface two
    /// routes share keeps the binding both still need.
    fn publish_scopes(
        &self,
        scopes: &BTreeMap<String, ScopedBinding>,
    ) -> std::result::Result<(), String> {
        let Some(leases) = &self.leases else {
            return Ok(());
        };
        leases
            .replace_target_scopes(
                scopes
                    .values()
                    .map(|binding| (&binding.target, binding.scope.as_str())),
            )
            .map_err(|error| error.to_string())
    }

    /// Load a routes document `{"routes":[{model,provider|endpoint,...,
    /// credentialScope?}]}` — plus the `credentialScopes` authorization
    /// table the scopes name, which the lease port reads. A `routes`
    /// member must be an array when present, and the whole document is
    /// parsed and checked before anything commits: a malformed entry
    /// refuses the table — the gateway never silently runs half of it.
    pub fn load_routes(&mut self, document: &Value) -> Result<()> {
        let entries = match document.get("routes") {
            None => return Ok(()),
            Some(routes) => routes.as_array().ok_or_else(|| invalid("routes"))?,
        };
        // Parse every entry first — a malformed one refuses the document
        // before any route or scope registration commits.
        let mut staged = Vec::with_capacity(entries.len());
        let mut seen = std::collections::BTreeSet::new();
        for entry in entries {
            let credential_scope = entry_credential_scope(entry)?;
            let (model, declaration) = match (
                entry.get("provider").is_some(),
                entry.get("endpoint").is_some(),
            ) {
                (true, true) => {
                    return Err(Error::Request(
                        "route entry names both a provider and an endpoint".to_owned(),
                    ));
                }
                (false, false) => {
                    return Err(Error::Request(
                        "route entry requires a provider or an endpoint".to_owned(),
                    ));
                }
                (true, false) => {
                    let (model, route) = Route::from_document(entry)?;
                    (model, Declaration::Profile(route))
                }
                (false, true) => {
                    let (model, route) = EndpointRoute::from_document(entry)?;
                    (model, Declaration::Endpoint(route))
                }
            };
            if !seen.insert(model.clone()) {
                return Err(Error::Request(format!(
                    "routes document declares {model:?} twice"
                )));
            }
            staged.push((model, declaration, credential_scope));
        }
        // Build the would-be tables and run every declaration check
        // against them, so a bad entry anywhere leaves the live table
        // untouched.
        let mut routes = self.routes.clone();
        let mut endpoint_routes = self.endpoint_routes.clone();
        let mut scopes = self.scopes.clone();
        for (model, declaration, scope) in staged {
            let collision = match declaration {
                Declaration::Profile(_) if endpoint_routes.contains_key(&model) => {
                    Some("model is already bound to an endpoint route")
                }
                Declaration::Endpoint(_) if routes.contains_key(&model) => {
                    Some("model is already bound to a profile route")
                }
                _ => None,
            };
            if let Some(reason) = collision {
                return Err(Error::Route {
                    model,
                    reason: reason.to_owned(),
                });
            }
            let target = match &declaration {
                Declaration::Profile(route) => self.check_profile(&model, route, &scope)?,
                Declaration::Endpoint(route) => self.check_endpoint(&model, route, &scope)?,
            };
            match scope {
                Some(scope) => {
                    scopes.insert(model.clone(), ScopedBinding { scope, target });
                }
                None => {
                    scopes.remove(&model);
                }
            }
            match declaration {
                Declaration::Profile(route) => {
                    routes.insert(model, route);
                }
                Declaration::Endpoint(route) => {
                    endpoint_routes.insert(model, route);
                }
            }
        }
        // One consistent landing: the scope publish — the only step that
        // can still refuse, on a surface conflict between entries — then
        // the route tables swap in together.
        self.publish_scopes(&scopes).map_err(Error::Request)?;
        self.routes = routes;
        self.endpoint_routes = endpoint_routes;
        self.scopes = scopes;
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

    /// The declared profile routes, for read-only projections.
    pub fn routes(&self) -> impl Iterator<Item = (&String, &Route)> {
        self.routes.iter()
    }

    /// The declared endpoint routes, for read-only projections.
    pub fn endpoint_routes(&self) -> impl Iterator<Item = (&String, &EndpointRoute)> {
        self.endpoint_routes.iter()
    }

    /// The credential scope a declared route named, for projections.
    pub fn credential_scope(&self, model: &str) -> Option<&str> {
        self.scopes.get(model).map(|binding| binding.scope.as_str())
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
        let refused = |reason: String| Error::Route {
            model: model.to_owned(),
            reason,
        };
        if let Some(route) = self.routes.get(model) {
            return Ok(BoundRoute {
                adapter: self.bind_profile(route).map_err(refused)?,
                upstream_model: route.upstream_model.clone(),
                provider: route.provider.clone(),
            });
        }
        if let Some(route) = self.endpoint_routes.get(model) {
            return Ok(BoundRoute {
                adapter: self.bind_endpoint(route).map_err(refused)?,
                upstream_model: route.upstream_model.clone(),
                provider: ProviderId::new(CUSTOM_PROVIDER),
            });
        }
        Err(Error::UnknownModel(model.to_owned()))
    }

    /// The profile bind both declaration and resolution run.
    fn bind_profile(&self, route: &Route) -> std::result::Result<Arc<dyn Adapter>, String> {
        self.client
            .bind_provider_with(
                route.provider.as_str(),
                route.protocol.clone(),
                route.region.as_deref(),
                route.auth.clone(),
                &bind_vars(&route.vars),
            )
            .map_err(|error| error.to_string())
    }

    /// The endpoint bind both declaration and resolution run — the
    /// cleartext-credential policy profile endpoints get inside a4mp,
    /// restated for an explicit target `bind_target` never checks.
    fn bind_endpoint(
        &self,
        route: &EndpointRoute,
    ) -> std::result::Result<Arc<dyn Adapter>, String> {
        check_cleartext_policy(&route.base_url, &route.auth)?;
        self.client
            .bind_target(
                ServiceTarget::new(
                    CUSTOM_PROVIDER,
                    route.protocol.clone(),
                    route.base_url.clone(),
                ),
                route.auth.clone(),
            )
            .map_err(|error| error.to_string())
    }
}

/// The credential-scope contract for one declared route: a scope binds
/// to a leased auth mechanism (`api-key`/`bearer`) — required for them,
/// meaningless and refused for anything else.
fn check_credential_scope(
    auth: &AuthKind,
    scope: &Option<String>,
) -> std::result::Result<(), String> {
    match (
        ProviderCredential::for_auth(auth).is_some(),
        scope.as_deref().filter(|scope| !scope.is_empty()),
    ) {
        (true, None) => Err(format!(
            "{} requires a credential scope: the host authorizes which \
             leased credentials a route may resolve",
            auth_label(auth)
        )),
        (false, Some(_)) => Err(format!(
            "credentialScope does not apply to {}: it binds leased \
             credentials (api-key, bearer)",
            auth_label(auth)
        )),
        _ => Ok(()),
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
        assert_eq!(route.protocol, Some(Protocol::Other("ollama".to_owned())));
        assert_eq!(route.vars["endpoint"], "http://localhost:11434");

        // A missing required field, an unknown vocabulary word or a
        // supplied member of the wrong type refuses the entry — never a
        // half-parsed route, never a default the document did not declare.
        for entry in [
            serde_json::json!({"provider": "ollama"}),
            serde_json::json!({"model": "m", "provider": "ollama", "auth": "oauth-magic"}),
            serde_json::json!({"model": "m", "provider": "ollama", "protocol": "grpc"}),
            serde_json::json!({"model": "m", "provider": "ollama", "auth": 5}),
            serde_json::json!({"model": "m", "provider": "ollama", "upstreamModel": 5}),
            serde_json::json!({"model": "m", "provider": "ollama", "region": 5}),
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
    /// invoked — declaration binds adapters but sends nothing — and
    /// whose lease port authorizes `vendor-scope`, the resolver shape
    /// every scoped declaration requires.
    fn declaring_router() -> Router {
        let leases = Arc::new(Leases::disconnected());
        leases
            .authorize_scope("vendor-scope", [uuid::Uuid::new_v4().to_string()])
            .expect("authorize");
        Router::with_leases(Arc::new(a4mp::ReqwestTransport::new()), leases)
    }

    fn declare(entry: Value) -> Result<()> {
        declaring_router().load_routes(&serde_json::json!({ "routes": [entry] }))
    }

    /// An api-key endpoint entry plus the scope it declares — the shape
    /// every leased-auth document entry must take.
    fn scoped_entry(mut entry: Value) -> Value {
        entry["credentialScope"] = "vendor-scope".into();
        entry
    }

    #[test]
    fn an_endpoint_entry_parses_into_a_custom_surface() {
        let (model, route) = EndpointRoute::from_document(&serde_json::json!({
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
        assert_eq!(route.base_url.as_str(), "https://api.vendor.example/v1");
        assert_eq!(route.protocol, Protocol::AnthropicMessages);
        assert_eq!(route.auth_header.as_deref(), Some("x-api-key"));
        assert_eq!(endpoint_authority(&route.base_url), "api.vendor.example");

        // Every protocol label the vocabulary names declares an endpoint.
        for (label, _) in PROTOCOL_VOCABULARY {
            let (_, route) = EndpointRoute::from_document(&serde_json::json!({
                "model": "m",
                "endpoint": {"baseUrl": "https://api.vendor.example", "protocol": label}
            }))
            .expect(label);
            assert_eq!(&protocol_label(&route.protocol), label);
        }

        let mut router = declaring_router();
        router
            .add_endpoint_route_scoped(model, route, "vendor-scope")
            .expect("declared");
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
            let error = declaring_router()
                .load_routes(&serde_json::json!({ "routes": [entry] }))
                .expect_err("refused");
            assert!(error.to_string().contains(needle), "{entry}: {error}");
        }
    }

    #[test]
    fn a_leased_auth_route_must_name_its_credential_scope() {
        let endpoint = serde_json::json!({"baseUrl": "https://api.vendor.example", "protocol": "openai-chat-completions"});
        // api-key and bearer routes without a scope refuse — a leased
        // credential can never ride a surface the host did not authorize.
        for auth in ["api-key", "bearer"] {
            for entry in [
                serde_json::json!({"model": "m", "provider": "ollama", "auth": auth,
                                   "protocol": "other:ollama",
                                   "vars": {"endpoint": "https://a.example"}}),
                serde_json::json!({"model": "m", "endpoint": endpoint, "auth": auth}),
            ] {
                let error = declare(entry).expect_err(auth);
                assert!(
                    error.to_string().contains("credential scope"),
                    "{auth}: {error}"
                );
            }
        }
        // And a scope on a mechanism that cannot lease one is refused —
        // the entry would pretend an authorization it does not have.
        for entry in [
            serde_json::json!({"model": "m", "provider": "ollama", "auth": "none",
                               "credentialScope": "s",
                               "vars": {"endpoint": "https://a.example"}}),
            serde_json::json!({"model": "m", "endpoint": endpoint,
                               "auth": "none", "credentialScope": "s"}),
        ] {
            let error = declare(entry).expect_err("scope on none");
            assert!(error.to_string().contains("does not apply"), "{error}");
        }
        // A malformed scope member refuses rather than degrading.
        for scope in [serde_json::json!(5), serde_json::json!("")] {
            let error = declare(serde_json::json!({"model": "m", "endpoint": endpoint,
                                   "auth": "api-key", "credentialScope": scope}))
            .expect_err("bad scope");
            assert!(error.to_string().contains("credentialScope"), "{error}");
        }
    }

    #[test]
    fn an_endpoint_route_only_accepts_leased_auth_mechanisms() {
        let endpoint = serde_json::json!({"baseUrl": "https://api.vendor.example", "protocol": "openai-chat-completions"});
        // Cloud identity and external access pass parsing — they are real
        // vocabulary — but the custody port can never answer them, so an
        // endpoint route naming one refuses at declaration, not at first
        // forward.
        for auth in ["cloud:aws", "external:acme.sso", "other:acme"] {
            let error =
                declare(serde_json::json!({"model": "m", "endpoint": endpoint, "auth": auth}))
                    .expect_err(auth);
            assert!(error.to_string().contains("not leased"), "{auth}: {error}");
        }
        // `none` needs no scope and no credential.
        declare(serde_json::json!({"model": "m", "endpoint": endpoint, "auth": "none"}))
            .expect("none binds");
    }

    #[test]
    fn an_endpoint_refuses_unknown_protocols_and_bad_urls() {
        let entry = |url: &str, protocol: &str| serde_json::json!({"model": "m", "endpoint": {"baseUrl": url, "protocol": protocol}});
        // An unnamed label fails parsing; an `other:` protocol with no
        // adapter factory fails the declaration bind.
        assert!(EndpointRoute::from_document(&entry("https://a.example", "grpc")).is_err());
        assert!(
            EndpointRoute::from_document(
                &serde_json::json!({"model": "m", "endpoint": {"baseUrl": "https://a.example"}})
            )
            .is_err()
        );
        let error = declare(entry("https://a.example", "other:no-such-wire")).expect_err("unbound");
        assert!(error.to_string().contains("no adapter"), "{error}");

        // Unparseable, non-http, credential-bearing, query or fragment
        // URLs refuse — and the refusal never quotes the URL.
        assert!(
            EndpointRoute::from_document(&entry("not a url", "openai-chat-completions")).is_err()
        );
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
            declare(scoped_entry(entry(protocol, auth, header))).expect(header);
        }
        // a4mp carries no header name in `AuthKind`: a header its adapter
        // does not use is refused, naming the placement it does use.
        let error = declare(scoped_entry(entry(
            "openai-chat-completions",
            "api-key",
            "x-api-key",
        )))
        .expect_err("openai sends authorization");
        assert!(error.to_string().contains("\"authorization\""), "{error}");
        let error = declare(entry("openai-chat-completions", "none", "authorization"))
            .expect_err("no credential, no header");
        assert!(error.to_string().contains("not expressible"), "{error}");
        assert!(
            EndpointRoute::from_document(&serde_json::json!({
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
            "auth": "api-key",
            "credentialScope": "vendor-scope"
        }))
        .expect_err("cleartext credentials to a resolved name");
        assert!(error.to_string().contains("cleartext"), "{error}");
    }
}
