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
        let adapter = self
            .client
            .bind_provider(
                route.provider.as_str(),
                route.protocol.clone(),
                route.region.as_deref(),
                route.auth.clone(),
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

/// The mechanism name projections and errors may show.
pub fn auth_label(auth: &AuthKind) -> String {
    match auth {
        AuthKind::None => "none".to_owned(),
        AuthKind::ApiKey => "api-key".to_owned(),
        AuthKind::Bearer => "bearer".to_owned(),
        AuthKind::CloudIdentity { service } => format!("cloud:{service}"),
        AuthKind::External { client } => format!("external:{client}"),
        _ => "other".to_owned(),
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
}
