---
name: fairliny-sdk
description: Embed the fairliny gateway in a Rust host — credential leases in over a process-local handoff, a4mp routing, and fault-isolated Metera metering.
---

# fairliny SDK mode

Embed `fairliny-gateway` and compose the outward model-service face in-process.

## When to use

- The host is Rust and wants the gateway's router, lease port and meter
  in its own process — `Service::dispatch` per request, or the modules
  directly.
- The host owns custody and feeds `CredentialHandoff` documents in, or
  drives the lease lifecycle itself through `Leases::over_lease`,
  `Leases::install_lease` and `Leases::clear` — each applies to the
  whole lease state, scoped slots included.

## Canonical calls

```rust
let leases = Arc::new(Leases::disconnected());          // resolves fail closed until a handoff lands
let document = Leases::read_handoff(channel)?;          // bounded, zeroizing buffer
leases.authorize_scope("openai-key", ["<credentialId>"])?;  // host-authorized scopes
leases.install_handoff(&document, epoch_source)?;       // FileEpochSource: custody-driven revocation
let transport = fairliny_gateway::transport::upstream_transport()?;  // never follows redirects
let mut router = Router::with_leases(transport, leases);  // registers scoped surfaces
router.add_route("local", route)?;                      // Route: profile routes, `none` auth
router.add_route_scoped("chat", scoped_route, "openai-key")?;  // api-key/bearer requires a scope
router.add_endpoint_route("vendor", endpoint_route)?;   // EndpointRoute: explicit baseUrl
router.add_endpoint_route_scoped("vendor-chat", scoped_endpoint, "openai-key")?;  // authenticated endpoints scope too
// or register_adapter / with_catalog_leases
let meter = Meter::open(state_root)?;                   // compose(root, binding) | unmetered()
let service = Service::new(router, meter);
let reply = service.dispatch(id, Some("chat.complete"), &params).await;
let exposition = fairliny_gateway::export::render(service.meter())?;
```

## Rules that keep the contract

- Custody, persistence and owner authorization stay in the host. The
  handoff document arrives over a process-local channel; Fairliny never
  stores keys, and secret bytes never appear in serialized output,
  debug projections, logs or errors. One lease may carry several
  vendors' credentials, so `api-key`/`bearer` routes must declare a
  credential scope (`*_scoped` route calls, or `credentialScope` in a
  routes document): the scope names a `Leases::authorize_scope`
  authorization — the credential ids that route may resolve — and a
  scope holding none fails closed. `Router::with_leases` registers each
  scoped route's bound surface so resolution dispatches on the target,
  never on the auth mechanism alone.
- `Route` keeps its published construction fields — `provider`,
  `protocol`, `region`, `auth`, `upstream_model`, `vars`. Endpoint
  bindings live on `EndpointRoute` (`base_url`, `protocol`,
  `auth_header`, `auth`, `upstream_model`); its auth is limited to the
  leased mechanisms — `none`, `api-key`, `bearer` — since cloud
  identity and external-client access stay with the host's custody.
- Unknown usage stays unknown: a counter the provider did not report is
  absent; one it named without a count settles `Quality::Unknown` —
  never zeroed into a claim that nothing happened.
- Metering is fault-isolated: `admit_request` and `settle_response` run
  beside the forwarded request; a metering failure is counted in-process
  (`failure_count`), never propagated into a response.
- Fairliny never opens a socket: the host owns the listeners and mounts
  `export::render` output where it wants it.
