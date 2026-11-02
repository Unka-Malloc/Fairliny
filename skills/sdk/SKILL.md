---
name: fairliny-sdk
description: Embed the fairliny gateway in a Rust host — credential leases in over a process-local handoff, a4mp routing, and fault-isolated Metera metering.
---

# fairliny SDK mode

Embed `fairliny` and compose the outward model-service face in-process.

## When to use

- The host is Rust and wants the gateway's router, lease port and meter
  in its own process — `Service::dispatch` per request, or the modules
  directly.
- The host owns custody and feeds `CredentialHandoff` documents in, or
  drives the lease lifecycle itself through `Leases::over_slot` and
  `Leases::slot`.

## Canonical calls

```rust
let leases = Arc::new(Leases::disconnected());          // resolves fail closed until a handoff lands
let document = Leases::read_handoff(channel)?;          // bounded, zeroizing buffer
leases.install_handoff(&document, epoch_source)?;       // FileEpochSource: custody-driven revocation
let mut router = Router::new(transport, leases);        // Leases: a4mp CredentialResolver
router.add_route("chat", route)?;                       // or register_adapter / with_catalog
let meter = Meter::open(state_root)?;                   // compose(root, binding) | unmetered()
let service = Service::new(router, meter);
let reply = service.dispatch(id, Some("chat.complete"), &params).await;
let exposition = fairliny_gateway::export::render(service.meter())?;
```

## Rules that keep the contract

- Custody, persistence and owner authorization stay in the host. The
  handoff document arrives over a process-local channel; Fairliny never
  stores keys, and secret bytes never appear in serialized output,
  debug projections, logs or errors.
- Unknown usage stays unknown: a counter the provider did not report is
  absent; one it named without a count settles `Quality::Unknown` —
  never zeroed into a claim that nothing happened.
- Metering is fault-isolated: `admit_request` and `settle_response` run
  beside the forwarded request; a metering failure is counted in-process
  (`failure_count`), never propagated into a response.
- Fairliny never opens a socket: the host owns the listeners and mounts
  `export::render` output where it wants it.
