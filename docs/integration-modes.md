# Integration modes

Two ways to consume the gateway, one semantics. A Rust host embeds the
`fairlead` crate and composes the router, the lease port and the meter
itself; a host in any other language spawns `fairlead serve` and speaks
one JSON object per line over stdio — both paths land on the same
`Service::dispatch`.

## SDK — embed the crate

```toml
[dependencies]
fairlead = "0.1"
```

```rust
use std::sync::Arc;
use fairlead::{
    leases::{FileEpochSource, Leases},
    meter::Meter,
    router::Router,
    service::Service,
};

// Custody hands a CredentialHandoff document in over a process-local
// channel; the rebuilt lease is process-bound and revocable through the
// epoch file the custody owner rotates.
let leases = Arc::new(Leases::disconnected());
let document = Leases::read_handoff(handoff_channel)?;
leases.install_handoff(&document, Arc::new(FileEpochSource::new(epoch_file)))?;

let mut router = Router::new(transport, leases); // Leases is the a4mp CredentialResolver
router.add_route("chat", route)?;
let meter = Meter::open(state_root)?;            // or compose(root, binding) / unmetered()
let service = Service::new(router, meter);
```

Every module composes alone: `router` binds outward model names to live
a4mp adapters, `leases` is the credential custody port, `meter` carries
the admission counters and response settlement, `export` renders the
Prometheus/OpenMetrics text a host mounts at its own `/metrics` route.
`Service::new` is only the assembly of those three.

## Sidecar — `fairlead serve`

```sh
fairlead serve [--config routes.json] [--state-root DIR] [--no-meter]
```

One `{"id":N,"method":...,"params":{}}` per stdin line, one
`{"id":N,"result"|"error"}` per stdout line; a malformed, oversized or
non-UTF-8 line answers `id: null` and the loop continues. Methods:
`models.list`, `chat.complete`, `metrics.exposition`. The process
composes, it does not listen — the host owns the sockets, the custody
channel (`FAIRLEAD_HANDOFF_FD`) and the epoch file
(`FAIRLEAD_EPOCH_FILE`) it rewrites to revoke.

## Skills

- `skills/sdk/` — embedding guidance (lease install, routing, metering,
  exposition).
- `skills/sidecar/` — sidecar guidance (wire shape, methods,
  host-owned custody and listeners).
