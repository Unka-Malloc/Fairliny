# Integration modes

Two ways to consume the gateway, one semantics. A Rust host embeds the
`fairliny` crate and composes the router, the lease port and the meter
itself; a host in any other language spawns `fairliny serve` and speaks
one JSON object per line over stdio — both paths land on the same
`Service::dispatch`.

## SDK — embed the crate

```toml
[dependencies]
fairliny = "0.1"
```

```rust
use std::sync::Arc;
use fairliny_gateway::{
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

## Sidecar — `fairliny serve`

```sh
fairliny serve [--config routes.json] [--state-root DIR] [--no-meter]
```

One `{"id":N,"method":...,"params":{}}` per stdin line, one
`{"id":N,"result"|"error"}` per stdout line; a malformed, oversized or
non-UTF-8 line answers `id: null` and the loop continues. Methods:
`models.list`, `chat.complete`, `metrics.exposition`. The process
composes, it does not listen — the host owns the sockets, the custody
channel (`FAIRLINY_HANDOFF_FD`) and the epoch file
(`FAIRLINY_EPOCH_FILE`) it rewrites to revoke.

The routes document is one object:

```json
{
  "upstreamDeadlineSecs": 600,
  "routes": [
    {
      "model": "chat",
      "provider": "openai",
      "upstreamModel": "gpt-5.2",
      "protocol": "openai-responses",
      "auth": "api-key",
      "vars": {"resource": "my-account"}
    }
  ]
}
```

- `routes[]` binds an outward `model` name to a catalog `provider`;
  `upstreamModel` (default: `model`) is the id the upstream call
  receives, `protocol` and `region` pin the profile's surface, and
  `auth` (default `none`) is the mechanism the lease must answer —
  `none`, `api-key`, `bearer`, `cloud:<service>` or `external:<client>`.
  A malformed entry refuses startup rather than running half a table.
- `routes[].vars` (default `{}`) supplies the profile's runtime
  variables — `{name}` placeholders in its service target. Local
  profiles carry no built-in address: their endpoint is supplied here
  per route, e.g. `"vars": {"endpoint": "<base URL>"}`. A route whose
  variables do not resolve the whole target is refused at declaration —
  startup fails on the entry rather than deferring the template error
  to the first forwarded request.
- `upstreamDeadlineSecs` bounds one upstream provider call so a hung
  provider cannot stall the gateway — default `600`, `0` restores an
  unbounded wait for hosts that bound the call themselves.

## Skills

- `skills/sdk/` — embedding guidance (lease install, routing, metering,
  exposition).
- `skills/sidecar/` — sidecar guidance (wire shape, methods,
  host-owned custody and listeners).
