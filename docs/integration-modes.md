# Integration modes

Two ways to consume the gateway, one semantics. A Rust host embeds the
`fairliny-gateway` crate and composes the router, the lease port and the meter
itself; a host in any other language spawns `fairliny serve` and speaks
one JSON object per line over stdio — both paths land on the same
`Service::dispatch`.

## SDK — embed the crate

```toml
[dependencies]
fairliny-gateway = "0.1"
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
`models.list`, `chat.complete`, `chat.stream`, `chat.cancel`,
`metrics.exposition`. Chat params are `{dialect, body, agent?}` over the
three wire dialects (`openai-chat-completions`, `openai-responses`,
`anthropic-messages`) — the body's `model` is the outward name;
`chat.stream` relays dialect SSE frames as `stream:"data"` lines then one
`stream:"end"` line, and `chat.cancel` cancels an in-flight request by
its `requestId`. Replies and frames for different requests may
interleave — correlate by `id`. The process composes, it does not
listen — the host owns the sockets, the custody channel
(`FAIRLINY_HANDOFF_FD`) and the epoch file (`FAIRLINY_EPOCH_FILE`) it
rewrites to revoke.

The routes document is one object:

```json
{
  "upstreamDeadlineSecs": 600,
  "credentialScopes": {
    "openai-key": ["<credentialId>"],
    "vendor-key": ["<otherCredentialId>"]
  },
  "routes": [
    {
      "model": "chat",
      "provider": "openai",
      "upstreamModel": "gpt-5.2",
      "protocol": "openai-responses",
      "auth": "api-key",
      "credentialScope": "openai-key",
      "vars": {"resource": "my-account"}
    },
    {
      "model": "vendor-chat",
      "endpoint": {
        "baseUrl": "https://api.vendor.example/v1",
        "protocol": "openai-chat-completions"
      },
      "auth": "api-key",
      "authHeader": "authorization",
      "credentialScope": "vendor-key",
      "upstreamModel": "vendor-large"
    }
  ]
}
```

- `routes[]` binds an outward `model` name to exactly one surface — a
  catalog `provider` or an explicit `endpoint`; an entry naming both or
  neither is refused. `upstreamModel` (default: `model`) is the id the
  upstream call receives and `auth` (default `none`) is the mechanism
  the lease must answer — `none`, `api-key`, `bearer`,
  `cloud:<service>` or `external:<client>`; a supplied value that is
  not one of those strings refuses the entry rather than degrading to
  `none`. A malformed entry refuses startup rather than running half a
  table.
- `credentialScopes` (optional) is the host-authorized table every
  `credentialScope` names: a scope to the `credentialId`s from the
  handoff it may resolve. An `api-key` or `bearer` route must declare
  `credentialScope`; a route on any other mechanism may not. A scope
  the table does not authorize, or one whose ids the handoff lacks,
  resolves nothing — the route fails closed rather than borrowing
  another vendor's credential. This is what keeps catalog and custom
  routes that both ride `api-key` on separate keys.
- A `provider` entry binds a catalog profile: `protocol` and `region`
  pin the profile's surface, and the profile must accept `auth`.
- An `endpoint` entry binds a vendor the catalog does not carry, purely
  by configuration. `endpoint.protocol` (required) is any protocol label
  — `openai-chat-completions`, `openai-responses`, `anthropic-messages`,
  `gemini-generate-content`, `bedrock-converse`, or `other:<name>` for a
  protocol with a registered adapter (`other:ollama`, `other:cohere`).
  `endpoint.baseUrl` (required) is the base the protocol's adapter joins
  its paths onto — `…/v1` for the OpenAI families (`chat/completions`,
  `responses`), the host root for `anthropic-messages` (`v1/messages`).
  It must be `http(s)` with a host and no embedded credentials, query or
  fragment, and it keeps a4mp's cleartext policy for profile endpoints:
  `https` anywhere; `http` only to `localhost`, `*.localhost`,
  `*.internal` or a loopback/private/link-local IP; and with any
  `auth` but `none`, `http` only to a private/loopback IP literal or
  `localhost`/`*.localhost`. The entry takes no top-level `protocol`,
  `region` or `vars`. Its `auth` is limited to the leased mechanisms —
  `none`, `api-key`, `bearer`: the sidecar's lease resolver cannot
  answer `cloud:*` or `external:*`, so an endpoint route naming one is
  refused at declaration instead of failing every forward. Requests
  never follow redirects — the validated origin is the only place
  credential headers may go.
- `authHeader` (endpoint entries only, optional) declares the header the
  vendor expects the credential in. a4mp's adapter for the protocol owns
  placement — `authorization` (`Bearer`) for the OpenAI families,
  Bedrock, Ollama and Cohere and for `bearer` everywhere; `x-api-key`
  for `api-key` over `anthropic-messages`; `x-goog-api-key` for
  `api-key` over `gemini-generate-content` — so a header other than that
  placement, or any header with `auth: none`, is refused rather than
  sending the credential somewhere else.
- `models.list` renders a provider entry with `provider` and `protocol`,
  and an endpoint entry with `endpoint` (the base URL's host and port,
  never its path), `protocol` and `authHeader` — both with `auth`,
  `upstreamModel`, `credentialScope` when declared and `bound`. Endpoint
  routes meter under the `custom` provider namespace.
- `routes[].vars` (default `{}`) supplies the profile's runtime
  variables — `{name}` placeholders in its service target. Local
  profiles carry no built-in address: their endpoint is supplied here
  per route, e.g. `"vars": {"endpoint": "<base URL>"}`. A route whose
  variables do not resolve the whole target is refused at declaration —
  startup fails on the entry rather than deferring the template error
  to the first forwarded request.
- `upstreamDeadlineSecs` bounds one upstream provider call so a hung
  provider cannot stall the gateway — a positive value is the host's
  explicit bound; absent or `0` waits unbounded — the caller cancels.

## Skills

- `skills/sdk/` — embedding guidance (lease install, routing, metering,
  exposition).
- `skills/sidecar/` — sidecar guidance (wire shape, methods,
  host-owned custody and listeners).
