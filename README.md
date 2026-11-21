# Fairliny

The unified model gateway. It gathers model-provider access (a4mp) and
credential leases (Credential-Lease) into one outward model-service face;
a forwarding-only core with Metera usage metering composed in.

A caller names a model; the router binds the configured provider profile
— or an explicit endpoint the host declares outside the catalog — to a
live a4mp adapter; the lease port answers credentials from a
process-bound `CredentialLease`; the response forwards back untouched.
Metering runs beside that path — one admission counter and one settlement
hook — never inside it.

## Boundary

- **Custody, persistence and owner authorization belong to the host.**
  Fairliny consumes `CredentialHandoff` documents over a process-local
  channel (an inherited file descriptor is the designed-for carrier) and
  rebuilds process-bound `CredentialLease`s; it never stores keys, and
  secret bytes never appear in serialized output, debug projections,
  logs or errors.
- **Unknown usage stays unknown.** A counter the provider did not report
  is absent; one it named without a count settles as `Quality::Unknown` —
  never zeroed into a claim that nothing happened.
- **Metering is fault-isolated.** Request-admission counters and
  response-settlement observations run asynchronously beside the
  forwarded request; a metering failure is counted in-process and never
  propagated into a response.
- **The host owns the listeners.** `fairliny serve` is an NDJSON sidecar
  on stdio; `metrics.exposition` returns text for a host-mounted
  `/metrics` route — Fairliny never opens a socket for metrics.

## Modules

| Module | Owns |
| --- | --- |
| `router` | Outward model names bound to provider access surfaces — a catalog profile or an explicit endpoint (base URL + protocol) — with an auth mechanism, an optional credential scope and an upstream model id. Unknown models, unaccepted auth and cleartext credential paths fail closed. |
| `leases` | The credential custody port: the `ProviderCredential` kind family, the process-bound `CredentialSlot`, host-authorized credential scopes, `FileEpochSource` for custody-driven revocation, and a4mp's `CredentialResolver`. |
| `meter` | Metera composed in: bounded per-day agent×model request counters (`GatewayUsageRecorder`-shaped), and response settlement — `ProviderMapping` → `SourceBinding` → `UsageSourcePort` — into the usage journal. |
| `export` | Prometheus/OpenMetrics text from `agent-statistics::export` for a host-mounted scrape route. |
| `service` | The `fairliny serve` sidecar: one JSON request per stdin line, methods `models.list`, `chat.complete`, `chat.stream`, `chat.cancel`, `metrics.exposition`. |

## `fairliny serve`

```
fairliny serve [--config routes.json] [--state-root DIR]
```

Requests are one JSON object per line: `{"id":N,"method":...,"params":{}}`.
Replies are `{"id":N,"result":{...}}` or `{"id":N,"error":"..."}`; a
malformed line answers `id: null` and the loop continues.

`chat.complete`/`chat.stream` params are `{dialect, body, agent?}` over
three wire dialects (`openai-chat-completions`, `openai-responses`,
`anthropic-messages`) — the body's `model` is the outward name.
`chat.complete` answers `{body, losses}`; `chat.stream` relays dialect
SSE frames as `stream:"data"` lines then one `stream:"end"` line.
`chat.cancel` cancels an in-flight request by its `requestId`. Chat
requests run on their own tasks, so replies and frames for different
requests may interleave — correlate by `id`. `upstreamDeadlineSecs`
absent or `0` waits unbounded — the caller cancels; a positive value
bounds one upstream call.

- `--config` / `FAIRLINY_CONFIG` — routes document. Each entry names
  exactly one surface — a catalog `provider` or an explicit `endpoint`;
  both or neither refuses startup:
  `{"credentialScopes":{"openai-key":["<credentialId>"],"vendor-key":["<otherCredentialId>"]},`
  `"routes":[{"model":"chat","provider":"openai","upstreamModel":"gpt-4o-mini","protocol":"openai-chat-completions","auth":"api-key","credentialScope":"openai-key"},`
  `{"model":"vendor","endpoint":{"baseUrl":"https://api.vendor.example/v1","protocol":"openai-chat-completions"},"auth":"api-key","authHeader":"authorization","credentialScope":"vendor-key","upstreamModel":"vendor-large"}]}`
  — an `api-key`/`bearer` route must name its authorized credential
  scope so catalog and custom vendors never share a key; upstream
  requests never follow redirects. See
  [integration modes](docs/integration-modes.md) for the full schema.
- `--state-root` / `FAIRLINY_STATE_ROOT` — the metering data home
  (default `~/.fairliny`, else `fairliny` under `XDG_STATE_HOME` or
  `LOCALAPPDATA`; never the working directory — with no absolute base
  the process refuses to start metered); `--no-meter` keeps counters in
  memory and skips the journal.
- `FAIRLINY_HANDOFF_FD` — an inherited file descriptor carrying the
  `CredentialHandoff` document (unix). `FAIRLINY_EPOCH_FILE` names the
  file the custody owner rewrites on epoch rotation; without it the
  lease runs against its own minted epoch — resolution works, revocation
  has no channel.

## Verify

```sh
./scripts/verify.sh
```

## License

AGPL-3.0-or-later
