# Fairlead

The unified model gateway. It gathers model-provider access (a4mp) and
credential leases (Credential-Lease) into one outward model-service face;
a forwarding-only core with Metera usage metering composed in.

A caller names a model; the router binds the configured provider profile
to a live a4mp adapter; the lease port answers credentials from a
process-bound `CredentialLease`; the response forwards back untouched.
Metering runs beside that path — one admission counter and one settlement
hook — never inside it.

## Boundary

- **Custody, persistence and owner authorization belong to the host.**
  Fairlead consumes `CredentialHandoff` documents over a process-local
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
- **The host owns the listeners.** `fairlead serve` is an NDJSON sidecar
  on stdio; `metrics.exposition` returns text for a host-mounted
  `/metrics` route — Fairlead never opens a socket for metrics.

## Modules

| Module | Owns |
| --- | --- |
| `router` | Outward model names bound to provider access surfaces: catalog profile, protocol target, auth mechanism, upstream model id. Unknown models and unaccepted auth fail closed. |
| `leases` | The credential custody port: the `ProviderCredential` kind family, the process-bound `CredentialSlot`, `FileEpochSource` for custody-driven revocation, and a4mp's `CredentialResolver`. |
| `meter` | Metera composed in: bounded per-day agent×model request counters (`GatewayUsageRecorder`-shaped), and response settlement — `ProviderMapping` → `SourceBinding` → `UsageSourcePort` — into the usage journal. |
| `export` | Prometheus/OpenMetrics text from `agent-statistics::export` for a host-mounted scrape route. |
| `service` | The `fairlead serve` sidecar: one JSON request per stdin line, methods `models.list`, `chat.complete`, `metrics.exposition`. |

## `fairlead serve`

```
fairlead serve [--config routes.json] [--state-root DIR]
```

Requests are one JSON object per line: `{"id":N,"method":...,"params":{}}`.
Replies are `{"id":N,"result":{...}}` or `{"id":N,"error":"..."}`; a
malformed line answers `id: null` and the loop continues.

- `--config` / `FAIRLEAD_CONFIG` — routes document:
  `{"routes":[{"model":"chat","provider":"openai","upstreamModel":"gpt-4o-mini","protocol":"openai-chat-completions","auth":"api-key"}]}`
- `--state-root` / `FAIRLEAD_STATE_ROOT` — the metering data home
  (default `~/.fairlead`); `--no-meter` keeps counters in memory and
  skips the journal.
- `FAIRLEAD_HANDOFF_FD` — an inherited file descriptor carrying the
  `CredentialHandoff` document (unix). `FAIRLEAD_EPOCH_FILE` names the
  file the custody owner rewrites on epoch rotation; without it the
  lease runs against its own minted epoch — resolution works, revocation
  has no channel.

## Verify

```sh
./scripts/verify.sh
```

## License

AGPL-3.0-or-later
