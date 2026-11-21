---
name: fairliny-sidecar
description: Drive the fairliny gateway from any language — `fairliny serve` is an NDJSON stdio sidecar exposing models.list, chat.complete, chat.stream, chat.cancel and metrics.exposition.
---

# fairliny Sidecar mode

Spawn `fairliny serve`, write one JSON request per stdin line, read one
JSON reply per stdout line.

## When to use

- The host is not Rust, or wants the gateway behind a process it can
  supervise and feed custody into.
- The host keeps owning everything the process must not: listeners,
  credential custody, the revocation epoch file.

## Session shape

- Wire: `{"id":N,"method":"...","params":{}}` in;
  `{"id":N,"result":{}}` or `{"id":N,"error":"..."}` out. A malformed,
  oversized or non-UTF-8 line answers `id: null` and the loop continues;
  EOF ends the process.
- `models.list` — the bound route table: configured surfaces and
  prebound adapters, never a provider discovery.
- `chat.complete` / `chat.stream` — `params` is
  `{dialect, body, agent?}`: `dialect` is one of
  `openai-chat-completions`, `openai-responses`, `anthropic-messages`;
  `body` is that dialect's full request object whose `model` field names
  the outward model; `agent` attributes the admission (default
  `"stdio"`). `chat.complete` answers `{body, losses}` — the dialect
  response plus every conversion loss the wire codecs reported.
  `chat.stream` relays the dialect's SSE frames as
  `{"stream":"data","frame":{event,id,data}}` lines, then exactly one
  `{"stream":"end","status":"done|error|cancelled","losses":[...]}`.
  Frames and other requests' replies may interleave — correlate by `id`.
- `chat.cancel` — `params.requestId` names the in-flight request's `id`;
  answers `{cancelled: true}` or an `unknown in-flight request` error.
- `metrics.exposition` — `{contentType, exposition}`; the host mounts
  the text at its own `/metrics` route.

## Rules that keep the contract

- Configuration lands by launch flags or environment: `--config` /
  `FAIRLINY_CONFIG` for the routes document, `--state-root` /
  `FAIRLINY_STATE_ROOT` for the metering data home (default
  `~/.fairliny`, else `fairliny` under `XDG_STATE_HOME` or
  `LOCALAPPDATA`, never the working directory), `--no-meter` for
  in-memory counters with no journal.
- Credentials arrive through `FAIRLINY_HANDOFF_FD` — an inherited file
  descriptor carrying the `CredentialHandoff` document.
  `FAIRLINY_EPOCH_FILE` names the file the custody owner rewrites on
  epoch rotation; without it the lease resolves but revocation has no
  channel.
- A route entry names a catalog `provider` or an explicit
  `endpoint: {baseUrl, protocol}` (with optional `authHeader`), never
  both — any vendor the catalog lacks is declared that way. A malformed
  route entry refuses startup rather than running half a
  route table; unknown models and unaccepted auth mechanisms fail
  closed. A supplied `auth` of the wrong type refuses too — it is never
  silently treated as `none` — and an endpoint route can only name a
  leased mechanism (`none`, `api-key`, `bearer`).
- One handoff may carry several vendors' credentials: `api-key`/`bearer`
  entries declare `credentialScope`, naming an entry in the document's
  `credentialScopes` table — the `credentialId`s the host authorized
  for that route's surface. A scope holding no matching credential
  fails closed; two vendors on `api-key` never share a key. Upstream
  requests never follow redirects — the validated endpoint origin is
  the only place credential headers go.
- `upstreamDeadlineSecs` in the routes document is the host's opt-in
  bound on one upstream provider call: absent or `0` waits unbounded —
  a viable call ends by caller cancellation or provider answer, never by
  a deadline the sidecar invented.
