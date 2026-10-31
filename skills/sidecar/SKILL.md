---
name: fairlead-sidecar
description: Drive the fairlead gateway from any language — `fairlead serve` is an NDJSON stdio sidecar exposing models.list, chat.complete and metrics.exposition.
---

# fairlead Sidecar mode

Spawn `fairlead serve`, write one JSON request per stdin line, read one
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
- `chat.complete` — `params.model` names the outward model,
  `params.messages` carries `{role, text}` entries plus common sampling
  keys and an `extensions` object forwarded verbatim;
  `params.agent` attributes the admission (default `"stdio"`).
- `metrics.exposition` — `{contentType, exposition}`; the host mounts
  the text at its own `/metrics` route.

## Rules that keep the contract

- Configuration lands by launch flags or environment: `--config` /
  `FAIRLEAD_CONFIG` for the routes document, `--state-root` /
  `FAIRLEAD_STATE_ROOT` for the metering data home (default
  `~/.fairlead`), `--no-meter` for in-memory counters with no journal.
- Credentials arrive through `FAIRLEAD_HANDOFF_FD` — an inherited file
  descriptor carrying the `CredentialHandoff` document.
  `FAIRLEAD_EPOCH_FILE` names the file the custody owner rewrites on
  epoch rotation; without it the lease resolves but revocation has no
  channel.
- A malformed route entry refuses startup rather than running half a
  route table; unknown models and unaccepted auth mechanisms fail
  closed.
