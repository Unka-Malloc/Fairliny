# Composition: one host, one face family

Fairliny is the host's outward service face — model traffic today, MCP
tool traffic through `fairliny-registrar` when the host enables it. The
face family shares three engines it never reimplements:

- **a4mp** — provider access (endpoints, auth, stream framing).
- **Credential-Lease** — process-bound leases rebuilt from
  `CredentialHandoff`; the gateway stores no keys.
- **Metera** — all usage accounting: admission counters beside the
  forward, settled observations into the `agent-usage` journal.

## Single-instance injection

A host that embeds Metera itself (LicoUp collecting agent-side usage)
and embeds Fairliny must not end up with two journal engines. The
composition root owns the engines; faces receive handles:

```
composition root (host)
  ├─ UsageSourceHost  ──► Meter::shared(state_root, host, binding)
  │                        agent-statistics collectors read the same
  │                        host — one writer per ledger, process-wide
  └─ fairliny_registrar::Registry ──► the same registry feeds the
                            gateway's MCP face and any standalone face
```

`Meter::shared` composes the gateway's own admission counters (its own
`gateway-usage.json` document) onto an injected `UsageSourceHost`; the
gateway still mints its own source binding, so gateway-settled facts
stay attributable to the gateway.

A self-contained gateway keeps `Meter::open`/`Meter::compose` — they
open a private `UsageSourceHost` and pass it to `shared`. Injection is
an option, never a requirement.

## What the face never owns

Listeners and network surface (the host binds; exposition is returned
text), root credential custody, ledgers and charges, dashboards. The
gateway's metered facts and the host's agent-side facts converge only
at the shared journal and the collection store — never by the gateway
reaching into agent records or the host reaching into the forward path.
