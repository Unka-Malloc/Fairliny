# Agent rules for Fairliny

## Boundary

Fairliny is the outward model-service face: a4mp adapters, credential
leases and Metera metering gathered behind one forwarding-only surface.
Custody — system keyring access, persistence, owner authorization —
belongs to the host and never enters this repository: Fairliny consumes
`CredentialHandoff` documents over a process-local channel and rebuilds
process-bound `CredentialLease`s; it never stores keys, and secret bytes
never appear in serialized output, debug projections, logs or errors.
Usage the provider did not count stays `Quality::Unknown`, never zeroed;
metering runs beside the forwarded request and its failures are counted
in-process, never propagated into a response. The host owns the
listeners and the network face — the exposition is returned text, never
a socket Fairliny opened.

## Verify

`scripts/verify.sh` — fmt + clippy + tests.
