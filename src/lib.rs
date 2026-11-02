//! Fairliny — the unified model gateway.
//!
//! Fairliny gathers model-provider access (a4mp adapters) and credential
//! leases (Credential-Lease) into one outward model-service face. The core
//! is forwarding-only: a caller names a model, [`router`] binds the
//! configured provider profile to a live a4mp adapter, [`leases`] answers
//! credentials from a process-bound `CredentialLease`, and the response
//! forwards back untouched. Metera usage metering composes in beside the
//! forward path — a request-admission counter and a response-settlement
//! hook in [`meter`] — never inside it.
//!
//! Boundaries are structural:
//!
//! - **Custody, persistence and owner authorization belong to the host.**
//!   Fairliny consumes `CredentialHandoff` documents over a process-local
//!   channel and rebuilds process-bound `CredentialLease`s; it never
//!   stores keys, and secret bytes never appear in serialized output,
//!   debug projections, logs or errors.
//! - **Unknown usage stays unknown.** A counter the provider did not
//!   report stays absent; one it named without a count settles as
//!   `Quality::Unknown` — a zero would be a claim the gateway has no
//!   right to make.
//! - **Metering is fault-isolated.** Both hooks run beside the forwarded
//!   request; a metering failure is counted in-process and never
//!   propagated into a response.
//! - **The host owns the listeners.** `fairliny serve` is an NDJSON
//!   sidecar on stdio; [`export`] returns exposition text for a
//!   host-mounted `/metrics` route — Fairliny never opens a socket.

pub mod error;
pub mod export;
pub mod leases;
pub mod meter;
pub mod router;
pub mod service;

pub use error::Error;

/// Every public fallible result in this crate.
pub type Result<T> = std::result::Result<T, Error>;
