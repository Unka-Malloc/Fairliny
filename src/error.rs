//! The crate's outward error type.
//!
//! Variants carry stable, secret-free text: adapter failures relay the
//! provider's own message, lease failures the lease contract's refusal
//! codes, and route failures name the model — never credential material.

/// One failure domain per composition boundary.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No route or host-bound adapter carries this model name.
    #[error("unknown model {0:?}")]
    UnknownModel(String),

    /// The route named a surface the catalog cannot bind: an unknown
    /// provider, an auth mechanism the profile never accepts, or a
    /// protocol the profile does not expose.
    #[error("route {model}: {reason}")]
    Route { model: String, reason: String },

    /// Credential resolution failed — the lease was absent, expired or
    /// revoked, or the mechanism has no leased kind. The message is the
    /// contract's refusal code, never secret material.
    #[error("credentials: {0}")]
    Credential(String),

    /// The metering composition failed to open or read its store.
    #[error("metering: {0}")]
    Meter(String),

    /// The request could not be parsed into a forwardable call.
    #[error("request: {0}")]
    Request(String),

    /// The upstream call outlived the configured deadline and was
    /// cancelled — whether the provider accepted the work is unknown, so
    /// repeating the request is the caller's explicit decision.
    #[error("upstream deadline exceeded after {0:?}")]
    UpstreamDeadline(std::time::Duration),

    /// The bound provider adapter failed the call.
    #[error("adapter: {0}")]
    Adapter(#[from] a4mp::Error),
}
