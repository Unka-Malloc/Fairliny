//! The upstream transport posture leased credentials require.
//!
//! Adapters send on the transport the host injects, and authenticated
//! routes carry credential material in their headers — `x-api-key`,
//! `x-goog-api-key`, `Authorization`. The router validates the
//! configured endpoint origin at declaration, so that origin is the only
//! place those headers may ever go. a4mp's default SDK transport
//! (`a4mp::ReqwestTransport::new()`) builds a stock reqwest client, which
//! follows redirects — and reqwest does not strip those headers on a
//! cross-origin redirect — so the transport bound for a leased router
//! must never follow one. A provider that legitimately redirects answers
//! its 3xx, and the refusal surfaces through the adapter's own error
//! path.

use std::sync::Arc;

use crate::{Error, Result};

/// The reqwest client the gateway's upstream calls ride: redirects are
/// never followed. Hosts that need caller-configured TLS or proxy
/// settings build their equivalent — the redirect policy is the part
/// the credential contract requires.
pub fn upstream_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| Error::Request(format!("upstream transport: {error}")))
}

/// The SDK transport for routers that forward leased credentials — the
/// same redirect-disabled posture the sidecar builds for itself.
pub fn upstream_transport() -> Result<Arc<dyn a4mp::Transport>> {
    Ok(Arc::new(a4mp::ReqwestTransport::with_client(
        upstream_client()?,
    )))
}
