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
//!
//! Proxy posture is split by scheme, because URL validation cannot
//! constrain the hop an ambient proxy would see: the only `http`
//! authorities the router accepts are loopback literals, and those ride
//! a direct client that never consults proxy settings — no environment
//! proxy can receive a cleartext payload or a leased credential meant
//! for a local peer. Verified-`https` requests keep the ordinary client
//! posture, where an enterprise proxy may still broker the CONNECT
//! tunnel without ever seeing plaintext.

use std::sync::Arc;

use crate::{Error, Result};

/// The reqwest client posture the gateway's HTTPS calls ride: redirects
/// are never followed. Hosts that need caller-configured TLS or proxy
/// settings build their equivalent — the redirect policy is the part
/// the credential contract requires.
pub fn upstream_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| Error::Request(format!("upstream transport: {error}")))
}

/// The cleartext posture: same redirect refusal on a client that never
/// consults proxy settings, so a permitted local `http` request can only
/// reach the peer its URL names.
fn direct_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(|error| Error::Request(format!("upstream transport: {error}")))
}

/// The two-pool transport leased routes ride: cleartext requests go
/// through the direct client and TLS requests through the ordinary one.
/// One pool each — `ReqwestTransport` clones share it — keeps
/// connection reuse identical to a single-client transport.
struct UpstreamTransport {
    cleartext: a4mp::ReqwestTransport,
    tls: a4mp::ReqwestTransport,
}

impl UpstreamTransport {
    /// The pool a request's own URL selects: `http` always takes the
    /// direct client — its only permitted authorities are loopback
    /// literals — and everything else the TLS one.
    fn pool(&self, req: &a4mp::HttpRequest) -> &a4mp::ReqwestTransport {
        match req.url.scheme() {
            "http" => &self.cleartext,
            _ => &self.tls,
        }
    }
}

#[async_trait::async_trait]
impl a4mp::Transport for UpstreamTransport {
    async fn send(
        &self,
        req: a4mp::HttpRequest,
        ctrl: &a4mp::RequestControl,
    ) -> std::result::Result<a4mp::HttpResponse, a4mp::TransportError> {
        self.pool(&req).send(req, ctrl).await
    }

    async fn send_stream(
        &self,
        req: a4mp::HttpRequest,
        ctrl: &a4mp::RequestControl,
    ) -> std::result::Result<a4mp::StreamingResponse, a4mp::TransportError> {
        self.pool(&req).send_stream(req, ctrl).await
    }

    async fn open_channel(
        &self,
        req: a4mp::HttpRequest,
        ctrl: &a4mp::RequestControl,
    ) -> std::result::Result<Box<dyn a4mp::DuplexChannel>, a4mp::TransportError> {
        self.pool(&req).open_channel(req, ctrl).await
    }
}

/// The SDK transport for routers that forward leased credentials — the
/// redirect-disabled posture the sidecar builds for itself, with
/// cleartext confined to the proxy-free direct pool.
pub fn upstream_transport() -> Result<Arc<dyn a4mp::Transport>> {
    Ok(Arc::new(UpstreamTransport {
        cleartext: a4mp::ReqwestTransport::with_client(direct_client()?),
        tls: a4mp::ReqwestTransport::with_client(upstream_client()?),
    }))
}
