//! Metrics exposition for a host-mounted scrape route.
//!
//! Fairliny returns text; the host owns the listener. The projection is
//! `agent-statistics`' own: the same journal the gateway settles into is
//! the journal a scrape summarizes, and the retained request counters
//! arrive as the gateway document the exposition already understands.

use crate::meter::Meter;
use crate::{Error, Result};

/// The media type a host should serve the exposition as.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4";

/// Render the Prometheus/OpenMetrics exposition the journal and the
/// request counters currently retain. Deterministic for one store state;
/// an unmetered gateway still projects its counters.
pub fn render(meter: &Meter) -> Result<String> {
    let document = meter.usage_document();
    match meter.with_journal(|host| agent_statistics::export::render(host, document.as_ref())) {
        Some(result) => result.map_err(|error| Error::Meter(error.to_string())),
        None => Ok(agent_statistics::export::exposition(&[], document.as_ref())),
    }
}
