//! fairlead — the unified model gateway.
//!
//! `fairlead serve [--config FILE] [--state-root DIR] [--no-meter]` runs
//! the NDJSON sidecar: one request per stdin line, one reply per stdout
//! line. The process composes, it does not listen — the host owns the
//! sockets, the custody, and the epoch file it rotates to revoke.
//!
//! The routes document is `{"upstreamDeadlineSecs"?: 600,
//! "routes":[{model,provider,upstreamModel?,protocol?,region?,auth?}]}` —
//! the deadline bounds one upstream call (`0` waits unbounded), and a
//! malformed entry refuses startup rather than running half a table.

use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use fairlead::leases::{FileEpochSource, Leases};
use fairlead::meter::Meter;
use fairlead::router::Router;
use fairlead::service::{DEFAULT_UPSTREAM_DEADLINE, Service};
use fairlead::{Error, Result};

/// The default data home when `--state-root` and `FAIRLEAD_STATE_ROOT`
/// both stay silent.
fn default_state_root() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(|home| PathBuf::from(home).join(".fairlead"))
        .unwrap_or_else(|_| PathBuf::from(".fairlead"))
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  fairlead serve [--config FILE] [--state-root DIR] [--no-meter]\n\n\
         environment:\n  \
         FAIRLEAD_CONFIG       routes document (same shape as --config)\n  \
         FAIRLEAD_STATE_ROOT   metering data home (default ~/.fairlead)\n  \
         FAIRLEAD_HANDOFF_FD   inherited fd carrying the CredentialHandoff document\n  \
         FAIRLEAD_EPOCH_FILE   file the custody owner rewrites to rotate the lease epoch"
    );
    exit(2)
}

/// The upstream-deadline knob the routes document carries:
/// `upstreamDeadlineSecs` bounds one provider call so a hung upstream
/// cannot stall the whole gateway — `0` opts back into an unbounded
/// wait. Absent means [`DEFAULT_UPSTREAM_DEADLINE`].
fn upstream_deadline(config: &Value) -> Result<Option<Duration>> {
    match config.get("upstreamDeadlineSecs") {
        None => Ok(Some(DEFAULT_UPSTREAM_DEADLINE)),
        Some(value) => {
            let seconds = value.as_u64().ok_or_else(|| {
                Error::Request("upstreamDeadlineSecs requires a non-negative integer".to_owned())
            })?;
            Ok((seconds > 0).then(|| Duration::from_secs(seconds)))
        }
    }
}

/// Read the handoff document off the host-inherited descriptor.
///
/// The host owns the descriptor's lifetime and it must already be open,
/// so the channel reads through our own duplicate: the `File` may close
/// its copy freely without ever retiring the host's descriptor.
#[cfg(unix)]
fn read_handoff_fd(fd: std::os::fd::RawFd) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    use std::os::fd::BorrowedFd;
    // SAFETY: the host contract behind FAIRLEAD_HANDOFF_FD guarantees an
    // open descriptor; borrowing it does not take ownership.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let channel = std::fs::File::from(
        borrowed
            .try_clone_to_owned()
            .map_err(|error| Error::Credential(format!("handoff channel: {error}")))?,
    );
    Leases::read_handoff(channel)
}

/// Read and install the handoff the host left on the inherited fd.
///
/// The channel and the epoch source are the two custody answers the
/// runtime needs: `FAIRLEAD_EPOCH_FILE` gives revocation a way to arrive;
/// without it the lease runs against its own minted epoch — functional,
/// but revocation has no channel.
fn install_handoff_if_offered(leases: &Leases) -> Result<()> {
    let Some(fd) = std::env::var("FAIRLEAD_HANDOFF_FD")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
    else {
        return Ok(());
    };
    #[cfg(unix)]
    {
        let document = read_handoff_fd(fd)?;
        match std::env::var("FAIRLEAD_EPOCH_FILE") {
            Ok(path) => leases.install_handoff(&document, Arc::new(FileEpochSource::new(path))),
            Err(_) => leases.install_handoff_self_epoch(&document),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = fd;
        Err(Error::Credential(
            "inherited-fd handoff requires a unix host".to_owned(),
        ))
    }
}

async fn serve(args: &[String]) -> Result<()> {
    let state_root = flag_value(args, "--state-root")
        .or_else(|| std::env::var("FAIRLEAD_STATE_ROOT").ok())
        .map(PathBuf::from)
        .unwrap_or_else(default_state_root);
    let config_text = flag_value(args, "--config")
        .or_else(|| std::env::var("FAIRLEAD_CONFIG").ok())
        .map(|path| {
            std::fs::read_to_string(&path)
                .map_err(|error| Error::Request(format!("config {path}: {error}")))
        })
        .transpose()?;
    let config: Value = match config_text {
        Some(text) => serde_json::from_str(&text)
            .map_err(|error| Error::Request(format!("config parse: {error}")))?,
        None => Value::Null,
    };

    let leases = Leases::disconnected();
    install_handoff_if_offered(&leases)?;
    let transport = Arc::new(a4mp::ReqwestTransport::new());
    let mut router = Router::new(transport, Arc::new(leases));
    router.load_routes(&config)?;
    let deadline = upstream_deadline(&config)?;

    let meter = if args.iter().any(|arg| arg == "--no-meter") {
        Meter::unmetered()
    } else {
        Meter::open(&state_root)?
    };
    let service = Service::new(router, meter).with_upstream_deadline(deadline);
    // Tokio's stdin reads through its blocking pool, so an idle sidecar
    // still yields the runtime to the settlement tasks replies spawned.
    service
        .serve(
            tokio::io::BufReader::new(tokio::io::stdin()),
            tokio::io::stdout(),
        )
        .await
        .map_err(|error| Error::Request(format!("serve loop: {error}")))?;
    // Drain settlements so a settled request is never lost to process exit.
    service.flush_metering().await;
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("serve") => serve(&args[1..]).await,
        _ => usage(),
    };
    if let Err(error) = result {
        eprintln!("error: {error}");
        exit(1);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use fairlead::leases::ProviderCredential;
    use std::collections::BTreeMap;
    use std::os::fd::{AsRawFd, BorrowedFd};
    use std::time::Duration;

    /// One API-key handoff minted under a fresh epoch — the document the
    /// host would leave on the inherited descriptor.
    fn handoff_bytes() -> Vec<u8> {
        let credential = credential_lease::LeasedCredential::new(
            uuid::Uuid::new_v4().to_string(),
            credential_lease::SecretBytes::try_from_bytes(b"test-material".to_vec())
                .expect("secret"),
            None,
        )
        .expect("credential");
        let mut credentials = BTreeMap::new();
        credentials.insert(ProviderCredential::ApiKey, vec![credential]);
        credential_lease::CredentialHandoff::new(
            credentials,
            Duration::from_secs(3600),
            uuid::Uuid::new_v4().to_string(),
        )
        .expect("handoff")
        .to_json()
        .expect("document")
        .expose_bytes()
        .to_vec()
    }

    #[test]
    fn the_inherited_descriptor_survives_the_handoff_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("handoff.json");
        std::fs::write(&path, handoff_bytes()).expect("write");
        let file = std::fs::File::open(&path).expect("open");
        let fd = file.as_raw_fd();

        let document = read_handoff_fd(fd).expect("document");
        assert!(!document.is_empty());

        // The host-owned descriptor is still live: the File the channel
        // read through only ever owned a duplicate of it.
        let still_open = unsafe { BorrowedFd::borrow_raw(fd) }
            .try_clone_to_owned()
            .expect("the inherited descriptor is still open");
        drop(still_open);

        // And the read document installs into a working lease.
        let leases = Leases::disconnected();
        leases
            .install_handoff_self_epoch(&document)
            .expect("install");
        assert!(leases.slot().resolve(ProviderCredential::ApiKey).is_ok());
    }
}
