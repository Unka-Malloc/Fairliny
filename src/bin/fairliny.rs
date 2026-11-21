//! fairliny — the unified model gateway.
//!
//! `fairliny serve [--config FILE] [--state-root DIR] [--no-meter]` runs
//! the NDJSON sidecar: one request per stdin line, one reply per stdout
//! line. The process composes, it does not listen — the host owns the
//! sockets, the custody, and the epoch file it rotates to revoke.
//!
//! The routes document is `{"upstreamDeadlineSecs"?,
//! "credentialScopes"?: {"<scope>": ["<credentialId>", ...]},
//! "routes":[{model,provider,upstreamModel?,protocol?,region?,auth?,vars?,
//! credentialScope?} | {model,endpoint:{baseUrl,protocol},upstreamModel?,
//! auth?,authHeader?,credentialScope?}]}` — the deadline bounds one
//! upstream call when the host sets it (`0` or absent waits unbounded —
//! the caller cancels; the sidecar never self-times-out viable work), and
//! a malformed entry refuses startup rather than running half a table.
//! A `credentialScope` is required on `api-key`/`bearer` routes and names
//! a `credentialScopes` authorization: the credential ids from the
//! handoff that scope may resolve — a scope the document does not
//! authorize holds no credential and fails closed.

use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

#[cfg(unix)]
use fairliny_gateway::leases::FileEpochSource;
use fairliny_gateway::leases::Leases;
use fairliny_gateway::meter::Meter;
use fairliny_gateway::router::Router;
use fairliny_gateway::service::Service;
use fairliny_gateway::{Error, Result};

/// The default data home when `--state-root` and `FAIRLINY_STATE_ROOT`
/// both stay silent: `~/.fairliny` under the home directory, else
/// `fairliny` under the platform state directory (`XDG_STATE_HOME`,
/// `LOCALAPPDATA`). Only absolute bases count, so metering data never
/// lands in the working directory — `None` when no base resolves.
fn default_state_root(var: impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    let absolute = |name: &str| {
        var(name)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    };
    absolute("HOME")
        .or_else(|| absolute("USERPROFILE"))
        .map(|home| home.join(".fairliny"))
        .or_else(|| {
            absolute("XDG_STATE_HOME")
                .or_else(|| absolute("LOCALAPPDATA"))
                .map(|state| state.join("fairliny"))
        })
}

/// The metering data home: the explicit flag or variable, else the
/// default; refused when nothing resolves outside the working directory.
fn state_root(args: &[String]) -> Result<PathBuf> {
    flag_value(args, "--state-root")
        .or_else(|| std::env::var("FAIRLINY_STATE_ROOT").ok())
        .map(PathBuf::from)
        .or_else(|| default_state_root(|name| std::env::var(name).ok()))
        .ok_or_else(|| {
            Error::Request(
                "no metering state root: set --state-root or FAIRLINY_STATE_ROOT, \
                 or pass --no-meter"
                    .to_owned(),
            )
        })
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  fairliny serve [--config FILE] [--state-root DIR] [--no-meter]\n\n\
         environment:\n  \
         FAIRLINY_CONFIG       routes document (same shape as --config)\n  \
         FAIRLINY_STATE_ROOT   metering data home (default ~/.fairliny, else\n                        \
         fairliny under XDG_STATE_HOME or LOCALAPPDATA)\n  \
         FAIRLINY_HANDOFF_FD   inherited fd carrying the CredentialHandoff document\n  \
         FAIRLINY_EPOCH_FILE   file the custody owner rewrites to rotate the lease epoch"
    );
    exit(2)
}

/// The upstream-deadline knob the routes document carries: absent or `0`
/// waits unbounded — a viable call ends by caller cancel or provider
/// answer. A positive value is the host's explicit bound on one upstream
/// call, so a hung upstream cannot stall the whole gateway.
fn upstream_deadline(config: &Value) -> Result<Option<Duration>> {
    match config.get("upstreamDeadlineSecs") {
        None => Ok(None),
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
    // SAFETY: the host contract behind FAIRLINY_HANDOFF_FD guarantees an
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
/// runtime needs: `FAIRLINY_EPOCH_FILE` gives revocation a way to arrive;
/// without it the lease runs against its own minted epoch — functional,
/// but revocation has no channel.
fn install_handoff_if_offered(leases: &Leases) -> Result<()> {
    let Some(fd) = std::env::var("FAIRLINY_HANDOFF_FD")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
    else {
        return Ok(());
    };
    #[cfg(unix)]
    {
        let document = read_handoff_fd(fd)?;
        match std::env::var("FAIRLINY_EPOCH_FILE") {
            Ok(path) => leases.install_handoff(&document, Arc::new(FileEpochSource::new(path))),
            Err(_) => leases.install_handoff_self_epoch(&document),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (fd, leases);
        Err(Error::Credential(
            "inherited-fd handoff requires a unix host".to_owned(),
        ))
    }
}

/// The sidecar's HTTP client. Redirects are never followed: the router
/// validates the configured endpoint origin, and a redirect could carry
/// the credential headers adapters place (`x-api-key`,
/// `x-goog-api-key`, `Authorization`) to an origin the host never
/// validated. A provider that legitimately redirects answers 3xx, and
/// the refusal surfaces through the adapter's own error path.
fn upstream_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| Error::Request(format!("upstream transport: {error}")))
}

async fn serve(args: &[String]) -> Result<()> {
    let config_text = flag_value(args, "--config")
        .or_else(|| std::env::var("FAIRLINY_CONFIG").ok())
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

    let leases = Arc::new(Leases::disconnected());
    // Authorize first, then install: a handoff's credentials land already
    // divided into the scopes the document authorized.
    leases.authorize_scopes(&config)?;
    install_handoff_if_offered(&leases)?;
    let transport = Arc::new(a4mp::ReqwestTransport::with_client(upstream_client()?));
    let mut router = Router::with_leases(transport, leases);
    router.load_routes(&config)?;
    let deadline = upstream_deadline(&config)?;

    let meter = if args.iter().any(|arg| arg == "--no-meter") {
        Meter::unmetered()
    } else {
        Meter::open(&state_root(args)?)?
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

#[cfg(test)]
mod deadline_tests {
    use super::*;

    #[test]
    fn an_absent_deadline_waits_unbounded() {
        assert_eq!(
            upstream_deadline(&serde_json::json!({})).expect("deadline"),
            None
        );
        assert_eq!(
            upstream_deadline(&serde_json::Value::Null).expect("deadline"),
            None
        );
    }

    #[test]
    fn a_zero_deadline_waits_unbounded() {
        assert_eq!(
            upstream_deadline(&serde_json::json!({"upstreamDeadlineSecs": 0})).expect("deadline"),
            None
        );
    }

    #[test]
    fn a_positive_deadline_is_the_hosts_bound() {
        assert_eq!(
            upstream_deadline(&serde_json::json!({"upstreamDeadlineSecs": 60})).expect("deadline"),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn a_non_integer_deadline_is_refused() {
        assert!(upstream_deadline(&serde_json::json!({"upstreamDeadlineSecs": "60"})).is_err());
        assert!(upstream_deadline(&serde_json::json!({"upstreamDeadlineSecs": -1})).is_err());
        assert!(upstream_deadline(&serde_json::json!({"upstreamDeadlineSecs": 1.5})).is_err());
    }
}

#[cfg(test)]
mod state_root_tests {
    use super::*;

    /// An absolute path in this platform's form.
    fn absolute(name: &str) -> String {
        std::env::temp_dir()
            .join(name)
            .to_string_lossy()
            .into_owned()
    }

    fn lookup(vars: &[(&str, String)]) -> impl Fn(&str) -> Option<String> {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .collect();
        move |name| {
            vars.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        }
    }

    #[test]
    fn the_home_directory_is_the_default_base() {
        let home = absolute("home");
        assert_eq!(
            default_state_root(lookup(&[("HOME", home.clone())])),
            Some(PathBuf::from(home).join(".fairliny"))
        );
    }

    #[test]
    fn without_a_home_the_platform_state_dir_is_used() {
        let state = absolute("state");
        assert_eq!(
            default_state_root(lookup(&[("XDG_STATE_HOME", state.clone())])),
            Some(PathBuf::from(state).join("fairliny"))
        );
        let local = absolute("local");
        assert_eq!(
            default_state_root(lookup(&[("LOCALAPPDATA", local.clone())])),
            Some(PathBuf::from(local).join("fairliny"))
        );
    }

    #[test]
    fn relative_or_missing_bases_never_resolve_into_the_working_directory() {
        assert_eq!(default_state_root(lookup(&[])), None);
        assert_eq!(
            default_state_root(lookup(&[
                ("HOME", String::new()),
                ("USERPROFILE", ".".to_owned()),
                ("XDG_STATE_HOME", "state".to_owned()),
                ("LOCALAPPDATA", "local".to_owned()),
            ])),
            None
        );
        // A relative home is skipped in favour of an absolute state dir.
        let state = absolute("state");
        assert_eq!(
            default_state_root(lookup(&[
                ("HOME", ".".to_owned()),
                ("XDG_STATE_HOME", state.clone())
            ])),
            Some(PathBuf::from(state).join("fairliny"))
        );
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use fairliny_gateway::leases::ProviderCredential;
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

#[cfg(test)]
mod transport_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[tokio::test(flavor = "current_thread")]
    async fn an_upstream_redirect_is_never_followed() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let url = format!("http://{}/v1/chat", listener.local_addr().expect("addr"));
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request);
            socket
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example/\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .expect("respond");
        });
        // A redirect is answered, not followed: the 3xx surfaces as the
        // response and the credential headers never reach the redirect's
        // origin.
        let response = upstream_client()
            .expect("client")
            .get(&url)
            .send()
            .await
            .expect("response");
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        server.join().expect("server");
    }
}
