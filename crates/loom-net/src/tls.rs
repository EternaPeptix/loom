//! The interception CA and per-host leaf certificates (CONTRACTS-TRAFFIC-TARGETS I2, I4).
//!
//! CONTRACT
//!
//! - [`Ca::load_or_create`] reads `{dir}/loom-ca.pem` and `{dir}/loom-ca.key`, or creates them (ECDSA
//!   P-256, 10 years, CN "loom interception CA (this machine)", key file mode `0600`).
//! - [`Ca::leaf`] returns a server config for a host (SAN = the name or IP, 24 h, ALPN `http/1.1`),
//!   cached per host for the life of the `Ca`.
//! - [`ca_bundle`] writes the system roots followed by the CA to a file and returns its path (I3).

use std::path::{Path, PathBuf};
use std::sync::Arc;

#[non_exhaustive]
pub struct Ca {
    pub cert_pem: String,
    pub fingerprint_sha256: String,
}

impl Ca {
    pub fn load_or_create(_dir: &Path) -> Result<Arc<Ca>, String> {
        todo!("CONTRACTS-TRAFFIC-TARGETS I2")
    }
    pub fn rotate(_dir: &Path) -> Result<Arc<Ca>, String> {
        todo!("CONTRACTS-TRAFFIC-TARGETS I2")
    }
}

/// Writes `{dir}/ca-bundle.pem` (system roots, then the loom CA) and returns its path.
pub fn ca_bundle(_ca: &Ca, _dir: &Path) -> Result<PathBuf, String> {
    todo!("CONTRACTS-TRAFFIC-TARGETS I3")
}

/// The environment variables that point a command's TLS clients at the bundle (I3).
pub const BUNDLE_ENV: [&str; 7] = [
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "GIT_SSL_CAINFO",
    "PIP_CERT",
    "AWS_CA_BUNDLE",
];
