//! The interception CA and per-host leaf certificates (CONTRACTS-TRAFFIC-TARGETS I2, I4).
//!
//! CONTRACT
//!
//! - [`Ca::load_or_create`] reads `{dir}/ferret-ca.pem` and `{dir}/ferret-ca.key`, or creates them (ECDSA
//!   P-256, 10 years, CN "ferret interception CA (this machine)", key file mode `0600`). When both files
//!   exist but do not make a usable CA it is an error that names `ferret ca rotate`; when one of them is
//!   missing a new pair is made. [`Ca::rotate`] always makes a new pair.
//! - [`Ca::leaf`] returns a server config for a host (SAN = the name or IP, valid 24 h, signed by the
//!   CA, ALPN `http/1.1`), cached per host for the life of the `Ca`. A cached leaf older than 12 hours
//!   is minted again, so a long-running daemon never serves an expired one.
//! - [`ca_bundle`] writes the system roots (the first of `/etc/ssl/cert.pem`,
//!   `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt` that exists, else the
//!   Mozilla roots of the `webpki-root-certs` crate as PEM) followed by the CA, to `{dir}/ca-bundle.pem`,
//!   and returns its path (I3).
//! - [`upstream_client_config`] builds the rustls client config the proxy uses towards a destination: the
//!   Mozilla roots plus extra PEM roots, ALPN `http/1.1`, or no verification at all (hosts the target
//!   lists in `upstream_insecure`). All configs use the `ring` provider explicitly, so they do not
//!   depend on a process-wide default.
//! - The CA key is written through a temporary file of mode `0600` and renamed, so it is never readable
//!   by anyone else, not even briefly. `~/.ferret` is unreadable in the sandbox, so no command reads it.

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

const CA_CN: &str = "ferret interception CA (this machine)";
const CERT_FILE: &str = "ferret-ca.pem";
const KEY_FILE: &str = "ferret-ca.key";
const LEAF_LIFETIME: Duration = Duration::from_secs(24 * 3600);
const LEAF_REFRESH: Duration = Duration::from_secs(12 * 3600);
const SYSTEM_BUNDLES: [&str; 3] =
    ["/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"];

/// The interception CA: its certificate for display and the bundle, its key for signing leaves.
#[non_exhaustive]
pub struct Ca {
    pub cert_pem: String,
    pub fingerprint_sha256: String,
    key: KeyPair,
    issuer: rcgen::Certificate,
    leaves: Mutex<HashMap<String, (Instant, Arc<ServerConfig>)>>,
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ca").field("fingerprint_sha256", &self.fingerprint_sha256).finish_non_exhaustive()
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

fn ca_params() -> Result<CertificateParams, String> {
    let mut p = CertificateParams::new(Vec::<String>::new()).map_err(|e| format!("CA parameters: {e}"))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_CN);
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    let now = OffsetDateTime::now_utc();
    p.not_before = now - time::Duration::days(1);
    p.not_after = now + time::Duration::days(3650);
    Ok(p)
}

fn fingerprint(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    let hex: Vec<String> = digest.iter().map(|b| format!("{b:02X}")).collect();
    hex.join(":")
}

impl Ca {
    /// Reads the CA in `dir`, or creates it there (see the module contract).
    pub fn load_or_create(dir: &Path) -> Result<Arc<Ca>, String> {
        let (cert_path, key_path) = (dir.join(CERT_FILE), dir.join(KEY_FILE));
        if cert_path.is_file() && key_path.is_file() {
            return Ca::load(&cert_path, &key_path);
        }
        Ca::create(dir)
    }

    /// Makes a new CA in `dir`, replacing the one there.
    pub fn rotate(dir: &Path) -> Result<Arc<Ca>, String> {
        Ca::create(dir)
    }

    fn load(cert_path: &Path, key_path: &Path) -> Result<Arc<Ca>, String> {
        let unusable = |why: String| {
            format!("the CA in {} is not usable ({why}); `ferret ca rotate` makes a new one", cert_path.display())
        };
        let cert_pem = std::fs::read_to_string(cert_path).map_err(|e| unusable(format!("reading it: {e}")))?;
        let key_pem = std::fs::read_to_string(key_path).map_err(|e| unusable(format!("reading its key: {e}")))?;
        let key = KeyPair::from_pem(&key_pem).map_err(|e| unusable(format!("its key: {e}")))?;
        let cert_der = CertificateDer::from_pem_slice(cert_pem.as_bytes()).map_err(|e| unusable(format!("{e}")))?;
        // The issuer is rebuilt from the same fixed name and the same key, so its leaves chain to the
        // stored certificate (same subject, same key identifier).
        let issuer = ca_params()?.self_signed(&key).map_err(|e| unusable(format!("{e}")))?;
        // The stored certificate must carry this key's public key.
        let spki = rcgen::PublicKeyData::der_bytes(&key);
        if !cert_der.as_ref().windows(spki.len()).any(|w| w == spki) {
            return Err(unusable("the certificate does not belong to the key".into()));
        }
        Ok(Arc::new(Ca {
            fingerprint_sha256: fingerprint(cert_der.as_ref()),
            cert_pem,
            key,
            issuer,
            leaves: Mutex::new(HashMap::new()),
        }))
    }

    fn create(dir: &Path) -> Result<Arc<Ca>, String> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| format!("CA key: {e}"))?;
        let issuer = ca_params()?.self_signed(&key).map_err(|e| format!("CA certificate: {e}"))?;
        let cert_pem = issuer.pem();
        make_dir(dir)?;
        write_private(&dir.join(KEY_FILE), key.serialize_pem().as_bytes(), 0o600)?;
        write_private(&dir.join(CERT_FILE), cert_pem.as_bytes(), 0o644)?;
        Ok(Arc::new(Ca {
            fingerprint_sha256: fingerprint(issuer.der().as_ref()),
            cert_pem,
            key,
            issuer,
            leaves: Mutex::new(HashMap::new()),
        }))
    }

    /// The CA certificate as DER.
    pub fn cert_der(&self) -> CertificateDer<'static> {
        self.issuer.der().clone()
    }

    /// The server config for `host` (a name or an IP literal): a leaf valid 24 h for it, signed by the CA,
    /// ALPN `http/1.1`. Cached per host.
    pub fn leaf(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        let key = host.to_ascii_lowercase();
        if let Some((made, cfg)) = self.leaves.lock().unwrap_or_else(|p| p.into_inner()).get(&key) {
            if made.elapsed() < LEAF_REFRESH {
                return Ok(cfg.clone());
            }
        }
        let cfg = self.mint(&key)?;
        self.leaves.lock().unwrap_or_else(|p| p.into_inner()).insert(key, (Instant::now(), cfg.clone()));
        Ok(cfg)
    }

    fn mint(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        let bad = |e: &dyn std::fmt::Display| format!("certificate for {host}: {e}");
        let mut p = CertificateParams::new(vec![host.to_string()]).map_err(|e| bad(&e))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        p.distinguished_name = dn;
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let now = OffsetDateTime::now_utc();
        p.not_before = now - time::Duration::minutes(10);
        p.not_after = now + time::Duration::seconds(LEAF_LIFETIME.as_secs() as i64);
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| bad(&e))?;
        let cert = p.signed_by(&leaf_key, &self.issuer, &self.key).map_err(|e| bad(&e))?;
        let der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let mut cfg = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| bad(&e))?
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], der)
            .map_err(|e| bad(&e))?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(cfg))
    }
}

fn make_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Writes `bytes` to `path` with `mode`, through a temporary file in the same directory, so the file
/// never exists with wider permissions and a reader never sees half of it.
fn write_private(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    use std::io::Write;
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let result = (|| -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(|e| format!("writing {}: {e}", path.display()))
}

/// Writes `{dir}/ca-bundle.pem` (system roots, then the ferret CA) and returns its path.
pub fn ca_bundle(ca: &Ca, dir: &Path) -> Result<PathBuf, String> {
    let mut pem = String::new();
    match SYSTEM_BUNDLES.iter().find_map(|p| std::fs::read_to_string(p).ok().filter(|s| !s.trim().is_empty())) {
        Some(system) => pem.push_str(&system),
        None => {
            for c in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
                pem.push_str(&pem_encode(c.as_ref()));
            }
        }
    }
    if !pem.ends_with('\n') && !pem.is_empty() {
        pem.push('\n');
    }
    pem.push_str(&ca.cert_pem);
    if !pem.ends_with('\n') {
        pem.push('\n');
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let path = dir.join("ca-bundle.pem");
    write_private(&path, pem.as_bytes(), 0o644)?;
    Ok(path)
}

fn pem_encode(der: &[u8]) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
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

/// Reads PEM files of extra roots; each file must hold at least one certificate.
pub fn read_pem_roots(files: &[String]) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut out = Vec::new();
    for f in files {
        let bytes = std::fs::read(f).map_err(|e| format!("upstream root file {f}: {e}"))?;
        let before = out.len();
        for c in CertificateDer::pem_slice_iter(&bytes) {
            out.push(c.map_err(|e| format!("upstream root file {f}: {e}"))?);
        }
        if out.len() == before {
            return Err(format!("upstream root file {f} holds no certificate"));
        }
    }
    Ok(out)
}

/// The client config towards a destination: the Mozilla roots plus `extra`, or, with `verify` false, no
/// check of the certificate at all. ALPN `http/1.1`.
pub fn upstream_client_config(extra: &[CertificateDer<'static>], verify: bool) -> Result<Arc<ClientConfig>, String> {
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS client config: {e}"))?;
    let mut cfg = if verify {
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
        roots.add_parsable_certificates(extra.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider.signature_verification_algorithms)))
            .with_no_client_auth()
    };
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// A server config that has no certificate for anyone: a handshake with it ends in a TLS alert. The proxy
/// uses it to refuse a client whose destination's certificate was not valid.
pub fn refusing_server_config() -> Result<Arc<ServerConfig>, String> {
    #[derive(Debug)]
    struct NoCert;
    impl rustls::server::ResolvesServerCert for NoCert {
        fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
            None
        }
    }
    let builder = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS server config: {e}"))?;
    Ok(Arc::new(builder.with_no_client_auth().with_cert_resolver(Arc::new(NoCert))))
}

/// Accepts any certificate: for hosts the operator listed in `upstream_insecure`.
#[derive(Debug)]
struct NoVerify(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ca_is_created_once_and_reused() {
        let d = tempfile::tempdir().unwrap();
        let a = Ca::load_or_create(d.path()).unwrap();
        let b = Ca::load_or_create(d.path()).unwrap();
        assert_eq!(a.fingerprint_sha256, b.fingerprint_sha256);
        assert_eq!(a.cert_pem, b.cert_pem);
        assert!(a.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert_eq!(a.fingerprint_sha256.len(), 32 * 3 - 1);
        // The reloaded CA signs leaves that the stored certificate verifies.
        b.leaf("example.test").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_key_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        Ca::load_or_create(d.path()).unwrap();
        let mode = |f: &str| std::fs::metadata(d.path().join(f)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode("ferret-ca.key"), 0o600);
        Ca::rotate(d.path()).unwrap();
        assert_eq!(mode("ferret-ca.key"), 0o600);
    }

    #[test]
    fn rotate_makes_a_new_ca_and_a_damaged_one_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        let a = Ca::load_or_create(d.path()).unwrap();
        let b = Ca::rotate(d.path()).unwrap();
        assert_ne!(a.fingerprint_sha256, b.fingerprint_sha256);
        assert_eq!(Ca::load_or_create(d.path()).unwrap().fingerprint_sha256, b.fingerprint_sha256);
        std::fs::write(d.path().join("ferret-ca.key"), "garbage").unwrap();
        let e = Ca::load_or_create(d.path()).unwrap_err();
        assert!(e.contains("ferret ca rotate"), "{e}");
    }

    #[test]
    fn the_bundle_holds_the_system_roots_then_the_ca() {
        let d = tempfile::tempdir().unwrap();
        let ca = Ca::load_or_create(&d.path().join("ca")).unwrap();
        let path = ca_bundle(&ca, d.path()).unwrap();
        let text = std::fs::read_to_string(path).unwrap();
        assert!(text.trim_end().ends_with(ca.cert_pem.trim_end()));
        assert!(text.matches("BEGIN CERTIFICATE").count() > 10, "system roots are in it");
        // Every certificate in it parses.
        let n = CertificateDer::pem_slice_iter(text.as_bytes()).filter(|c| c.is_ok()).count();
        assert_eq!(n, text.matches("BEGIN CERTIFICATE").count());
    }

    #[test]
    fn leaves_are_cached_per_host_and_offer_http_1_1() {
        let d = tempfile::tempdir().unwrap();
        let ca = Ca::load_or_create(d.path()).unwrap();
        let a = ca.leaf("a.test").unwrap();
        assert!(Arc::ptr_eq(&a, &ca.leaf("A.test").unwrap()));
        assert!(!Arc::ptr_eq(&a, &ca.leaf("b.test").unwrap()));
        assert_eq!(a.alpn_protocols, vec![b"http/1.1".to_vec()]);
        ca.leaf("127.0.0.1").unwrap();
        ca.leaf("::1").unwrap();
    }
}
