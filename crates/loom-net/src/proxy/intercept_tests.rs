//! Tests of captured exchanges and interception (CONTRACTS-TRAFFIC-TARGETS C, I), on loopback.

use super::intercept::listed;
use super::*;
use crate::capture::{CaptureGrant, Captured, Transport};
use crate::tls::Ca;
use loom_core::config::{NetworkCfg, NetworkMode};
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const T: Duration = Duration::from_secs(10);
type CapRx = UnboundedReceiver<(SessionId, Captured)>;
type Seen = Arc<Mutex<Vec<NetDecision>>>;

fn lab() -> Policy {
    let cfg =
        NetworkCfg { mode: NetworkMode::Open, allow_private: vec!["127.0.0.1".to_string()], ..NetworkCfg::default() };
    Policy::new(&cfg).unwrap()
}

struct Env {
    proxy: Proxy,
    grant: SessionGrant,
    ca: Arc<Ca>,
    rx: CapRx,
    seen: Seen,
    _dir: tempfile::TempDir,
}

async fn env(grant: CaptureGrant) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::load_or_create(dir.path()).unwrap();
    let (dtx, _drx) = unbounded_channel();
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let audit: AuditFn = Arc::new(move |_s, d| {
        lock(&log).push(d.clone());
        Ok(())
    });
    let proxy = Proxy::start_with(0, dtx, Some(audit), Limits::default()).await.unwrap();
    let (tx, rx) = unbounded_channel();
    let sid = SessionId::from("s-capture");
    let g = proxy.grant_with_capture(&sid, lab(), grant, tx, Some(ca.clone())).unwrap();
    Env { proxy, grant: g, ca, rx, seen, _dir: dir }
}

fn cg(max_bytes: u64) -> CaptureGrant {
    CaptureGrant { max_bytes, ..CaptureGrant::default() }
}

fn intercepting() -> CaptureGrant {
    CaptureGrant {
        max_bytes: 1024,
        intercept: true,
        upstream_insecure: vec!["127.0.0.1".into()],
        ..CaptureGrant::default()
    }
}

fn auth(g: &SessionGrant) -> String {
    let c = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", g.user, g.password));
    format!("Proxy-Authorization: Basic {c}\r\n")
}

async fn next(rx: &mut CapRx) -> Captured {
    timeout(T, rx.recv()).await.unwrap().unwrap().1
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).to_string()
}

fn content_length(head: &str) -> usize {
    head.lines()
        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
        .unwrap_or(0)
}

/// A plain HTTP server that answers every request on every connection with `reply`.
async fn plain_server(reply: &'static str) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let _ = http_requests(&mut s, |_| reply.to_string()).await;
            });
        }
    });
    port
}

/// Reads requests (head plus Content-Length body) from `s` and answers each with `f(first line)`.
async fn http_requests<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    f: impl Fn(&str) -> String,
) -> std::io::Result<()> {
    let mut got: Vec<u8> = Vec::new();
    let mut b = [0u8; 4096];
    loop {
        let end = loop {
            if let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            let n = s.read(&mut b).await?;
            if n == 0 {
                return Ok(());
            }
            got.extend_from_slice(&b[..n]);
        };
        let head = text(&got[..end]);
        let want = content_length(&head);
        while got.len() < end + want {
            let n = s.read(&mut b).await?;
            if n == 0 {
                return Ok(());
            }
            got.extend_from_slice(&b[..n]);
        }
        got.drain(..end + want);
        let reply = f(head.lines().next().unwrap_or(""));
        s.write_all(reply.as_bytes()).await?;
        s.flush().await?;
    }
}

fn ok_reply(first_line: &str) -> String {
    let body = format!("you asked: {first_line}");
    format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}", body.len())
}

/// A TLS server with a fresh self-signed certificate for 127.0.0.1; `serve` runs on each connection.
async fn tls_server<F, Fut>(serve: F) -> u16
where
    F: Fn(tokio_rustls::server::TlsStream<TcpStream>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der());
    let cfg = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![ck.cert.der().clone()], key.into())
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let serve = Arc::new(serve);
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let (acceptor, serve) = (acceptor.clone(), serve.clone());
            tokio::spawn(async move {
                if let Ok(t) = acceptor.accept(s).await {
                    serve(t).await;
                }
            });
        }
    });
    port
}

async fn https_server() -> u16 {
    tls_server(|mut s| async move {
        let _ = http_requests(&mut s, ok_reply).await;
    })
    .await
}

fn session_port(e: &Env) -> u16 {
    e.proxy.session_port(&SessionId::from("s-capture")).unwrap()
}

/// `CONNECT` through the proxy; returns the connection after the `200`.
async fn connect(e: &Env, port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", session_port(e))).await.unwrap();
    let req = format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{}\r\n", auth(&e.grant));
    s.write_all(req.as_bytes()).await.unwrap();
    let mut got = Vec::new();
    let mut b = [0u8; 1];
    while !got.ends_with(b"\r\n\r\n") {
        timeout(T, s.read_exact(&mut b)).await.unwrap().unwrap();
        got.push(b[0]);
    }
    assert!(text(&got).starts_with("HTTP/1.1 200"), "{}", text(&got));
    s
}

/// `CONNECT`, then TLS to the tunnel trusting the loom CA (or nothing).
async fn tunnel_tls(
    e: &Env,
    port: u16,
    trust_loom_ca: bool,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let s = connect(e, port).await;
    let mut roots = RootCertStore::empty();
    if trust_loom_ca {
        roots.add(e.ca.cert_der()).unwrap();
    }
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from("127.0.0.1".to_string()).unwrap();
    TlsConnector::from(Arc::new(cfg)).connect(name, s).await
}

/// Writes `req` and reads one response with a Content-Length body.
async fn roundtrip<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, req: &str) -> String {
    s.write_all(req.as_bytes()).await.unwrap();
    let mut got = Vec::new();
    let mut b = [0u8; 1];
    while !got.ends_with(b"\r\n\r\n") {
        timeout(T, s.read_exact(&mut b)).await.unwrap().unwrap();
        got.push(b[0]);
    }
    let head = text(&got);
    let mut body = vec![0u8; content_length(&head)];
    timeout(T, s.read_exact(&mut body)).await.unwrap().unwrap();
    head + &text(&body)
}

async fn plain_via_proxy(e: &Env, req: String) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", session_port(e))).await.unwrap();
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = timeout(T, s.read_to_end(&mut out)).await;
    text(&out)
}

#[tokio::test]
async fn plain_http_is_captured_with_both_bodies_and_without_proxy_credentials() {
    let mut e = env(cg(1024)).await;
    let port = plain_server("HTTP/1.1 201 Created\r\nContent-Length: 7\r\n\r\ncreated").await;
    let req = format!(
        "POST http://127.0.0.1:{port}/items?x=1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{}Content-Length: 5\r\n\r\nhello",
        auth(&e.grant)
    );
    let resp = plain_via_proxy(&e, req).await;
    assert!(resp.starts_with("HTTP/1.1 201 Created"), "{resp}");
    let c = next(&mut e.rx).await;
    assert_eq!(c.transport, Transport::Plain);
    assert_eq!((c.method.as_str(), c.host.as_str(), c.port), ("POST", "127.0.0.1", port));
    assert_eq!(c.target, "/items?x=1");
    assert_eq!(c.status, Some(201));
    assert_eq!(c.error, None);
    assert!(!c.upstream_unverified);
    let request = text(&c.request);
    assert!(request.starts_with("POST /items?x=1 HTTP/1.1\r\n"), "{request}");
    assert!(request.ends_with("\r\n\r\nhello"), "{request}");
    assert!(!request.to_ascii_lowercase().contains("proxy-authorization"), "{request}");
    assert!(!request.contains(&e.grant.password));
    let response = text(c.response.as_ref().unwrap());
    assert!(response.starts_with("HTTP/1.1 201 Created"), "{response}");
    assert!(response.ends_with("\r\n\r\ncreated"), "{response}");
    assert_eq!(c.request_bytes, c.request.len() as u64);
    assert_eq!(c.response_bytes, c.response.as_ref().unwrap().len() as u64);
    assert!(!c.truncated);
    assert!(e.rx.try_recv().is_err(), "one capture per request");
}

#[tokio::test]
async fn a_body_over_the_cap_is_cut_and_its_true_size_kept() {
    let mut e = env(cg(4)).await;
    let port = plain_server("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789").await;
    let req = format!(
        "POST http://127.0.0.1:{port}/up HTTP/1.1\r\nHost: x\r\n{}Content-Length: 12\r\n\r\nabcdefghijkl",
        auth(&e.grant)
    );
    plain_via_proxy(&e, req).await;
    let c = next(&mut e.rx).await;
    assert!(c.truncated);
    assert!(text(&c.request).ends_with("\r\n\r\nabcd"), "{}", text(&c.request));
    assert!(text(c.response.as_ref().unwrap()).ends_with("\r\n\r\n0123"));
    let head_len = c.request.len() as u64 - 4;
    assert_eq!(c.request_bytes, head_len + 12);
    let resp_head = c.response.as_ref().unwrap().len() as u64 - 4;
    assert_eq!(c.response_bytes, resp_head + 10);
}

#[tokio::test]
async fn a_session_granted_without_capture_is_relayed_as_before() {
    let (dtx, _drx) = unbounded_channel();
    let proxy = Proxy::start(0, dtx).await.unwrap();
    let g = proxy.grant(&SessionId::from("s-plain"), lab()).unwrap();
    let port = plain_server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
    let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
    s.write_all(format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: x\r\n{}\r\n", auth(&g)).as_bytes())
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = timeout(T, s.read_to_end(&mut out)).await;
    assert_eq!(text(&out), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
}

#[tokio::test]
async fn with_interception_off_https_is_an_opaque_tunnel_and_nothing_is_captured() {
    let mut e = env(cg(1024)).await;
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let mut s = connect(&e, port).await;
    s.write_all(b"\x16not really tls").await.unwrap();
    let mut back = [0u8; 15];
    timeout(T, s.read_exact(&mut back)).await.unwrap().unwrap();
    assert_eq!(&back, b"\x16not really tls");
    drop(s);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(e.rx.try_recv().is_err());
}

#[tokio::test]
async fn intercepted_https_is_captured_per_request_on_one_keep_alive_connection() {
    let mut e = env(intercepting()).await;
    let port = https_server().await;
    let mut s = tunnel_tls(&e, port, true).await.expect("the client trusts the loom CA");
    let first = "GET /one?a=b HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Test: 1\r\n\r\n";
    let r1 = roundtrip(&mut s, first).await;
    assert!(r1.ends_with("you asked: GET /one?a=b HTTP/1.1"), "{r1}");
    let second = "POST /two HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 3\r\n\r\nabc";
    let r2 = roundtrip(&mut s, second).await;
    assert!(r2.ends_with("you asked: POST /two HTTP/1.1"), "{r2}");
    let c1 = next(&mut e.rx).await;
    let c2 = next(&mut e.rx).await;
    assert_eq!(c1.transport, Transport::Intercepted);
    assert_eq!((c1.method.as_str(), c1.host.as_str(), c1.port), ("GET", "127.0.0.1", port));
    assert_eq!(c1.target, "/one?a=b");
    assert_eq!(c1.request, first.as_bytes());
    assert_eq!(c1.status, Some(200));
    assert_eq!(text(c1.response.as_ref().unwrap()), r1);
    assert_eq!(c1.request_bytes, first.len() as u64);
    assert!(c1.upstream_unverified && c1.error.is_none() && !c1.truncated);
    assert_eq!((c2.method.as_str(), c2.target.as_str()), ("POST", "/two"));
    assert_eq!(c2.request, second.as_bytes());
    assert_eq!(text(c2.response.as_ref().unwrap()), r2);
    drop(s);
    let connects = lock(&e.seen).iter().filter(|d| d.method == "CONNECT").count();
    assert_eq!(connects, 1, "the CONNECT is decided and recorded once");
    assert!(e.rx.try_recv().is_err());
}

#[tokio::test]
async fn a_client_that_does_not_trust_the_loom_ca_is_recorded_as_refusing_it() {
    let e = env(intercepting()).await;
    let port = https_server().await;
    assert!(tunnel_tls(&e, port, false).await.is_err());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let seen = lock(&e.seen).clone();
    assert!(seen.iter().any(|d| d.rule == "client refused the interception certificate for 127.0.0.1"), "{seen:?}");
}

#[tokio::test]
async fn a_passthrough_host_is_tunneled_untouched() {
    let mut e = env(CaptureGrant { passthrough: vec!["127.0.0.1".into()], ..intercepting() }).await;
    let port = https_server().await;
    // The server's own self-signed certificate answers, not one of the loom CA: a client trusting only
    // the loom CA cannot verify it.
    assert!(tunnel_tls(&e, port, true).await.is_err());
    assert!(e.rx.try_recv().is_err());
}

#[tokio::test]
async fn an_invalid_upstream_certificate_is_refused_and_captured_with_the_error() {
    let mut e = env(CaptureGrant { upstream_insecure: Vec::new(), ..intercepting() }).await;
    let port = https_server().await;
    assert!(tunnel_tls(&e, port, true).await.is_err());
    let c = next(&mut e.rx).await;
    assert_eq!((c.method.as_str(), c.transport), ("CONNECT", Transport::Intercepted));
    assert_eq!(c.target, format!("127.0.0.1:{port}"));
    let err = c.error.unwrap();
    assert!(err.starts_with("upstream certificate not valid for 127.0.0.1: "), "{err}");
    assert_eq!(c.status, None);
    let seen = lock(&e.seen).clone();
    assert!(seen.iter().any(|d| !d.allowed && d.rule == err), "{seen:?}");
}

#[tokio::test]
async fn a_tls_stream_that_is_not_http_is_relayed_and_recorded_as_tls() {
    let mut e = env(intercepting()).await;
    let port = tls_server(|mut s| async move {
        let (mut r, mut w) = tokio::io::split(&mut s);
        let _ = tokio::io::copy(&mut r, &mut w).await;
    })
    .await;
    let mut s = tunnel_tls(&e, port, true).await.unwrap();
    s.write_all(b"\x01\x02binary hello\n").await.unwrap();
    let mut back = [0u8; 15];
    timeout(T, s.read_exact(&mut back)).await.unwrap().unwrap();
    assert_eq!(&back, b"\x01\x02binary hello\n");
    let _ = s.shutdown().await;
    drop(s);
    let c = next(&mut e.rx).await;
    assert_eq!(c.method, "TLS");
    assert_eq!((c.status, c.request_bytes, c.response_bytes), (None, 15, 15));
    assert_eq!(c.error.as_deref(), Some("not HTTP/1.1: 15 bytes out, 15 bytes in, not stored"));
    assert!(c.upstream_unverified && c.response.is_none());
}

#[test]
fn host_patterns() {
    let l = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert!(listed(&l(&["example.com"]), "Example.com", 443));
    assert!(!listed(&l(&["example.com"]), "www.example.com", 443));
    assert!(listed(&l(&["*.example.com"]), "a.b.example.com", 443));
    assert!(!listed(&l(&["*.example.com"]), "example.com", 443));
    assert!(listed(&l(&["*"]), "anything", 1));
    assert!(listed(&l(&["10.0.0.1:8443"]), "10.0.0.1", 8443));
    assert!(!listed(&l(&["10.0.0.1:8443"]), "10.0.0.1", 443));
    assert!(!listed(&[], "x", 1));
}
