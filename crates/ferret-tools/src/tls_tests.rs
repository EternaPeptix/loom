//! In-process TLS to the target (CONTRACTS-TRAFFIC-TARGETS S12, S13): a self-signed https server, the
//! session's `upstream_insecure` list, and the error text of a certificate failure.

use crate::testutil::{env, TestEnv};
use crate::web;
use ferret_core::creds::{Item, ItemKind, Secrets};
use ferret_net::Inject;
use rustls::pki_types::PrivatePkcs8KeyDer;
use serde_json::json;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const COOKIE_VALUE: &str = "tls-cookie-secret-4321";

/// A self-signed https server for `127.0.0.1` and `localhost`. `/go?to=URL` redirects to `URL`; every other
/// path answers with the `Cookie` header it received.
async fn https_server() -> u16 {
    let names = vec!["127.0.0.1".to_string(), "localhost".to_string()];
    let ck = rcgen::generate_simple_self_signed(names).unwrap();
    let key = PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der());
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![ck.cert.der().clone()], key.into())
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else { return };
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&head).into_owned();
                let line = text.lines().next().unwrap_or("");
                let reply = if let Some(to) = line.split(' ').nth(1).and_then(|p| p.strip_prefix("/go?to=")) {
                    format!("HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                } else {
                    let cookie = text
                        .lines()
                        .find_map(|l| l.to_ascii_lowercase().starts_with("cookie:").then(|| l[7..].trim().to_string()))
                        .unwrap_or_else(|| "-".into());
                    let body = format!("cookie=[{cookie}]");
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                };
                let _ = tls.write_all(reply.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}

async fn http_server() -> u16 {
    let app = axum::Router::new().route("/ok", axum::routing::get(|| async { "plain" }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    port
}

fn list(e: &TestEnv, hosts: &[&str]) {
    e.ctx.capabilities.upstream_insecure.set(hosts.iter().map(|h| h.to_string()).collect()).unwrap();
}

fn scope(e: &TestEnv, hosts: &[&str]) {
    let hosts: Vec<String> = hosts.iter().map(|h| h.to_string()).collect();
    e.ctx.capabilities.target_scope.set(ferret_core::target::Scope::parse(&hosts, &[]).unwrap()).unwrap();
}

fn profile(e: &TestEnv) {
    let items =
        vec![Item { kind: ItemKind::Cookie, name: "sid".into(), value: COOKIE_VALUE.into(), host: "127.0.0.1".into() }];
    let secrets = Secrets::for_items(&items);
    e.ctx.capabilities.creds.set(Arc::new(Inject::new(items))).unwrap();
    e.ctx.capabilities.secrets.set(Arc::new(secrets)).unwrap();
}

const SENTENCE: &str = "The server's certificate did not verify; the operator can list 127.0.0.1 in the target's upstream_insecure if it is a lab host with a self-signed certificate.";

#[tokio::test]
async fn http_send_reaches_a_listed_self_signed_host_unverified_and_still_injects() {
    let port = https_server().await;
    let e = env();
    list(&e, &["127.0.0.1"]);
    profile(&e);
    let r = e.call("http_send", json!({"request": {"url": format!("https://127.0.0.1:{port}/echo")}})).await;
    assert!(r.text.contains("200"), "{}", r.text);
    // The server got the real cookie; nothing shown holds it.
    assert!(!r.text.contains(COOKIE_VALUE), "{}", r.text);
    assert!(r.text.contains("sid=[redacted]"), "{}", r.text);
    let ex = r.exchanges.first().expect("exchange");
    assert!(ex.upstream_unverified);
    assert_eq!(ex.port, port);
}

#[tokio::test]
async fn a_host_port_entry_only_matches_its_port() {
    let port = https_server().await;
    let e = env();
    list(&e, &[&format!("127.0.0.1:{}", port.wrapping_add(1))]);
    let r = e.call("http_send", json!({"request": {"url": format!("https://127.0.0.1:{port}/echo")}})).await;
    assert!(r.text.contains("HTTP exchange failed"), "{}", r.text);
}

#[tokio::test]
async fn http_send_to_an_unlisted_self_signed_host_names_the_certificate_cause() {
    let port = https_server().await;
    // No target: the cause is named, the operator sentence is not (the host is not known to be in scope).
    let e = env();
    let url = format!("https://127.0.0.1:{port}/echo");
    let r = e.call("http_send", json!({"request": {"url": url}})).await;
    assert!(r.text.contains("HTTP exchange failed"), "{}", r.text);
    assert!(r.text.contains("error sending request for url"), "{}", r.text);
    assert!(r.text.to_lowercase().contains("certificate"), "the cause is in the text: {}", r.text);
    assert!(!r.text.contains("upstream_insecure"), "{}", r.text);
    let ex = r.exchanges.first().expect("a failed exchange is recorded");
    assert!(!ex.upstream_unverified);
    assert!(ex.error.as_deref().unwrap_or_default().to_lowercase().contains("certificate"));

    // A target whose scope holds the host and whose list does not: the sentence follows.
    let e = env();
    list(&e, &["other.test"]);
    scope(&e, &["127.0.0.1"]);
    let r = e.call("http_send", json!({"request": {"url": format!("https://127.0.0.1:{port}/echo")}})).await;
    assert!(r.text.to_lowercase().contains("certificate"), "{}", r.text);
    assert!(r.text.contains(SENTENCE), "{}", r.text);

    // A host outside the scope gets no suggestion.
    let e = env();
    list(&e, &[]);
    scope(&e, &["*.acme.test"]);
    let r = e.call("http_send", json!({"request": {"url": format!("https://127.0.0.1:{port}/echo")}})).await;
    assert!(!r.text.contains("upstream_insecure"), "{}", r.text);
}

#[tokio::test]
async fn web_fetch_reaches_a_listed_host_and_verifies_the_unlisted_hop_after_it() {
    let port = https_server().await;
    let e = env();
    list(&e, &["127.0.0.1"]);
    scope(&e, &["127.0.0.1", "localhost"]);
    profile(&e);
    let direct = e.call("web_fetch", json!({"url": format!("https://127.0.0.1:{port}/echo"), "raw": true})).await;
    assert!(direct.text.contains("sid=[redacted]"), "{}", direct.text);
    assert!(direct.exchanges.iter().all(|x| x.upstream_unverified), "{:?}", direct.exchanges);

    let to = format!("https://localhost:{port}/echo");
    let r = e.call("web_fetch", json!({"url": format!("https://127.0.0.1:{port}/go?to={to}"), "raw": true})).await;
    assert!(r.text.to_lowercase().contains("certificate"), "{}", r.text);
    assert!(r.text.contains("did not verify") && r.text.contains("list localhost"), "{}", r.text);
    assert_eq!(r.exchanges.len(), 2, "{}", r.text);
    assert!(r.exchanges[0].upstream_unverified, "the listed first hop was sent unverified");
    assert!(!r.exchanges[1].upstream_unverified, "the unlisted second hop was verified");
    assert!(r.exchanges[1].error.is_some());
}

#[tokio::test]
async fn a_listed_plain_http_request_is_unaffected() {
    let port = http_server().await;
    let e = env();
    list(&e, &["127.0.0.1"]);
    let r = e.call("http_send", json!({"request": {"url": format!("http://127.0.0.1:{port}/ok")}})).await;
    assert!(r.text.contains("plain"), "{}", r.text);
    assert!(!r.exchanges[0].upstream_unverified);
    let r = e.call("web_fetch", json!({"url": format!("http://127.0.0.1:{port}/ok")})).await;
    assert!(!r.exchanges[0].upstream_unverified);
}

#[tokio::test]
async fn the_decision_is_per_url_and_only_for_https() {
    let e = env();
    let url = |s: &str| url::Url::parse(s).unwrap();
    assert!(!web::insecure_for(&e.ctx, &url("https://127.0.0.1:1/")), "unset list verifies everything");
    list(&e, &["127.0.0.1", "lab.test:8443"]);
    assert!(web::insecure_for(&e.ctx, &url("https://127.0.0.1:9999/")));
    assert!(!web::insecure_for(&e.ctx, &url("http://127.0.0.1:9999/")));
    assert!(web::insecure_for(&e.ctx, &url("https://lab.test:8443/")));
    assert!(!web::insecure_for(&e.ctx, &url("https://lab.test/")));
    assert!(!web::insecure_for(&e.ctx, &url("https://other.test/")));
}

/// The clients of `cve`, `dep_scan`, MCP and the reference path are built without `upstream_insecure`
/// (`web::build_client`, `cve::build_client`, `web::reference_client`); `web::build_client` is the one
/// the first two share in shape, and it verifies even for a listed host. (A `cve` lookup would need the
/// network, so the builder is checked directly.)
#[tokio::test]
async fn the_verifying_builder_ignores_the_list() {
    let port = https_server().await;
    let e = env();
    list(&e, &["127.0.0.1"]);
    let client = web::build_client(&e.ctx).unwrap();
    let err = client.get(format!("https://127.0.0.1:{port}/echo")).send().await.unwrap_err();
    assert!(web::error_chain(&err).to_lowercase().contains("certificate"), "{}", web::error_chain(&err));
    let client = web::build_client_for(&e.ctx, true).unwrap();
    assert!(client.get(format!("https://127.0.0.1:{port}/echo")).send().await.is_ok());
}

#[test]
fn error_chain_joins_causes_and_skips_repeats() {
    #[derive(Debug)]
    struct E(&'static str, Option<Box<E>>);
    impl std::fmt::Display for E {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for E {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.1.as_deref().map(|e| e as &(dyn std::error::Error + 'static))
        }
    }
    let e = E("top (https://h/x)", Some(Box::new(E("client error", Some(Box::new(E("top", None)))))));
    assert_eq!(web::error_chain(&e), "top (https://h/x): client error");
}
