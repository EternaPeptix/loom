//! Credential profiles in the in-process tools (CONTRACTS-TRAFFIC-TARGETS S5, S8, S9).

use crate::testutil::{env, TestEnv};
use crate::{traffic, web};
use axum::{http::HeaderMap, response::Redirect, routing::get, Router};
use loom_core::creds::{Item, ItemKind, Secrets};
use loom_net::Inject;
use serde_json::json;
use std::sync::Arc;

const COOKIE_VALUE: &str = "cookie-secret-1234";
const TOKEN_VALUE: &str = "Bearer header-secret-5678";

async fn serve(app: Router) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    port
}

/// A server that answers with the cookie and authorization headers it received.
fn echo() -> Router {
    let show = |h: HeaderMap| async move {
        let get = |n: &str| h.get(n).and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();
        format!("cookie=[{}] auth=[{}]", get("cookie"), get("authorization"))
    };
    Router::new().route("/echo", get(show))
}

fn items(host: &str) -> Vec<Item> {
    vec![
        Item { kind: ItemKind::Cookie, name: "sid".into(), value: COOKIE_VALUE.into(), host: host.into() },
        Item { kind: ItemKind::Header, name: "Authorization".into(), value: TOKEN_VALUE.into(), host: host.into() },
    ]
}

fn attach(e: &TestEnv, items: Vec<Item>) {
    let secrets = Secrets::for_items(&items);
    e.ctx.capabilities.creds.set(Arc::new(Inject::new(items))).unwrap();
    e.ctx.capabilities.secrets.set(Arc::new(secrets)).unwrap();
}

fn blob_text(e: &TestEnv, id: &loom_core::BlobRef) -> String {
    String::from_utf8_lossy(&e.ctx.blobs.read_all(&id.id).unwrap()).into_owned()
}

#[test]
fn session_proxy_prefers_the_tool_credential() {
    let mut e = env();
    assert_eq!(web::session_proxy(&e.ctx), None);
    let mut vars = std::collections::BTreeMap::new();
    vars.insert("HTTP_PROXY".to_string(), "http://cmd:pw@127.0.0.1:1".to_string());
    e.ctx.env = Arc::new(vars);
    assert_eq!(web::session_proxy(&e.ctx), Some("http://cmd:pw@127.0.0.1:1"));
    e.ctx.capabilities.tool_proxy.set("http://tool:pw@127.0.0.1:2".to_string()).unwrap();
    assert_eq!(web::session_proxy(&e.ctx), Some("http://tool:pw@127.0.0.1:2"));
}

#[tokio::test]
async fn http_send_injects_for_the_host_only_and_records_the_redacted_copy() {
    let port = serve(echo()).await;
    let e = env();
    attach(&e, items("127.0.0.1"));
    let r = e.call("http_send", json!({"request": {"url": format!("http://127.0.0.1:{port}/echo")}})).await;
    let shown = r.text.clone();
    // The server received the real values, the result shows neither.
    assert!(!shown.contains(COOKIE_VALUE) && !shown.contains("header-secret"), "{shown}");
    assert!(shown.contains("[redacted]"), "{shown}");
    let ex = r.exchanges.first().expect("exchange");
    let request = blob_text(&e, &ex.request);
    assert!(request.contains("sid=[redacted]"), "{request}");
    assert!(
        request.contains("authorization: [redacted]") || request.contains("Authorization: [redacted]"),
        "{request}"
    );
    assert!(!request.contains(COOKIE_VALUE) && !request.contains("header-secret"), "{request}");
    let response = blob_text(&e, ex.response.as_ref().unwrap());
    assert!(!response.contains(COOKIE_VALUE) && !response.contains("header-secret"), "{response}");
    assert!(response.contains("sid=[redacted]"), "echoed values are redacted: {response}");
}

#[tokio::test]
async fn http_send_sends_the_real_values_upstream() {
    // A server that checks the values itself: only the right ones give 200.
    let app = Router::new().route(
        "/check",
        get(|h: HeaderMap| async move {
            let ok = h.get("cookie").is_some_and(|v| v == format!("sid={COOKIE_VALUE}").as_str())
                && h.get("authorization").is_some_and(|v| v == TOKEN_VALUE);
            if ok {
                axum::http::StatusCode::OK
            } else {
                axum::http::StatusCode::BAD_REQUEST
            }
        }),
    );
    let port = serve(app).await;
    let e = env();
    attach(&e, items("127.0.0.1"));
    let r = e.call("http_send", json!({"request": {"url": format!("http://127.0.0.1:{port}/check")}})).await;
    assert_eq!(r.exchanges.first().and_then(|x| x.status), Some(200), "{}", r.text);
}

#[tokio::test]
async fn http_send_attaches_nothing_to_another_host() {
    let port = serve(echo()).await;
    let e = env();
    attach(&e, items("127.0.0.1"));
    let r = e.call("http_send", json!({"request": {"url": format!("http://localhost:{port}/echo")}})).await;
    let shown = r.text.clone();
    assert!(shown.contains("cookie=[-] auth=[-]"), "{shown}");
    let request = blob_text(&e, &r.exchanges[0].request);
    assert!(!request.contains("redacted"), "{request}");
}

#[tokio::test]
async fn the_request_wins_over_an_item() {
    let port = serve(echo()).await;
    let e = env();
    attach(&e, items("127.0.0.1"));
    let r = e
        .call(
            "http_send",
            json!({"request": {"url": format!("http://127.0.0.1:{port}/echo"),
                   "headers": {"Cookie": "sid=mine-own-value", "authorization": "Bearer mine"}}}),
        )
        .await;
    let shown = r.text.clone();
    assert!(shown.contains("sid=mine-own-value") && shown.contains("Bearer mine"), "{shown}");
    assert!(!shown.contains("[redacted]"), "{shown}");
    let request = blob_text(&e, &r.exchanges[0].request);
    assert!(request.contains("sid=mine-own-value") && !request.contains("redacted"), "{request}");
}

#[tokio::test]
async fn a_jar_cookie_is_not_overridden_and_the_jar_is_still_sent() {
    let app = echo()
        .route("/login", get(|| async { ([("set-cookie", "sid=from-jar-0000; Path=/"), ("x-a", "1")], "in") }))
        .route("/other", get(|| async { ([("set-cookie", "extra=jar-extra; Path=/")], "in") }));
    let port = serve(app).await;
    let e = env();
    let base = format!("http://127.0.0.1:{port}");
    // The jar learns `sid` before the profile is attached.
    e.call("http_send", json!({"request": {"url": format!("{base}/login")}})).await;
    attach(&e, items("127.0.0.1"));
    let r = e.call("http_send", json!({"request": {"url": format!("{base}/echo")}})).await;
    let shown = r.text.clone();
    assert!(shown.contains("sid=from-jar-0000"), "the jar's cookie is sent: {shown}");
    assert!(!shown.contains("[redacted]") || !shown.contains("sid=[redacted]"), "{shown}");
    assert!(shown.contains("auth=[[redacted]]"), "the header item is still attached: {shown}");
    // With another jar cookie present, the item's cookie joins the jar's cookies instead of replacing them.
    let items2 = vec![Item {
        kind: ItemKind::Cookie,
        name: "profile".into(),
        value: "profile-cookie-9999".into(),
        host: "127.0.0.1".into(),
    }];
    let e2 = env();
    e2.call("http_send", json!({"request": {"url": format!("{base}/other")}})).await;
    attach(&e2, items2);
    let r = e2.call("http_send", json!({"request": {"url": format!("{base}/echo")}})).await;
    let request = blob_text(&e2, &r.exchanges[0].request);
    assert!(request.contains("extra=jar-extra; profile=[redacted]"), "{request}");
    let shown = r.text.clone();
    assert!(shown.contains("extra=jar-extra") && shown.contains("profile=[redacted]"), "{shown}");
}

#[tokio::test]
async fn web_fetch_injects_and_a_redirect_to_another_host_carries_nothing() {
    let target = serve(echo()).await;
    let to = format!("http://localhost:{target}/echo");
    let hop = Router::new()
        .route("/go", get(move || async move { Redirect::temporary(&to) }))
        .route("/here", get(|| async { Redirect::temporary("/echo") }))
        .merge(echo());
    let port = serve(hop).await;
    let e = env();
    attach(&e, items("127.0.0.1"));
    // Same host: injected, and the recorded request is redacted.
    let r = e.call("web_fetch", json!({"url": format!("http://127.0.0.1:{port}/echo"), "raw": true})).await;
    assert!(r.text.contains("sid=[redacted]"), "{}", r.text);
    assert!(!r.text.contains(COOKIE_VALUE) && !r.text.contains("header-secret"), "{}", r.text);
    let request = blob_text(&e, &r.exchanges[0].request);
    assert!(request.contains("sid=[redacted]") && !request.contains(COOKIE_VALUE), "{request}");
    // A redirect inside the host is decided again on that host and carries it.
    let r = e.call("web_fetch", json!({"url": format!("http://127.0.0.1:{port}/here"), "raw": true})).await;
    assert!(r.text.contains("sid=[redacted]"), "{}", r.text);
    // A redirect to another host: the first hop carries the items, the second nothing.
    let r = e.call("web_fetch", json!({"url": format!("http://127.0.0.1:{port}/go"), "raw": true})).await;
    assert!(r.text.contains("cookie=[-] auth=[-]"), "{}", r.text);
    assert_eq!(r.exchanges.len(), 2, "{}", r.text);
    let first = blob_text(&e, &r.exchanges[0].request);
    let second = blob_text(&e, &r.exchanges[1].request);
    assert!(first.contains("sid=[redacted]"), "{first}");
    assert!(!second.contains("redacted") && !second.contains("sid="), "{second}");
}

#[tokio::test]
async fn nothing_is_attached_without_a_profile() {
    let port = serve(echo()).await;
    let e = env();
    let u = format!("http://127.0.0.1:{port}/echo");
    for (tool, args) in [("http_send", json!({"request": {"url": u}})), ("web_fetch", json!({"url": u, "raw": true}))] {
        let r = e.call(tool, args).await;
        let text = r.text.clone();
        assert!(text.contains("cookie=[-] auth=[-]"), "{tool}: {text}");
    }
}

#[test]
fn traffic_record_redacts_both_messages() {
    let e = env();
    attach(&e, items("127.0.0.1"));
    let url = url::Url::parse("http://127.0.0.1:9/x").unwrap();
    let request = traffic::request_message("GET", &url, &[("Cookie".into(), format!("a={COOKIE_VALUE}"))], b"");
    let response = traffic::response_message(200, &[], format!("echo {TOKEN_VALUE}").as_bytes());
    let made = traffic::Made {
        tool: "t",
        url: &url,
        method: "GET",
        request: &request,
        response: Some(&response),
        status: Some(200),
        error: Some(format!("failed with {COOKIE_VALUE}")),
        response_cut: false,
        started: std::time::Instant::now(),
    };
    let x = traffic::record(&e.ctx, &made).unwrap();
    let (req, resp) = (blob_text(&e, &x.request), blob_text(&e, x.response.as_ref().unwrap()));
    assert!(req.contains("a=[redacted]") && !req.contains(COOKIE_VALUE), "{req}");
    assert!(resp.contains("echo [redacted]") && !resp.contains("header-secret"), "{resp}");
    assert!(!x.error.unwrap().contains(COOKIE_VALUE));
}

#[test]
fn traffic_record_keeps_everything_without_secrets() {
    let e = env();
    let url = url::Url::parse("http://127.0.0.1:9/x").unwrap();
    let request = traffic::request_message("GET", &url, &[("Cookie".into(), format!("a={COOKIE_VALUE}"))], b"");
    let made = traffic::Made {
        tool: "t",
        url: &url,
        method: "GET",
        request: &request,
        response: None,
        status: None,
        error: None,
        response_cut: false,
        started: std::time::Instant::now(),
    };
    let x = traffic::record(&e.ctx, &made).unwrap();
    assert_eq!(blob_text(&e, &x.request).as_bytes(), request.as_slice());
    assert_eq!(x.request_bytes, request.len() as u64);
}

#[tokio::test]
async fn finalize_redacts_text_and_the_stored_output() {
    let e = env();
    attach(&e, items("127.0.0.1"));
    std::fs::write(e.ctx.workspace.join("notes.txt"), format!("line one\nkey={COOKIE_VALUE}\nend\n")).unwrap();
    // A bash-style output (bytes the tool produced).
    let r = e.call("bash", json!({"command": format!("echo token {TOKEN_VALUE}; echo {COOKIE_VALUE}")})).await;
    assert!(!r.text.contains("header-secret") && !r.text.contains(COOKIE_VALUE), "{}", r.text);
    assert!(r.text.contains("[redacted]"), "{}", r.text);
    let stored = r.text.clone();
    assert!(!stored.contains("header-secret") && !stored.contains(COOKIE_VALUE), "{stored}");
    assert!(stored.contains("[redacted]"), "{stored}");
    // A view of a file blob: the text and the blob the view points at.
    let r = e.call("read", json!({"path": "notes.txt"})).await;
    assert!(!r.text.contains(COOKIE_VALUE) && r.text.contains("key=[redacted]"), "{}", r.text);
    let of = r.meta.get(loom_core::event::META_OF_BLOB).and_then(|v| v.as_str()).expect("view meta");
    let id = loom_core::BlobId::from(of);
    let held = String::from_utf8_lossy(&e.ctx.blobs.read_all(&id).unwrap()).into_owned();
    assert!(!held.contains(COOKIE_VALUE), "{held}");
}

#[tokio::test]
async fn finalize_changes_nothing_without_secrets() {
    let e = env();
    let r = e.call("bash", json!({"command": format!("echo {COOKIE_VALUE}")})).await;
    assert!(r.text.contains(COOKIE_VALUE), "{}", r.text);
    assert!(r.text.clone().contains(COOKIE_VALUE));
}
