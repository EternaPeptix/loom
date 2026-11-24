#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use loom_core::config::{McpServerCfg, SandboxCfg, SandboxMode, ToolsCfg};
use loom_core::event::{McpListing, McpToolDef, ToolStatus};
use serde_json::{json, Value};

use super::*;
use crate::testutil::{env, env_with, TestEnv};

const SECRET: &str = "s3cr3t-value-xyz";

const FAKE: &str = r#"
PROTO="${PROTO:-2025-06-18}"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  m=$(printf '%s' "$line" | sed -n 's/.*"method":"\([^"]*\)".*/\1/p')
  case "$m" in
    initialize)
      if [ -n "$LEAK" ]; then echo "boot failed with $SECRET" >&2; fi
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"%s","capabilities":{"tools":{}},"serverInfo":{"name":"fake","version":"1.2"}}}\n' "$id" "$PROTO";;
    notifications/*) echo "note $m $line" >&2;;
    tools/list)
      case "$line" in
        *'"cursor":"p2"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"b.tool","description":"second","inputSchema":{"type":"object","properties":{}},"annotations":{"readOnlyHint":true}}]}}\n' "$id";;
        *) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"echo","description":"first","inputSchema":{"type":"object","properties":{"text":{"type":"string"}}}}],"nextCursor":"p2"}}\n' "$id";;
      esac;;
    tools/call)
      name=$(printf '%s' "$line" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p')
      ok() { printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"%s"}]}}\n' "$id" "$1"; }
      case "$name" in
        echo) ok hello;;
        fail) printf '{"jsonrpc":"2.0","id":%s,"result":{"isError":true,"content":[{"type":"text","text":"it broke"}]}}\n' "$id";;
        rpcerr) printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32602,"message":"bad args","data":{"field":"x"}}}\n' "$id";;
        slow) ;;
        crash) exit 3;;
        noisy) i=0; while [ $i -lt 250 ]; do i=$((i+1)); echo "line $i" >&2; done; ok done;;
        ping) printf '{"jsonrpc":"2.0","id":900,"method":"ping"}\n{"jsonrpc":"2.0","id":901,"method":"roots/list"}\n'; ok pinged;;
        leak) printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"key=%s"}]}}\n' "$id" "$SECRET"; echo "secret=$SECRET" >&2;;
        probe)
          if (echo x > "$OUT/no.txt") 2>/dev/null; then w=wrote; else w=denied; fi
          if /usr/bin/nc -z -w 2 127.0.0.1 "$PORT" >/dev/null 2>&1; then n=open; else n=blocked; fi
          ok "write=$w net=$n";;
        *) ok "unknown $name";;
      esac;;
    "") echo "reply $line" >&2;;
  esac
done
"#;

fn cfg_for(t: &TestEnv, env_vars: &[(&str, &str)], timeout_s: u64) -> McpServerCfg {
    let script = t.ctx.workspace.join("fake.sh");
    std::fs::write(&script, FAKE).expect("write script");
    McpServerCfg {
        command: Some(vec!["/bin/sh".into(), script.to_string_lossy().into_owned()]),
        env: env_vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        timeout_s,
        ..McpServerCfg::default()
    }
}

fn handle(t: &TestEnv, env_vars: &[(&str, &str)], timeout_s: u64, idle: Duration) -> Arc<McpHandle> {
    let server = McpServer::resolve("fake", &cfg_for(t, env_vars, timeout_s)).expect("resolve");
    McpHandle::new(server, idle)
}

async fn wait_for(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..80 {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    f()
}

fn text_of(out: &ToolOutput) -> String {
    match &out.body {
        Body::Message(t) => t.clone(),
        other => panic!("unexpected body {other:?}"),
    }
}

// ---------------------------------------------------------------- stdio protocol

#[tokio::test]
async fn stdio_handshake_paging_and_a_call() {
    let t = env();
    let h = handle(&t, &[], 10, Duration::from_secs(600));
    assert_eq!(h.status().state, "not started");
    let listing = h.list(&t.ctx).await.expect("list");
    assert_eq!(listing.transport, "stdio");
    assert_eq!(listing.protocol, "2025-06-18");
    assert_eq!((listing.server_name.as_str(), listing.server_version.as_str()), ("fake", "1.2"));
    let names: Vec<_> = listing.tools.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names, ["echo", "b.tool"]);
    assert_eq!(listing.tools[1].read_only_hint, Some(true));
    assert_eq!(listing.tools[0].read_only_hint, None);
    assert_eq!(h.status().state, "running");

    let r = h.call(&t.ctx, "echo", json!({"text": "x"})).await.expect("call");
    assert_eq!(r["content"][0]["text"], "hello");
    let st = h.status();
    assert_eq!(st.calls, 1);
    assert!(st.last_call_ms.is_some());
    // The handshake sent `initialized`.
    assert!(wait_for(|| h.status().stderr_tail.iter().any(|l| l.contains("notifications/initialized"))).await);
    h.close().await;
    assert_eq!(h.status().state, "closed");
}

#[tokio::test]
async fn an_unknown_protocol_version_ends_the_connection_naming_the_versions() {
    let t = env();
    let h = handle(&t, &[("PROTO", "1999-01-01")], 10, Duration::from_secs(600));
    let e = h.list(&t.ctx).await.expect_err("version");
    // (The test hands the version over as a server env value, so it is redacted like a secret.)
    assert!(e.contains("2024-11-05") && e.contains("2025-11-25"), "{e}");
    assert_eq!(h.status().state, "failed");
}

#[tokio::test]
async fn jsonrpc_errors_and_is_error_results_map_to_error_outputs() {
    let t = env();
    let h = handle(&t, &[], 10, Duration::from_secs(600));
    let e = h.call(&t.ctx, "rpcerr", json!({})).await.expect_err("rpc error");
    assert_eq!(e, CallError::Rpc { code: -32602, message: "bad args".into(), data: Some(json!({"field": "x"})) });
    let out = map_result(&t.ctx, "fake", Err(e), false);
    assert_eq!(out.status, ToolStatus::Error);
    assert_eq!(out.outcome, "mcp error -32602");
    assert_eq!(out.more, ["fake"]);
    assert_eq!(text_of(&out), "bad args\n{\"field\":\"x\"}");

    let r = h.call(&t.ctx, "fail", json!({})).await.expect("isError is a result");
    let out = map_result(&t.ctx, "fake", Ok(r), false);
    assert_eq!((out.status, out.outcome.as_str()), (ToolStatus::Error, "error"));
    assert_eq!(text_of(&out), "it broke");

    let r = h.call(&t.ctx, "echo", json!({})).await.expect("call");
    let out = map_result(&t.ctx, "fake", Ok(r), false);
    assert_eq!((out.status, out.outcome.as_str(), text_of(&out).as_str()), (ToolStatus::Ok, "ok", "hello"));
    assert_eq!(out.more, ["fake"]);
}

#[tokio::test]
async fn server_requests_get_answers_ping_is_empty_and_the_rest_is_method_not_found() {
    let t = env();
    let h = handle(&t, &[], 10, Duration::from_secs(600));
    let r = h.call(&t.ctx, "ping", json!({})).await.expect("call");
    assert_eq!(r["content"][0]["text"], "pinged");
    assert!(
        wait_for(|| {
            let tail = h.status().stderr_tail.join("\n");
            tail.contains("\"id\":900") && tail.contains("\"result\":{}") && tail.contains("-32601")
        })
        .await,
        "{:?}",
        h.status().stderr_tail
    );
}

#[tokio::test]
async fn a_timeout_sends_cancelled_and_the_connection_stays_usable() {
    let t = env();
    let h = handle(&t, &[], 1, Duration::from_secs(600));
    let started = std::time::Instant::now();
    let e = h.call(&t.ctx, "slow", json!({})).await.expect_err("timeout");
    assert_eq!(e, CallError::Timeout { after_s: 1 });
    assert!(started.elapsed() < Duration::from_secs(5));
    let out = map_result(&t.ctx, "fake", Err(e), false);
    assert_eq!((out.status, out.outcome.as_str()), (ToolStatus::Timeout, "stopped after 1s"));
    assert!(
        wait_for(|| h
            .status()
            .stderr_tail
            .iter()
            .any(|l| l.contains("notifications/cancelled") && l.contains("requestId")))
        .await,
        "{:?}",
        h.status().stderr_tail
    );
    let r = h.call(&t.ctx, "echo", json!({})).await.expect("still usable");
    assert_eq!(r["content"][0]["text"], "hello");
}

#[tokio::test]
async fn stopping_a_call_is_interrupted_and_sends_cancelled() {
    let t = env();
    let h = handle(&t, &[], 30, Duration::from_secs(600));
    h.list(&t.ctx).await.expect("list");
    let cancel = t.ctx.cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        cancel.cancel();
    });
    let e = h.call(&t.ctx, "slow", json!({})).await.expect_err("stopped");
    assert_eq!(e, CallError::Interrupted);
    assert_eq!(map_result(&t.ctx, "fake", Err(e), false).status, ToolStatus::Interrupted);
    assert!(wait_for(|| h.status().stderr_tail.iter().any(|l| l.contains("notifications/cancelled"))).await);
}

#[tokio::test]
async fn a_dead_server_is_restarted_once_for_the_next_call() {
    let t = env();
    let h = handle(&t, &[], 10, Duration::from_secs(600));
    h.list(&t.ctx).await.expect("list");
    let e = h.call(&t.ctx, "crash", json!({})).await.expect_err("crash");
    assert!(matches!(e, CallError::Failed { .. }), "{e:?}");
    assert_eq!(h.status().state, "failed");
    let (r, restarted) = h.call_restarting(&t.ctx, "echo", json!({})).await;
    assert!(restarted);
    let out = map_result(&t.ctx, "fake", r, restarted);
    assert_eq!((out.status, text_of(&out).as_str()), (ToolStatus::Ok, "hello"));
    assert_eq!(out.more, ["fake", "server restarted"]);
    assert_eq!(h.status().state, "running");
    let (_, again) = h.call_restarting(&t.ctx, "echo", json!({})).await;
    assert!(!again);
}

#[tokio::test]
async fn a_server_that_cannot_start_gives_the_reason_and_its_stderr() {
    let t = env();
    let cfg = McpServerCfg {
        command: Some(vec!["/bin/sh".into(), "-c".into(), "echo 'cannot open database' >&2; exit 2".into()]),
        timeout_s: 10,
        ..McpServerCfg::default()
    };
    let h = McpHandle::new(McpServer::resolve("bad", &cfg).expect("resolve"), Duration::from_secs(600));
    let e = h.call(&t.ctx, "echo", json!({})).await.expect_err("start fails");
    let CallError::Failed { reason, stderr_tail } = &e else { panic!("{e:?}") };
    assert!(!reason.is_empty());
    assert_eq!(stderr_tail, &["cannot open database".to_string()]);
    let out = map_result(&t.ctx, "bad", Err(e), false);
    assert!(text_of(&out).contains("cannot open database"));
    let e = h.list(&t.ctx).await.expect_err("list fails too");
    assert!(e.contains("cannot open database"), "{e}");
}

#[tokio::test]
async fn the_stderr_ring_keeps_the_last_200_lines() {
    let t = env();
    let h = handle(&t, &[], 10, Duration::from_secs(600));
    h.call(&t.ctx, "noisy", json!({})).await.expect("call");
    assert!(wait_for(|| h.shared.tail(500).last().is_some_and(|l| l == "line 250")).await);
    let tail = h.shared.tail(500);
    assert_eq!(tail.len(), conn::STDERR_RING);
    assert_eq!(tail[0], "line 51");
    assert_eq!(h.status().stderr_tail.len(), 40);
}

#[tokio::test]
async fn an_idle_connection_closes_and_the_next_call_opens_it_again() {
    let t = env();
    let h = handle(&t, &[], 10, Duration::from_millis(300));
    h.call(&t.ctx, "echo", json!({})).await.expect("call");
    assert_eq!(h.status().state, "running");
    assert!(wait_for(|| h.status().state == "closed").await);
    let (r, restarted) = h.call_restarting(&t.ctx, "echo", json!({})).await;
    assert!(r.is_ok() && !restarted);
    assert_eq!(h.status().state, "running");
}

// ---------------------------------------------------------------- secrets

#[tokio::test]
async fn a_resolved_secret_appears_in_no_output_error_or_debug() {
    let t = env();
    let file = t.ctx.workspace.join("secret.txt");
    std::fs::write(&file, format!("{SECRET}\n")).expect("write secret");
    let src = format!("file:{}", file.display());
    let h = handle(&t, &[("SECRET", &src)], 10, Duration::from_secs(600));
    assert_eq!(h.server().env["SECRET"], SECRET);
    assert!(!format!("{:?}", h.server()).contains(SECRET));

    let tool = McpTool {
        handle: h.clone(),
        name: tool_name("fake", "leak"),
        def: McpToolDef {
            name: "leak".into(),
            description: String::new(),
            input_schema: Value::Null,
            read_only_hint: None,
        },
    };
    let out = tool.run(&t.ctx, &serde_json::Map::new()).await;
    assert_eq!(text_of(&out), "key=[redacted]");
    assert!(!format!("{out:?}").contains(SECRET));
    assert!(wait_for(|| h.status().stderr_tail.iter().any(|l| l.contains("secret=[redacted]"))).await);
    assert!(!format!("{:?}", h.status()).contains(SECRET));

    // A start that fails and prints the secret on stderr.
    let bad = handle(&t, &[("SECRET", &src), ("LEAK", "1"), ("PROTO", "bad")], 10, Duration::from_secs(600));
    let e = bad.list(&t.ctx).await.expect_err("fails");
    assert!(!e.contains(SECRET) && e.contains("boot failed with [redacted]"), "{e}");
    let e = bad.call(&t.ctx, "echo", json!({})).await.expect_err("fails");
    assert!(!format!("{e:?}").contains(SECRET));
    assert!(!format!("{:?}", bad.status()).contains(SECRET));

    // A missing source names the source, not a value.
    let cfg = McpServerCfg {
        command: Some(vec!["x".into()]),
        env: [("A".to_string(), "file:/nonexistent/loom-secret".to_string())].into(),
        ..McpServerCfg::default()
    };
    let e = McpServer::resolve("s", &cfg).expect_err("missing");
    assert!(e.contains("mcp.servers.s.env.A") && e.contains("/nonexistent/loom-secret"), "{e}");
    let cfg = McpServerCfg {
        url: Some("http://x".into()),
        headers: [("Authorization".to_string(), "env:LOOM_MCP_TEST_SURELY_UNSET_VAR".to_string())].into(),
        ..McpServerCfg::default()
    };
    let e = McpServer::resolve("s", &cfg).expect_err("unset");
    assert!(e.contains("LOOM_MCP_TEST_SURELY_UNSET_VAR") && e.contains("headers.Authorization"), "{e}");
}

// ---------------------------------------------------------------- sandbox

fn seatbelt_available() -> bool {
    Path::new("/usr/bin/sandbox-exec").exists()
}

async fn probe(mode: SandboxMode, outside: &Path, port: u16) -> String {
    let t = env_with(
        ToolsCfg { dialect: loom_core::config::Dialect::Loom, ..ToolsCfg::default() },
        SandboxCfg { mode, ..SandboxCfg::default() },
    );
    let out_s = outside.to_string_lossy().into_owned();
    let port_s = port.to_string();
    let h = handle(&t, &[("OUT", &out_s), ("PORT", &port_s)], 20, Duration::from_secs(600));
    let r = h.call(&t.ctx, "probe", json!({})).await.expect("probe call");
    h.close().await;
    r["content"][0]["text"].as_str().unwrap_or_default().to_string()
}

#[tokio::test]
async fn a_stdio_server_cannot_write_outside_the_workspace_or_connect_out() {
    if !seatbelt_available() {
        return;
    }
    let Some(home) = std::env::var_os("HOME") else { return };
    let Ok(outside) = tempfile::Builder::new().prefix("loom-mcp-").tempdir_in(home) else { return };
    let outside_dir = outside.path().canonicalize().expect("canonical");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();

    // Without a sandbox both work, so the refusals below are the sandbox's doing.
    assert_eq!(probe(SandboxMode::None, &outside_dir, port).await, "write=wrote net=open");
    std::fs::remove_file(outside_dir.join("no.txt")).expect("remove");
    assert_eq!(probe(SandboxMode::Seatbelt, &outside_dir, port).await, "write=denied net=blocked");
    assert!(!outside_dir.join("no.txt").exists());
}

// ---------------------------------------------------------------- content mapping

const PNG_1X1: &[u8] = &[
    0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, b'I', b'H', b'D', b'R', 0, 0, 0, 1, 0, 0, 0, 1, 8, 6,
    0, 0, 0, 0x1F, 0x15, 0xC4, 0x89,
];

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[test]
fn every_content_block_kind_maps_in_order() {
    let t = env();
    let result = json!({"content": [
        {"type": "text", "text": "one"},
        {"type": "image", "mimeType": "image/png", "data": b64(PNG_1X1)},
        {"type": "audio", "mimeType": "audio/wav", "data": b64(&[0u8; 12])},
        {"type": "resource_link", "uri": "file:///a", "name": "a", "mimeType": "text/plain"},
        {"type": "resource_link", "uri": "file:///b"},
        {"type": "resource", "resource": {"uri": "file:///t", "text": "inside"}},
        {"type": "resource", "resource": {"uri": "file:///blob", "mimeType": "application/zip", "blob": b64(&[1u8; 30])}},
        {"type": "text", "text": "last"},
    ]});
    let out = map_result(&t.ctx, "s", Ok(result), false);
    let text = text_of(&out);
    let blocks: Vec<&str> = text.split("\n\n").collect();
    assert_eq!(blocks[0], "one");
    assert!(blocks[1].starts_with("[image: 1x1 image/png"), "{}", blocks[1]);
    assert_eq!(blocks[2], "[audio not shown: audio/wav, 12 bytes]");
    assert_eq!(blocks[3], "[resource file:///a \u{b7} a \u{b7} text/plain]");
    assert_eq!(blocks[4], "[resource file:///b]");
    assert_eq!(blocks[5], "[resource file:///t]\ninside");
    assert_eq!(blocks[6], "[resource file:///blob: application/zip, 30 bytes, not shown]");
    assert_eq!(blocks[7], "last");
    let images = out.meta.get(crate::META_IMAGES).and_then(Value::as_array).expect("images");
    assert_eq!(images.len(), 1);
    assert_eq!(images[0]["mime"], "image/png");
    let id = t.ctx.blobs.resolve(images[0]["blob"].as_str().unwrap()).expect("blob");
    assert_eq!(t.ctx.blobs.read_all(&id).expect("read"), PNG_1X1);
}

#[test]
fn structured_content_empty_content_and_oversized_images() {
    let t = env();
    let out = map_result(&t.ctx, "s", Ok(json!({"content": [], "structuredContent": {"a": 1}})), false);
    assert_eq!(text_of(&out), "{\n  \"a\": 1\n}");
    // With a text block the structured content is not repeated.
    let out = map_result(
        &t.ctx,
        "s",
        Ok(json!({"content": [{"type":"text","text":"t"}], "structuredContent": {"a": 1}})),
        false,
    );
    assert_eq!(text_of(&out), "t");
    let out = map_result(&t.ctx, "s", Ok(json!({})), false);
    assert_eq!(text_of(&out), "(no content)");
    assert_eq!(out.status, ToolStatus::Ok);

    let small = env_with(
        ToolsCfg { dialect: loom_core::config::Dialect::Loom, max_image_bytes: 10, ..ToolsCfg::default() },
        SandboxCfg { mode: SandboxMode::None, ..SandboxCfg::default() },
    );
    let out = map_result(
        &small.ctx,
        "s",
        Ok(json!({"content": [{"type": "image", "mimeType": "image/png", "data": b64(PNG_1X1)}]})),
        false,
    );
    assert_eq!(text_of(&out), format!("[image not kept: image/png, {} bytes]", PNG_1X1.len()));
    assert!(out.meta.get(crate::META_IMAGES).is_none());
}

// ---------------------------------------------------------------- naming and spec

#[test]
fn names_are_sanitised_cut_and_collisions_keep_the_first() {
    assert_eq!(tool_name("gh", "search.issues v2"), "mcp__gh__search_issues_v2");
    assert_eq!(tool_name("gh", "ok-name_1"), "mcp__gh__ok-name_1");
    let long = tool_name("gh", &"x".repeat(200));
    assert_eq!(long.chars().count(), MAX_TOOL_NAME);
    assert!(long.starts_with("mcp__gh__xxx"));

    let def = |n: &str| McpToolDef {
        name: n.into(),
        description: String::new(),
        input_schema: Value::Null,
        read_only_hint: None,
    };
    let listing = McpListing {
        server: "gh".into(),
        transport: "stdio".into(),
        protocol: String::new(),
        server_name: String::new(),
        server_version: String::new(),
        tools: vec![def("a.b"), def("a b"), def("c"), def(&"y".repeat(100)), def(&format!("{}z", "y".repeat(100)))],
        error: None,
    };
    let (kept, left_out) = presented_tools(&listing, None);
    let names: Vec<_> = kept.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names[0], "mcp__gh__a_b");
    assert_eq!(names[1], "mcp__gh__c");
    assert_eq!(names.len(), 3);
    assert_eq!(left_out, vec!["a b".to_string(), format!("{}z", "y".repeat(100))]);
    let (kept, left_out) = presented_tools(&listing, Some(&["c".to_string(), "a b".to_string()]));
    assert_eq!(kept.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), ["mcp__gh__a_b", "mcp__gh__c"]);
    assert!(left_out.is_empty());
}

#[test]
fn spec_follows_the_listing() {
    let h = McpHandle::new(
        McpServer {
            name: "gh".into(),
            cfg: McpServerCfg::default(),
            env: Default::default(),
            headers: Default::default(),
        },
        Duration::from_secs(1),
    );
    let tool = |schema: Value, hint: Option<bool>, desc: String| McpTool {
        handle: h.clone(),
        name: "mcp__gh__t".into(),
        def: McpToolDef { name: "t".into(), description: desc, input_schema: schema, read_only_hint: hint },
    };
    let s = tool(json!({"$schema": "http://json-schema.org/draft-07/schema#", "type": "object", "properties": {"a": {"type": "string"}}}), Some(true), "d".repeat(3000)).spec();
    assert_eq!(s.parameters, json!({"type": "object", "properties": {"a": {"type": "string"}}}));
    assert_eq!(s.description.chars().count(), 2000);
    assert_eq!(s.class, loom_core::event::ToolClass::Read);
    assert!(!tool(Value::Null, Some(true), String::new()).speculative());
    let s = tool(Value::Null, None, String::new()).spec();
    assert_eq!(s.parameters, json!({"type": "object", "properties": {}}));
    assert_eq!(s.class, loom_core::event::ToolClass::Exec);
}

// ---------------------------------------------------------------- Streamable HTTP

#[derive(Default)]
struct Hits {
    sessions: AtomicU64,
    forget_next_call: AtomicBool,
    deletes: AtomicU64,
    log: Mutex<Vec<String>>,
    bad_headers: AtomicU64,
}

async fn serve_http() -> (String, Arc<Hits>) {
    use axum::extract::State;
    use axum::http::{HeaderMap, Method, StatusCode};
    use axum::response::{IntoResponse, Response};

    async fn h(State(st): State<Arc<Hits>>, method: Method, headers: HeaderMap, body: String) -> Response {
        if method == Method::DELETE {
            st.deletes.fetch_add(1, Ordering::SeqCst);
            return StatusCode::OK.into_response();
        }
        let msg: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let m = msg.get("method").and_then(Value::as_str).unwrap_or("").to_string();
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        st.log.lock().unwrap().push(if m.is_empty() { "reply".to_string() } else { m.clone() });
        let accept = headers.get("accept").and_then(|v| v.to_str().ok()).unwrap_or("");
        if !(accept.contains("application/json") && accept.contains("text/event-stream"))
            || headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(&format!("Bearer {SECRET}"))
        {
            st.bad_headers.fetch_add(1, Ordering::SeqCst);
            return StatusCode::UNAUTHORIZED.into_response();
        }
        if m != "initialize"
            && !m.is_empty()
            && headers.get("mcp-protocol-version").and_then(|v| v.to_str().ok()) != Some("2025-03-26")
        {
            st.bad_headers.fetch_add(1, Ordering::SeqCst);
        }
        let json_resp = |v: Value| ([("content-type", "application/json")], v.to_string()).into_response();
        match m.as_str() {
            "initialize" => {
                let n = st.sessions.fetch_add(1, Ordering::SeqCst) + 1;
                let mut r = json_resp(
                    json!({"jsonrpc": "2.0", "id": id, "result": {"protocolVersion": "2025-03-26", "capabilities": {}, "serverInfo": {"name": "web", "version": "9"}}}),
                );
                r.headers_mut().insert("mcp-session-id", format!("sess-{n}").parse().unwrap());
                r
            }
            "" | "notifications/initialized" | "notifications/cancelled" => StatusCode::ACCEPTED.into_response(),
            "tools/list" => json_resp(
                json!({"jsonrpc": "2.0", "id": id, "result": {"tools": [{"name": "echo", "description": "e", "inputSchema": {"type": "object"}}]}}),
            ),
            "tools/call" => {
                let name = msg["params"]["name"].as_str().unwrap_or("");
                if st.forget_next_call.swap(false, Ordering::SeqCst) {
                    return StatusCode::NOT_FOUND.into_response();
                }
                if name == "stream" {
                    let events = format!(
                        ": keepalive\n\nevent: message\ndata: {}\n\nevent: message\ndata: {}\n\nevent: message\ndata: {}\n\n",
                        json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}),
                        json!({"jsonrpc": "2.0", "id": 77, "method": "ping"}),
                        json!({"jsonrpc": "2.0", "id": id, "result": {"content": [{"type": "text", "text": "streamed"}]}}),
                    );
                    return ([("content-type", "text/event-stream")], events).into_response();
                }
                if name == "rpcerr" {
                    return json_resp(
                        json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": "nope"}}),
                    );
                }
                json_resp(
                    json!({"jsonrpc": "2.0", "id": id, "result": {"content": [{"type": "text", "text": "plain"}]}}),
                )
            }
            _ => json_resp(json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "no"}})),
        }
    }

    let st = Arc::new(Hits::default());
    let app = axum::Router::new().route("/mcp", axum::routing::any(h)).with_state(st.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, st)
}

fn http_handle(url: &str) -> Arc<McpHandle> {
    let cfg = McpServerCfg {
        url: Some(url.to_string()),
        headers: [("Authorization".to_string(), format!("Bearer {SECRET}"))].into(),
        timeout_s: 10,
        ..McpServerCfg::default()
    };
    McpHandle::new(McpServer::resolve("web", &cfg).expect("resolve"), Duration::from_secs(600))
}

#[tokio::test]
async fn http_handshake_json_and_sse_answers_and_delete_on_close() {
    let t = env();
    let (url, st) = serve_http().await;
    let h = http_handle(&url);
    let listing = h.list(&t.ctx).await.expect("list");
    assert_eq!(
        (listing.transport.as_str(), listing.protocol.as_str(), listing.server_name.as_str()),
        ("http", "2025-03-26", "web")
    );
    assert_eq!(listing.tools.len(), 1);

    let r = h.call(&t.ctx, "echo", json!({})).await.expect("json call");
    assert_eq!(r["content"][0]["text"], "plain");
    assert!(!h.status().list_changed);
    let r = h.call(&t.ctx, "stream", json!({})).await.expect("sse call");
    assert_eq!(r["content"][0]["text"], "streamed");
    assert!(h.status().list_changed);
    // The ping the server sent inside the stream was answered by a POST.
    assert!(wait_for(|| st.log.lock().unwrap().iter().any(|l| l == "reply")).await);
    let e = h.call(&t.ctx, "rpcerr", json!({})).await.expect_err("rpc error");
    assert!(matches!(e, CallError::Rpc { code: -32000, .. }), "{e:?}");

    assert_eq!(st.bad_headers.load(Ordering::SeqCst), 0, "accept, authorization and protocol version headers");
    h.close().await;
    assert_eq!(st.deletes.load(Ordering::SeqCst), 1);
    assert_eq!(h.status().state, "closed");
}

#[tokio::test]
async fn http_initializes_again_once_when_the_server_forgot_the_session() {
    let t = env();
    let (url, st) = serve_http().await;
    let h = http_handle(&url);
    h.list(&t.ctx).await.expect("list");
    st.forget_next_call.store(true, Ordering::SeqCst);
    let r = h.call(&t.ctx, "echo", json!({})).await.expect("call after a forgotten session");
    assert_eq!(r["content"][0]["text"], "plain");
    assert_eq!(st.sessions.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn an_http_error_status_is_a_failure_without_the_header_value() {
    let t = env();
    let (url, _st) = serve_http().await;
    let cfg = McpServerCfg {
        url: Some(url),
        headers: [("Authorization".to_string(), "Bearer wrong-token-123".to_string())].into(),
        timeout_s: 10,
        ..McpServerCfg::default()
    };
    let h = McpHandle::new(McpServer::resolve("web", &cfg).expect("resolve"), Duration::from_secs(600));
    let e = h.list(&t.ctx).await.expect_err("401");
    assert!(e.contains("401") && !e.contains("wrong-token-123"), "{e}");
}
