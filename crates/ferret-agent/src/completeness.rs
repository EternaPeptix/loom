//! What a result says it did not cover (contract Part N).
//!
//! The tools put their own limits in a result's meta (`limits`, `complete: false`; see
//! `ferret_tools::add_limit`). The egress proxy's decisions are written by the runtime to the session's
//! `net.jsonl`, which a tool cannot see, so the session reads them here when a `bash`/`box_exec` call
//! ends: connections denied between the call's start and its result become the header fact
//! `network: {k} connections denied ({up to 3 hosts})`, the meta `net_denied: k` and the limit `net denied`.

use std::io::{BufRead, BufReader};
use std::path::Path;

use ferret_core::event::ToolResult;
use ferret_tools::{add_limit, META_NET_DENIED};
use serde_json::Value;

/// The tools whose calls run commands that can reach the network.
pub fn reaches_network(tool: &str) -> bool {
    matches!(tool, "bash" | "box_exec")
}

/// The denied proxy decisions in `net_jsonl` stamped from `from_ms` to `to_ms` inclusive: how many, and
/// the first three distinct hosts.
pub fn denied_between(net_jsonl: &Path, from_ms: u64, to_ms: u64) -> (u64, Vec<String>) {
    let Ok(file) = std::fs::File::open(net_jsonl) else {
        return (0, Vec::new());
    };
    let (mut count, mut hosts) = (0u64, Vec::<String>::new());
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
        if v.get("allowed").and_then(Value::as_bool) != Some(false) {
            continue;
        }
        let ts = v.get("ts_ms").and_then(Value::as_u64).unwrap_or(0);
        if ts < from_ms || ts > to_ms {
            continue;
        }
        count += 1;
        if let Some(host) = v.get("host").and_then(Value::as_str) {
            if hosts.len() < 3 && !hosts.iter().any(|h| h == host) {
                hosts.push(host.to_string());
            }
        }
    }
    (count, hosts)
}

/// The header fact for `k` denied connections.
pub fn net_fact(k: u64, hosts: &[String]) -> String {
    let noun = if k == 1 { "connection" } else { "connections" };
    if hosts.is_empty() {
        format!("network: {k} {noun} denied")
    } else {
        format!("network: {k} {noun} denied ({})", hosts.join(", "))
    }
}

/// Record `k` denied connections in `result`: the fact in the header (the first line), the meta and the limit.
pub fn mark_net_denied(result: &mut ToolResult, k: u64, hosts: &[String]) {
    if k == 0 {
        return;
    }
    let fact = net_fact(k, hosts);
    if result.text.starts_with('[') {
        if let Some(end) = result.text.find("]\n") {
            result.text.insert_str(end, &format!(" · {fact}"));
        }
    } else {
        result.text = format!("[{fact}]\n{}", result.text);
    }
    result.meta.insert(META_NET_DENIED.into(), Value::from(k));
    add_limit(&mut result.meta, "net denied");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denials_are_counted_inside_the_window_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.jsonl");
        let lines = [
            r#"{"ts_ms":90,"host":"early.test","port":1,"allowed":false}"#,
            r#"{"ts_ms":100,"host":"a.test","port":443,"allowed":false}"#,
            r#"{"ts_ms":110,"host":"127.0.0.1","port":1,"allowed":true}"#,
            r#"{"ts_ms":120,"host":"a.test","port":443,"allowed":false}"#,
            r#"{"ts_ms":130,"host":"b.test","port":443,"allowed":false}"#,
            r#"{"ts_ms":140,"host":"c.test","port":443,"allowed":false}"#,
            r#"{"ts_ms":150,"host":"d.test","port":443,"allowed":false}"#,
            r#"{"ts_ms":900,"host":"late.test","port":1,"allowed":false}"#,
            "not json",
        ];
        std::fs::write(&path, lines.join("\n")).unwrap();
        let (k, hosts) = denied_between(&path, 100, 200);
        assert_eq!(k, 5);
        assert_eq!(hosts, ["a.test", "b.test", "c.test"]);
        assert_eq!(net_fact(k, &hosts), "network: 5 connections denied (a.test, b.test, c.test)");
        assert_eq!(denied_between(&dir.path().join("none.jsonl"), 0, 1000), (0, Vec::new()));
    }
}
