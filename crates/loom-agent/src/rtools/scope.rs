//! `request_scope`: ask the operator to authorize network access to more hosts.
//!
//! CONTRACT.
//!
//! The tool grants nothing and changes no policy; only the operator widens the scope
//! (`Runtime::grant_scope`). It ends no turn: the agent keeps working.
//!
//! `request_scope { hosts: [string], why: string }`
//! - refused in a child session, as `ask_user` is: `Only the lead can ask the operator. Say in your
//!   result (`not_established`) which hosts you could not reach, or call report_blocker if you cannot
//!   continue.`
//! - `why` must contain non-whitespace (else an error saying so); `hosts` must pass
//!   `loom_net::policy::check_hosts` (at least one, none blank, one host per entry, each a valid host
//!   pattern); a failure is returned as the error, and nothing is opened.
//! - emits one `InboxOpened(InboxItem { kind: Question, text: texts::scope_request(hosts, why),
//!   blocking: false, options: [], call_id: Some(ctx.call_id), reference: None })`. The text names the
//!   hosts and the reason and says the operator can authorize them.
//! - ok, outcome `scope requested`, message `texts::scope_requested(hosts)`: the request is with the
//!   operator, nothing is authorized yet, carry on without it, and do not try the host until the
//!   authorization appears in the harness-state.
//!
//! Tests required: one non-blocking inbox item naming hosts and reason, no effect, no ledger entry;
//! invalid, empty and blank hosts and a blank reason refused with nothing opened; refused in a child.

use super::Shared;
use crate::texts;
use async_trait::async_trait;
use loom_core::event::{Author, Event, InboxItem, InboxKind, ToolClass, ToolSpec};
use loom_core::ids::new_item_id;
use loom_tools::params::{req, spec};
use loom_tools::{Body, Tool, ToolCtx, ToolOutput};
use serde_json::{Map, Value};
use std::sync::Arc;

pub struct RequestScope(pub Arc<Shared>);

#[async_trait]
impl Tool for RequestScope {
    fn spec(&self) -> ToolSpec {
        spec(
            "request_scope",
            "Ask the operator to authorize network access to hosts outside the engagement's current scope. This grants nothing: the request goes to the operator's inbox and you keep working. Use it when the work needs a host the network policy refuses, and say why. Do not try to reach the host until the authorization appears in your harness-state.",
            ToolClass::State,
            &[
                req("hosts", "array", "The hosts to authorize, one per entry: `api.example.test` or `*.example.test`, optionally with `:port`.")
                    .items("string"),
                req("why", "string", "Why the work needs them, in a sentence the operator can decide on."),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let s = &self.0;
        if s.is_child() {
            return ToolOutput::error(
                "Only the lead can ask the operator. Say in your result (`not_established`) which hosts you could not reach, or call report_blocker if you cannot continue.",
            );
        }
        let why = args.get("why").and_then(Value::as_str).unwrap_or("").trim();
        if why.is_empty() {
            return ToolOutput::error("request_scope needs `why`: say what the work needs the hosts for. Nothing was requested.");
        }
        let listed: Vec<String> = args
            .get("hosts")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let hosts = match loom_net::policy::check_hosts(&listed) {
            Ok(h) => h,
            Err(e) => return ToolOutput::error(format!("{e} Nothing was requested.")),
        };
        s.emit(
            Author::Harness,
            Event::InboxOpened(InboxItem {
                item_id: new_item_id(),
                kind: InboxKind::Question,
                text: texts::scope_request(&hosts, why),
                options: Vec::new(),
                blocking: false,
                call_id: Some(ctx.call_id.clone()),
                reference: None,
            }),
        );
        ToolOutput::ok("scope requested", Body::Message(texts::scope_requested(&hosts)))
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit::{core_role, rig_with, Rig};
    use super::*;
    use loom_core::config::AgentsCfg;
    use loom_core::event::ToolStatus as Status;
    use serde_json::json;

    fn with_tool(child: bool) -> Rig {
        let mut role = core_role("lead");
        role.tools.push("request_scope".into());
        rig_with(role, child, true, AgentsCfg::default())
    }

    fn items(r: &Rig) -> Vec<InboxItem> {
        r.shared
            .take_emitted()
            .into_iter()
            .filter_map(|(_, e)| if let Event::InboxOpened(i) = e { Some(i) } else { None })
            .collect()
    }

    #[tokio::test]
    async fn a_request_opens_one_non_blocking_item_naming_the_hosts_and_grants_nothing() {
        let r = with_tool(false);
        let res = r.call("request_scope", json!({"hosts": [" api.example.test ", "*.cdn.example.test"], "why": "the API is the target"})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(res.text.contains("Nothing is authorized yet") && res.text.contains("Carry on"), "{}", res.text);
        assert!(res.text.contains("api.example.test, *.cdn.example.test"), "{}", res.text);
        assert!(res.text.contains("harness-state"), "{}", res.text);
        let opened = items(&r);
        assert_eq!(opened.len(), 1, "{opened:?}");
        let item = &opened[0];
        assert_eq!((item.kind, item.blocking), (InboxKind::Question, false));
        assert!(item.text.contains("api.example.test, *.cdn.example.test") && item.text.contains("the API is the target"), "{}", item.text);
        assert!(item.text.contains("Authorize"), "{}", item.text);
        // Nothing ended the turn and nothing was recorded in the ledger.
        assert!(r.shared.take_effect().is_none());
        assert!(r.shared.ledger().unwrap().scope_grants.is_empty());
    }

    #[tokio::test]
    async fn bad_requests_are_refused_and_open_nothing() {
        let r = with_tool(false);
        for args in [
            json!({"hosts": [], "why": "x"}),
            json!({"hosts": ["a.test", "  "], "why": "x"}),
            json!({"hosts": ["bad host"], "why": "x"}),
            json!({"hosts": ["a.test"], "why": "  "}),
        ] {
            let res = r.call("request_scope", args.clone()).await;
            assert_eq!(res.status, Status::Error, "{args}");
            assert!(res.text.contains("Nothing was requested"), "{}", res.text);
        }
        assert!(items(&r).is_empty());
        let c = with_tool(true);
        let res = c.call("request_scope", json!({"hosts": ["a.test"], "why": "x"})).await;
        assert_eq!(res.status, Status::Error);
        assert!(res.text.contains("Only the lead can ask the operator"), "{}", res.text);
        assert!(items(&c).is_empty());
    }
}
