// Included in session::tests to exercise the real session loop with the mock model.

fn guarded_call(nodes: Value) -> Reply {
    Reply::tool("guarded_plan", json!({"nodes": nodes}).to_string())
}

fn guarded_enable(fx: &mut Fx) {
    Arc::get_mut(&mut fx.shared).unwrap().role.tools.push("guarded_plan".into());
}

fn guarded_nodes(first: &str, second: &str) -> Value {
    json!([
        {"tool":"bash","arguments":{"command":first},"guard":"start"},
        {"tool":"bash","arguments":{"command":second},"guard":"previous_success"}
    ])
}

#[tokio::test]
async fn guarded_actions_omit_callbacks_but_preserve_native_receipts_and_budget() {
    let nodes = guarded_nodes("printf first", "printf second");
    let mut fx = Fx::new("chat", false, false, seq(vec![guarded_call(nodes).into(), Reply::text("done").into()])).await;
    guarded_enable(&mut fx);
    let mut session = fx.create();
    session.step().await.unwrap(); // Author the literal plan.
    session.step().await.unwrap();
    session.step().await.unwrap();
    assert_eq!(fx.server.requests().len(), 1);
    assert_eq!(session.status().step, 3); // One callback and two native dispatches.
    let rs = fx.sink.records();
    assert_eq!(count(&rs, "stored_action"), 2);
    assert_eq!(count(&rs, "model_response"), 1);
    let stored: Vec<_> = rs.iter().filter_map(|r| match &r.event {
        Event::StoredAction(action) => Some(action), _ => None,
    }).collect();
    assert_eq!(stored[0].call.arguments, r#"{"command":"printf first"}"#);
    assert_eq!(stored[1].predecessor.as_ref(), Some(&stored[0].call.call_id));
    for action in stored {
        assert!(rs.iter().any(|r| r.author == Author::Harness && matches!(&r.event, Event::ToolCall(c) if c.call_id == action.call.call_id)));
        let result = results(&rs).into_iter().find(|r| r.call_id == action.call.call_id).unwrap();
        assert_eq!(result.meta[META_DEFERRED_OBSERVATION], true);
        assert_eq!(result.meta[META_EXIT_CODE], 0);
        let blob = result.output.unwrap();
        assert!(!loom_core::observe::coverage(&rs)[&blob.id].covers(1, 1));
    }
    session.step().await.unwrap(); // The actor actually receives both outputs.
    let rs = fx.sink.records();
    assert_eq!(fx.server.requests().len(), 2);
    assert_eq!(count(&rs, "outputs_observed"), 1);
    assert!(all_text(&fx.server.requests()[1]).contains("second"));
    for result in results(&rs).into_iter().filter(|r| r.meta.get(META_DEFERRED_OBSERVATION) == Some(&Value::Bool(true))) {
        assert!(loom_core::observe::coverage(&rs)[&result.output.unwrap().id].covers(1, 1));
    }
    assert_no_cache_break(&rs);

    let mut baseline = Fx::new("chat", false, false, seq(vec![bash("printf first").into(), bash("printf second").into(), Reply::text("done").into()])).await;
    let session = baseline.create();
    run_with(session, vec![user("do it")]).await;
    assert_eq!(baseline.server.requests().len(), 3); // Mechanism check, no timing claim.
}

#[tokio::test]
async fn guarded_failed_receipt_and_changed_file_return_to_actor() {
    for changed_file in [false, true] {
        let first = if changed_file { "printf new > input" } else { "exit 7" };
        let mut nodes = guarded_nodes(first, "touch must-not-run");
        if changed_file { nodes[1]["unchanged"] = json!(["input"]); }
        let mut fx = Fx::new("chat", false, false, seq(vec![guarded_call(nodes).into(), Reply::text("reconcile").into()])).await;
        guarded_enable(&mut fx);
        std::fs::write(fx.ctx.workspace.join("input"), "old").unwrap();
        let session = fx.create();
        run_with(session, vec![user("do it")]).await;
        assert!(!fx.ctx.workspace.join("must-not-run").exists());
        let rs = fx.sink.records();
        assert_eq!(count(&rs, "stored_action"), 1);
        assert_eq!(fx.server.requests().len(), 2);
        let reason = rs.iter().find_map(|r| match &r.event {
            Event::ContinuationStopped { reason, .. } => Some(reason), _ => None,
        }).unwrap();
        assert!(reason.contains(if changed_file { "changed" } else { "no successful" }));
    }
}

#[tokio::test]
async fn guarded_new_instructions_and_standing_rules_invalidate_a_plan() {
    for constraint in [false, true] {
        let mut fx = Fx::new("chat", false, true, seq(vec![guarded_call(guarded_nodes("touch must-not-run", "true")).into(), Reply::text("reconcile").into()])).await;
        guarded_enable(&mut fx);
        let mut session = fx.create();
        session.step().await.unwrap();
        if constraint {
            fx.shared.ledger_append(true, LedgerOp::ConstraintAdd { text: "New operator rule".into() }).unwrap();
        } else {
            session.append(Author::User, Event::UserMessage { text: "Change direction".into() }).unwrap();
        }
        session.step().await.unwrap();
        assert!(!fx.ctx.workspace.join("must-not-run").exists());
        assert_eq!(count(session.records(), "stored_action"), 0);
        assert_eq!(fx.server.requests().len(), 2);
    }
}

#[tokio::test]
async fn guarded_other_actor_actions_and_budget_cannot_be_bypassed() {
    let plan = json!({"nodes":guarded_nodes("touch must-not-run", "true")}).to_string();
    let reply = Reply::tools([("guarded_plan", plan), ("bash", json!({"command":"true"}).to_string())]);
    let mut fx = Fx::new("chat", false, false, seq(vec![reply.into(), Reply::text("reconcile").into()])).await;
    guarded_enable(&mut fx);
    let session = fx.create();
    run_with(session, vec![user("go")]).await;
    assert_eq!(count(&fx.sink.records(), "stored_action"), 0);
    assert!(!fx.ctx.workspace.join("must-not-run").exists());

    let mut fx = Fx::new("chat", false, false, seq(vec![guarded_call(guarded_nodes("touch must-not-run", "true")).into(), Reply::text("budget reached").into()])).await;
    guarded_enable(&mut fx);
    let mut session = fx.create_with(Budget { max_steps: Some(1), max_minutes: None }, None);
    session.step().await.unwrap();
    session.step().await.unwrap();
    assert_eq!(count(session.records(), "stored_action"), 0);
    assert!(notes(session.records(), NoteKind::Budget).len() == 1);
    assert!(!fx.ctx.workspace.join("must-not-run").exists());
}

#[tokio::test]
async fn guarded_restart_never_replays_pending_actions() {
    let mut fx = Fx::new("chat", false, false, seq(vec![guarded_call(guarded_nodes("printf once >> marker", "printf twice >> marker")).into(), Reply::text("reconcile").into()])).await;
    guarded_enable(&mut fx);
    let mut session = fx.create();
    session.step().await.unwrap();
    session.step().await.unwrap(); // First action completed; second is still queued.
    drop(session);
    let mut reopened = Session::open(fx.deps()).unwrap();
    reopened.step().await.unwrap();
    assert_eq!(std::fs::read_to_string(fx.ctx.workspace.join("marker")).unwrap(), "once");
    assert_eq!(count(reopened.records(), "stored_action"), 1);
    assert!(reopened.records().iter().any(|r| matches!(&r.event, Event::ContinuationStopped { reason, .. } if reason.contains("restarted"))));
    assert_eq!(reopened.status().step, 3); // Recovered actor + stored + new actor.
}

#[tokio::test]
async fn guarded_restart_with_an_unknown_native_result_requires_reconciliation() {
    let mut fx = Fx::new("chat", false, false, seq(vec![guarded_call(guarded_nodes("printf once >> marker", "printf twice >> marker")).into(), Reply::text("reconcile").into()])).await;
    guarded_enable(&mut fx);
    let mut session = fx.create();
    session.step().await.unwrap();
    session.step().await.unwrap();
    let last_intent = session.records().iter().rposition(|r| matches!(&r.event, Event::ToolCall(c) if c.call_id.as_str().starts_with("stored-"))).unwrap();
    drop(session);
    // Preserve the real side effect, but simulate a crash before its receipt was durable.
    let raw = std::fs::read_to_string(fx.log_path()).unwrap();
    let prefix = raw.lines().take(last_intent + 1).collect::<Vec<_>>().join("\n") + "\n";
    std::fs::write(fx.log_path(), prefix).unwrap();
    let mut reopened = Session::open(fx.deps()).unwrap();
    reopened.step().await.unwrap();
    assert_eq!(std::fs::read_to_string(fx.ctx.workspace.join("marker")).unwrap(), "once");
    assert!(all_text(&fx.server.requests()[1]).contains(loom_core::weave::MISSING_RESULT));
    assert!(all_text(&fx.server.requests()[1]).contains("never repeat it blindly"));
    assert_eq!(count(reopened.records(), "stored_action"), 1);
}

#[tokio::test]
async fn guarded_background_receipt_cannot_trigger_a_successor() {
    let mut fx = Fx::new("chat", false, false, seq(vec![guarded_call(guarded_nodes("sleep 60", "touch must-not-run")).into(), Reply::text("wait for job").into()])).await;
    guarded_enable(&mut fx);
    Arc::make_mut(&mut fx.ctx.cfg).bash_foreground_s = 0;
    let session = fx.create();
    run_with(session, vec![user("go")]).await;
    assert!(!fx.ctx.workspace.join("must-not-run").exists());
    assert_eq!(count(&fx.sink.records(), "stored_action"), 1);
    assert_eq!(fx.server.requests().len(), 2);
    assert!(fx.ctx.jobs.list().await.iter().all(|j| j.state != JobState::Running));
}

#[tokio::test]
async fn guarded_cancellation_and_deferred_stubs_are_not_observations() {
    let mut fx = Fx::new("chat", false, false, seq(vec![guarded_call(guarded_nodes("touch must-not-run", "true")).into()])).await;
    guarded_enable(&mut fx);
    let mut session = fx.create();
    session.step().await.unwrap();
    session.token.cancel();
    session.step().await.unwrap();
    assert!(!fx.ctx.workspace.join("must-not-run").exists());
    assert_eq!(count(session.records(), "stored_action"), 0);

    let mut fx = Fx::new("chat", false, false, seq(vec![guarded_call(json!([{"tool":"bash","arguments":{"command":"printf receipt"},"guard":"start"}])).into()])).await;
    guarded_enable(&mut fx);
    let mut session = fx.create();
    session.step().await.unwrap();
    session.step().await.unwrap();
    let woven = weave(session.records());
    assert_eq!(session.deferred_observations(&woven.messages).len(), 1);
    let mut stubbed = woven.messages;
    for message in &mut stubbed {
        if message.tool_call_id.as_deref().is_some_and(|id| id.starts_with("stored-")) { message.content = "shortened; reopen output".into(); }
    }
    assert!(session.deferred_observations(&stubbed).is_empty());
}

#[test]
fn guarded_default_pack_does_not_grant_prototype() {
    for role in ["lead", "worker", "chat", "verifier"] {
        assert!(!core_role(role).tools.contains(&"guarded_plan".into()));
    }
}
