//! The daemon's side of the proxy controls: the synchronous veto, canary users and hosts, and the lab-listener
//! identity check (`docs/MONITOR.md` §2.2, E4b, E4d and E4e).
//!
//! CONTRACT.
//!
//! `loom_net::Proxy` has the mechanisms (a veto hook, a canary table and hook, a listener check, `cut`); this module
//! is what the daemon puts in them. It needs no model and no monitor: it decides by lists the daemon owns, and it
//! reports each decision as a `FloorEvent` for the monitor (M2) and the operator.
//!
//! - `Floor::new(infrastructure)`: `infrastructure` is a policy built only from the daemon's infrastructure
//!   (`Policy::new(default).with_infrastructure(spec)`), the same classes every session's policy refuses first
//!   (`docs/MONITOR.md` E1). `set_infrastructure` replaces it when the daemon resolves its names again.
//! - `install(proxy, probe)` puts the veto, the canary hook and, when `probe` is given, the listener check into the
//!   proxy and keeps a handle on it for `add_canary_user`. `probe(port)` is `loom_tools::sandbox::census::listener_of`
//!   over the sessions the daemon knows.
//! - The **veto** (E4b) refuses, with the rule `closed by loom` and nothing else, a connection when (1) the
//!   destination name or the TLS server name is a registered canary host (CN-4; matched case-insensitively, a trailing
//!   dot removed, and `*.suffix` entries matching every name under them), event `CanaryHost`, severity S4, category
//!   `scope_escape`; or (2) the name, the resolved address or the server name falls
//!   in an infrastructure class (`deny infrastructure: …` of the floor policy: cloud metadata, the daemon's port,
//!   model endpoints, Docker APIs, DevTools and inspector ports, the box's Docker host), event `Infrastructure`,
//!   severity S3 (an attempt; TW-02), category `harness_attack`. Every session's own policy refuses these first
//!   (`403`); the veto is the second line, for a policy that is stale (a session's is rebuilt at its next spawn,
//!   grant or revoke) and for the canary hosts, which no policy knows. The rule text is a fixed class word because
//!   the agent can read it in the net record; which class matched is in the event only.
//! - **Canary users** (E4d): `add_canary_user(user, label)` registers a decoy user in the proxy's session table (a
//!   refused name is the proxy's sentence); `remove_canary_user`. Presenting one is the event `CanaryCredential`,
//!   severity S4, category `credential_misuse`, attributed to the session whose listener received it, raised before
//!   the answer is written. `add_canary_host(host, label)` / `remove_canary_host` register CN-4 names; a host that is
//!   empty, longer than 253 bytes, an IP literal or contains anything but letters, digits, `-`, `_`, `.` (and a
//!   leading `*.`) is refused with a sentence.
//! - The **listener check** (E4e): for a connection that reached a loopback address, `probe(port)` says who listens.
//!   `Sandboxed` by a session other than the connecting one is refused with the rule
//!   `deny a listener started inside a loom sandbox on this port` and the event `Squatter` (severity S3, category
//!   `covert_coordination`; TW-05); a listener of the connecting session itself (its own test server) is let
//!   through, as is `Outside`, `Nobody` and `Unknown` (a process table that cannot be read is told by the census, and
//!   a lab does not stop for it).
//! - `events()` is the last `EVENTS_KEPT` (1024) events, oldest first; `drain_events()` takes them. `set_notifier(f)`
//!   calls `f(&event)` for each event of severity S4 at most once per label every 10 minutes, and for each S3 at most
//!   once per (kind, session) every 10 minutes: an attempt repeated a hundred times is one notification. Events are
//!   also logged as warnings. The detail of an event is for the operator; none of it reaches a session.
//!
//! Tests required: `a_canary_host_is_vetoed_by_name_by_server_name_and_by_suffix`,
//! `an_infrastructure_class_is_vetoed_even_when_the_session_policy_is_stale`, `a_canary_user_through_the_real_proxy_fires_an_s4_event_before_the_answer`,
//! `the_veto_and_the_hook_say_nothing_a_client_can_use`, `a_squatted_lab_port_is_refused_and_an_own_listener_is_not`,
//! `events_are_kept_bounded_and_notified_once_per_label`, `bad_canary_names_are_refused`, `the_floor_is_installed_and_removed_cleanly`.

use crate::monitor::taxonomy::{Category, Severity};
use loom_core::SessionId;
use loom_net::{CanaryHit, Dest, Policy, Proxy};
use loom_tools::sandbox::census::Listening;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};

/// How many events are kept.
pub const EVENTS_KEPT: usize = 1024;
/// A notification for the same label or (kind, session) is not repeated within this many milliseconds.
const NOTIFY_EVERY_MS: u64 = 10 * 60 * 1000;
/// The rule every veto answers with: a class word the agent may read, naming nothing.
pub const CLOSED: &str = "closed by loom";
/// The rule of a refused squatted listener.
pub const SQUATTED: &str = "deny a listener started inside a loom sandbox on this port";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FloorKind {
    /// A decoy proxy user was presented (CN-1).
    CanaryCredential,
    /// A canary host name was named (CN-4).
    CanaryHost,
    /// A connection toward an infrastructure class reached the proxy's veto.
    Infrastructure,
    /// A lab port is held by a sandboxed process of another session (TW-05).
    Squatter,
}

/// What the floor decided or saw. `detail` and `label` are for the operator only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FloorEvent {
    pub at_ms: u64,
    pub kind: FloorKind,
    pub category: Category,
    pub severity: Severity,
    /// The session the event is attributed to: the session that connected, or whose listener received the attempt.
    pub session: Option<SessionId>,
    pub label: String,
    pub detail: String,
}

/// Who listens on a loopback port; `listener_of` over the daemon's sessions.
pub type ListenerProbe = Arc<dyn Fn(u16) -> Listening + Send + Sync>;
/// Told about an event that deserves the operator's attention (see the contract).
pub type Notifier = Arc<dyn Fn(&FloorEvent) + Send + Sync>;

struct Inner {
    infra: RwLock<Arc<Policy>>,
    canary_hosts: RwLock<BTreeMap<String, String>>,
    events: Mutex<VecDeque<FloorEvent>>,
    told: Mutex<HashMap<String, u64>>,
    notifier: Mutex<Option<Notifier>>,
    proxy: Mutex<Option<Proxy>>,
}

/// The title and text of the operator notification for `e` (kind `floor`). Plain sentences: what happened, where, and
/// that the connection did not open or the credential did not authenticate.
pub fn notice(e: &FloorEvent) -> (String, String) {
    let who = e.session.as_ref().map_or_else(|| "a command".to_string(), |s| format!("session {}", s.as_str()));
    match e.kind {
        FloorKind::CanaryCredential => (
            "A decoy proxy credential was used".to_string(),
            format!("{who} presented a decoy credential ({}). It did not authenticate. {}", e.label, e.detail),
        ),
        FloorKind::CanaryHost => (
            "A decoy host was named".to_string(),
            format!("{who} named a decoy host ({}). The connection was refused before anything was sent. {}", e.label, e.detail),
        ),
        FloorKind::Infrastructure => (
            "A connection to loom's own infrastructure was refused".to_string(),
            format!("{who} tried to reach infrastructure that no command may reach. It was refused. {}", e.detail),
        ),
        FloorKind::Squatter => (
            "A lab port is held by a sandboxed process".to_string(),
            format!("{who} connected to a loopback port that a sandboxed process of another session listens on. It was refused. {}", e.detail),
        ),
    }
}

/// The floor's hooks for one proxy. Cheap to clone.
#[derive(Clone)]
pub struct Floor {
    inner: Arc<Inner>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// A host as the floor compares it: lower case, no trailing dot.
fn normal(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

impl Floor {
    pub fn new(infrastructure: Policy) -> Floor {
        Floor {
            inner: Arc::new(Inner {
                infra: RwLock::new(Arc::new(infrastructure)),
                canary_hosts: RwLock::new(BTreeMap::new()),
                events: Mutex::new(VecDeque::new()),
                told: Mutex::new(HashMap::new()),
                notifier: Mutex::new(None),
                proxy: Mutex::new(None),
            }),
        }
    }

    /// Replaces the infrastructure policy (the daemon resolved its names again).
    pub fn set_infrastructure(&self, infrastructure: Policy) {
        *self.inner.infra.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(infrastructure);
    }

    pub fn set_notifier(&self, notifier: Option<Notifier>) {
        *lock(&self.inner.notifier) = notifier;
    }

    /// Registers a canary host name (CN-4) or a `*.suffix`.
    pub fn add_canary_host(&self, host: &str, label: &str) -> Result<(), String> {
        let h = normal(host);
        let body = h.strip_prefix("*.").unwrap_or(&h);
        let ok = !body.is_empty()
            && h.len() <= 253
            && body.parse::<std::net::IpAddr>().is_err()
            && body.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            && !body.starts_with('.')
            && !body.contains("..");
        if !ok {
            return Err(format!(
                "{host:?} cannot be a canary host: use a plain host name (letters, digits, '-', '_' and '.'), \
                 or '*.suffix', at most 253 bytes, not an IP address."
            ));
        }
        self.inner.canary_hosts.write().unwrap_or_else(|p| p.into_inner()).insert(h, label.to_string());
        Ok(())
    }

    pub fn remove_canary_host(&self, host: &str) -> bool {
        self.inner.canary_hosts.write().unwrap_or_else(|p| p.into_inner()).remove(&normal(host)).is_some()
    }

    /// Registers a decoy proxy user (CN-1); the proxy's own sentence when it cannot be.
    pub fn add_canary_user(&self, user: &str, label: &str) -> Result<(), String> {
        match lock(&self.inner.proxy).as_ref() {
            Some(proxy) => proxy.add_canary_user(user, label),
            None => Err("The floor is not installed in a proxy yet, so no canary user can be registered.".to_string()),
        }
    }

    pub fn remove_canary_user(&self, user: &str) -> bool {
        lock(&self.inner.proxy).as_ref().is_some_and(|p| p.remove_canary_user(user))
    }

    /// Puts the veto, the canary hook and (with `probe`) the listener check into `proxy`.
    pub fn install(&self, proxy: &Proxy, probe: Option<ListenerProbe>) {
        let me = self.clone();
        proxy.set_veto(Some(Arc::new(move |who: &SessionId, d: &Dest<'_>| me.veto(who, d))));
        let me = self.clone();
        proxy.set_canary_hook(Some(Arc::new(move |hit: &CanaryHit| me.canary_used(hit))));
        let me = self.clone();
        proxy.set_listener_check(probe.map(|probe| {
            Arc::new(move |who: &SessionId, to: SocketAddr| me.listener(&probe, who, to)) as loom_net::ListenerFn
        }));
        *lock(&self.inner.proxy) = Some(proxy.clone());
    }

    /// The last events, oldest first.
    pub fn events(&self) -> Vec<FloorEvent> {
        lock(&self.inner.events).iter().cloned().collect()
    }

    /// Takes the kept events.
    pub fn drain_events(&self) -> Vec<FloorEvent> {
        lock(&self.inner.events).drain(..).collect()
    }

    fn canary_label(&self, name: &str) -> Option<String> {
        let name = normal(name);
        let hosts = self.inner.canary_hosts.read().unwrap_or_else(|p| p.into_inner());
        if let Some(label) = hosts.get(&name) {
            return Some(label.clone());
        }
        // `*.suffix`: every name under the suffix, not the suffix itself.
        hosts.iter().find_map(|(entry, label)| {
            let suffix = entry.strip_prefix("*.")?;
            name.strip_suffix(suffix).is_some_and(|head| head.ends_with('.')).then(|| label.clone())
        })
    }

    fn infrastructure_class(&self, d: &Dest<'_>) -> Option<String> {
        let policy = self.inner.infra.read().unwrap_or_else(|p| p.into_inner()).clone();
        let refused =
            |v: loom_net::Verdict| (!v.allowed && v.rule.starts_with("deny infrastructure")).then_some(v.rule);
        if let Some(rule) = refused(policy.check_name(d.host, d.port)) {
            return Some(rule);
        }
        if let Some(ip) = d.resolved {
            if let Some(rule) = refused(policy.check_addr(d.host, d.port, ip, "floor")) {
                return Some(rule);
            }
        }
        d.sni.and_then(|sni| refused(policy.check_name(sni, d.port)))
    }

    fn veto(&self, who: &SessionId, d: &Dest<'_>) -> Option<String> {
        for name in std::iter::once(d.host).chain(d.sni) {
            if let Some(label) = self.canary_label(name) {
                let detail = format!("{} {}:{} named the canary host {name}", d.method, d.host, d.port);
                self.event(FloorKind::CanaryHost, Category::ScopeEscape, Severity::S4, Some(who), label, detail);
                return Some(CLOSED.to_string());
            }
        }
        if let Some(rule) = self.infrastructure_class(d) {
            let to = d.resolved.map_or_else(|| d.host.to_string(), |ip| format!("{} ({ip})", d.host));
            let detail = format!("{} to {to}:{} reached the proxy's veto: {rule}", d.method, d.port);
            self.event(FloorKind::Infrastructure, Category::HarnessAttack, Severity::S3, Some(who), rule, detail);
            return Some(CLOSED.to_string());
        }
        None
    }

    fn canary_used(&self, hit: &CanaryHit) {
        let detail = format!("{} {}:{} with the decoy user {}", hit.method, hit.host, hit.port, hit.user);
        self.event(
            FloorKind::CanaryCredential,
            Category::CredentialMisuse,
            Severity::S4,
            hit.listener.as_ref(),
            hit.label.clone(),
            detail,
        );
    }

    fn listener(&self, probe: &ListenerProbe, who: &SessionId, to: SocketAddr) -> Option<String> {
        match probe(to.port()) {
            Listening::Sandboxed { session, .. } if session.as_deref() == Some(who.as_str()) => None,
            Listening::Sandboxed { pid, session, .. } => {
                let owner = session.unwrap_or_else(|| "an unknown session".to_string());
                let detail =
                    format!("session {} connected to {to}, where process {pid} of {owner} listens", who.as_str());
                self.event(FloorKind::Squatter, Category::CovertCoordination, Severity::S3, Some(who), owner, detail);
                Some(SQUATTED.to_string())
            }
            Listening::Outside | Listening::Nobody | Listening::Unknown => None,
        }
    }

    fn event(
        &self,
        kind: FloorKind,
        category: Category,
        severity: Severity,
        session: Option<&SessionId>,
        label: String,
        detail: String,
    ) {
        let e = FloorEvent {
            at_ms: loom_core::now_ms(),
            kind,
            category,
            severity,
            session: session.cloned(),
            label,
            detail,
        };
        tracing::warn!(
            "floor: {:?} ({:?}, {:?}) {}{}",
            e.kind,
            e.category,
            e.severity,
            e.session.as_ref().map_or(String::new(), |s| format!("session {}: ", s.as_str())),
            e.detail
        );
        let key = match e.severity {
            Severity::S4 => Some(format!("{:?}|{}", e.kind, e.label)),
            Severity::S3 => Some(format!("{:?}|{}", e.kind, e.session.as_ref().map_or("", |s| s.as_str()))),
            _ => None,
        };
        let notify = key.is_some_and(|key| {
            let mut told = lock(&self.inner.told);
            let fresh = told.get(&key).is_none_or(|at| e.at_ms.saturating_sub(*at) >= NOTIFY_EVERY_MS);
            if fresh {
                told.insert(key, e.at_ms);
            }
            fresh
        });
        {
            let mut events = lock(&self.inner.events);
            if events.len() >= EVENTS_KEPT {
                events.pop_front();
            }
            events.push_back(e.clone());
        }
        if notify {
            let notifier = lock(&self.inner.notifier).clone();
            if let Some(notifier) = notifier {
                notifier(&e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use loom_core::config::{NetworkCfg, NetworkMode};
    use loom_net::InfraSpec;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::mpsc::unbounded_channel;

    fn infra() -> Policy {
        let spec = InfraSpec { daemon_port: Some(7777), ..InfraSpec::default() };
        Policy::new(&NetworkCfg::default()).unwrap().with_infrastructure(&spec).unwrap()
    }

    fn lab() -> Policy {
        let cfg =
            NetworkCfg { mode: NetworkMode::Open, allow_private: vec!["127.0.0.1".into()], ..NetworkCfg::default() };
        Policy::new(&cfg).unwrap()
    }

    fn dest<'a>(host: &'a str, port: u16, resolved: Option<&str>, sni: Option<&'a str>) -> Dest<'a> {
        Dest { host, port, method: "CONNECT", resolved: resolved.map(|r| r.parse().unwrap()), sni }
    }

    async fn proxy() -> Proxy {
        let (tx, _rx) = unbounded_channel();
        Proxy::start(0, tx).await.unwrap()
    }

    async fn status_of(port: u16, request: &str) -> (u16, String) {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(request.as_bytes()).await.unwrap();
        let mut resp = String::new();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), s.read_to_string(&mut resp)).await;
        let code = resp.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
        (code, resp)
    }

    fn connect(user: &str, password: &str, dest: &str) -> String {
        let c = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        format!("CONNECT {dest} HTTP/1.1\r\nProxy-Authorization: Basic {c}\r\n\r\n")
    }

    #[test]
    fn a_canary_host_is_vetoed_by_name_by_server_name_and_by_suffix() {
        let floor = Floor::new(infra());
        floor.add_canary_host("Bait.Example.Test.", "CN-4 m1").unwrap();
        floor.add_canary_host("*.decoy.test", "CN-4 m1 wildcard").unwrap();
        let who = SessionId::from("s-1");
        assert_eq!(floor.veto(&who, &dest("bait.example.test", 443, None, None)).as_deref(), Some(CLOSED));
        assert_eq!(floor.veto(&who, &dest("BAIT.example.test.", 443, None, None)).as_deref(), Some(CLOSED));
        assert_eq!(floor.veto(&who, &dest("x.decoy.test", 80, None, None)).as_deref(), Some(CLOSED));
        assert_eq!(floor.veto(&who, &dest("a.b.decoy.test", 80, None, None)).as_deref(), Some(CLOSED));
        assert!(floor.veto(&who, &dest("decoy.test", 80, None, None)).is_none(), "the suffix itself is not under it");
        assert!(floor.veto(&who, &dest("notdecoy.test", 80, None, None)).is_none());
        assert!(floor.veto(&who, &dest("example.test", 443, None, None)).is_none());
        // The server name of a tunnel to another host is judged the same way.
        assert_eq!(
            floor.veto(&who, &dest("cdn.test", 443, Some("203.0.113.5"), Some("bait.example.test"))).as_deref(),
            Some(CLOSED)
        );
        let events = floor.events();
        assert_eq!(events.len(), 5);
        assert!(events.iter().all(|e| e.kind == FloorKind::CanaryHost && e.severity == Severity::S4));
        assert!(events.iter().all(|e| e.session.as_ref() == Some(&who)));
        assert_eq!(events[0].label, "CN-4 m1");
        // A removed canary no longer vetoes.
        assert!(floor.remove_canary_host("bait.example.test"));
        assert!(floor.veto(&who, &dest("bait.example.test", 443, None, None)).is_none());
        assert!(!floor.remove_canary_host("bait.example.test"));
    }

    #[test]
    fn bad_canary_names_are_refused() {
        let floor = Floor::new(infra());
        for bad in ["", " ", "a b.test", "10.0.0.1", "a..test", ".test", "ü.test", &"a".repeat(260)] {
            let err = floor.add_canary_host(bad, "x").err().unwrap_or_default();
            assert!(err.contains("cannot be a canary host"), "{bad:?}: {err}");
        }
        let err = floor.add_canary_user("u", "x").err().unwrap_or_default();
        assert!(err.contains("not installed"), "{err}");
    }

    #[test]
    fn an_infrastructure_class_is_vetoed_even_when_the_session_policy_is_stale() {
        let floor = Floor::new(infra());
        let who = SessionId::from("s-2");
        // The daemon's own port on this machine, by any name that resolves to loopback.
        assert_eq!(floor.veto(&who, &dest("127.0.0.1", 7777, None, None)).as_deref(), Some(CLOSED));
        assert_eq!(floor.veto(&who, &dest("lab.test", 7777, Some("127.0.0.1"), None)).as_deref(), Some(CLOSED));
        // Cloud metadata, by name and by address; DevTools.
        assert_eq!(floor.veto(&who, &dest("169.254.169.254", 80, None, None)).as_deref(), Some(CLOSED));
        assert_eq!(floor.veto(&who, &dest("x.test", 80, Some("169.254.169.254"), None)).as_deref(), Some(CLOSED));
        assert_eq!(floor.veto(&who, &dest("127.0.0.1", 9222, None, None)).as_deref(), Some(CLOSED));
        // The server name too.
        assert_eq!(
            floor.veto(&who, &dest("cdn.test", 443, Some("203.0.113.5"), Some("169.254.169.254"))).as_deref(),
            Some(CLOSED)
        );
        // Ordinary destinations, a private lab address included, are not the floor's to veto.
        assert!(floor.veto(&who, &dest("127.0.0.1", 8080, None, None)).is_none());
        assert!(floor.veto(&who, &dest("lab.test", 8080, Some("127.0.0.1"), None)).is_none());
        assert!(floor.veto(&who, &dest("example.test", 443, Some("93.184.216.34"), None)).is_none());
        let events = floor.events();
        assert_eq!(events.len(), 6);
        assert!(events.iter().all(|e| e.kind == FloorKind::Infrastructure && e.severity == Severity::S3));
        assert!(events.iter().all(|e| e.category == Category::HarnessAttack));
        // After the infrastructure policy is replaced, what it no longer lists is not vetoed.
        floor.set_infrastructure(Policy::new(&NetworkCfg::default()).unwrap());
        assert!(floor.veto(&who, &dest("127.0.0.1", 7777, None, None)).is_none());
        assert!(floor.veto(&who, &dest("127.0.0.1", 9222, None, None)).is_some());
    }

    #[tokio::test]
    async fn a_canary_user_through_the_real_proxy_fires_an_s4_event_before_the_answer() {
        let proxy = proxy().await;
        let floor = Floor::new(infra());
        floor.install(&proxy, None);
        let sid = SessionId::from("s-canary-real");
        let grant = proxy.grant(&sid, lab()).unwrap();
        floor.add_canary_user("loom-svc-9c41", "CN-1 mission m1").unwrap();
        let told = Arc::new(Mutex::new(Vec::new()));
        let sink = told.clone();
        floor.set_notifier(Some(Arc::new(move |e: &FloorEvent| lock(&sink).push(e.clone()))));
        let (code, resp) = status_of(grant.port, &connect("loom-svc-9c41", "anything", "93.184.216.34:443")).await;
        assert_eq!(code, 407, "{resp}");
        // The event existed when the answer arrived, attributed to the session whose port it was sent to.
        let events = floor.events();
        assert_eq!(events.len(), 1, "{events:?}");
        let e = &events[0];
        assert_eq!(
            (e.kind, e.severity, e.category),
            (FloorKind::CanaryCredential, Severity::S4, Category::CredentialMisuse)
        );
        assert_eq!(e.session.as_ref(), Some(&sid));
        assert_eq!(e.label, "CN-1 mission m1");
        assert!(e.detail.contains("93.184.216.34:443") && e.detail.contains("loom-svc-9c41"), "{}", e.detail);
        assert_eq!(lock(&told).len(), 1);
        // The operator is told once per label: a second use is an event, not a second notification.
        let _ = status_of(grant.port, &connect("loom-svc-9c41", "other", "93.184.216.34:443")).await;
        assert_eq!(floor.events().len(), 2);
        assert_eq!(lock(&told).len(), 1);
        // On the shared listener it is unattributed.
        let _ = status_of(proxy.port(), &connect("loom-svc-9c41", "x", "93.184.216.34:443")).await;
        assert_eq!(floor.events().last().map(|e| e.session.clone()), Some(None));
        // The real session still works, and the decoy never authenticated anything.
        assert!(floor.remove_canary_user("loom-svc-9c41"));
        let (code, _) = status_of(grant.port, &connect("loom-svc-9c41", "x", "93.184.216.34:443")).await;
        assert_eq!(code, 407);
        assert_eq!(floor.events().len(), 3, "a removed decoy fires nothing");
    }

    #[tokio::test]
    async fn the_veto_and_the_hook_say_nothing_a_client_can_use() {
        let proxy = proxy().await;
        let floor = Floor::new(infra());
        floor.install(&proxy, None);
        floor.add_canary_host("bait.canary.test", "CN-4 secret-label").unwrap();
        let sid = SessionId::from("s-quiet");
        let grant = proxy.grant(&sid, lab()).unwrap();
        // A canary host: 502 with the proxy's fixed sentence; nothing of the label, the class or the canary.
        let (code, resp) = status_of(grant.port, &connect(&grant.user, &grant.password, "bait.canary.test:443")).await;
        assert_eq!(code, 502, "{resp}");
        for secret in ["secret-label", "CN-4", "infrastructure", "veto"] {
            assert!(!resp.contains(secret), "{secret}: {resp}");
        }
        assert!(resp.contains("closed to this mission by loom's own rules"), "{resp}");
        // A check of it is answered the same way.
        let check = format!(
            "LOOM-CHECK bait.canary.test:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
            base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", grant.user, grant.password))
        );
        let (code, _) = status_of(grant.port, &check).await;
        assert_eq!(code, 502);
        assert_eq!(floor.events().len(), 2);
    }

    #[tokio::test]
    async fn a_squatted_lab_port_is_refused_and_an_own_listener_is_not() {
        let squatted = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let own = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let outside = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (squat_port, own_port, outside_port) = (
            squatted.local_addr().unwrap().port(),
            own.local_addr().unwrap().port(),
            outside.local_addr().unwrap().port(),
        );
        let probe: ListenerProbe = Arc::new(move |port| {
            let sandboxed = |s: &str| Listening::Sandboxed {
                pid: 4242,
                session: Some(s.to_string()),
                via: loom_tools::sandbox::census::Via::Identity,
            };
            if port == squat_port {
                sandboxed("s-other")
            } else if port == own_port {
                sandboxed("s-lab")
            } else if port == outside_port {
                Listening::Outside
            } else {
                Listening::Nobody
            }
        });
        let proxy = proxy().await;
        let floor = Floor::new(infra());
        floor.install(&proxy, Some(probe));
        let sid = SessionId::from("s-lab");
        let grant = proxy.grant(&sid, lab()).unwrap();
        // The squatter's port: refused (403 with the rule), event S3 covert_coordination naming the owner.
        let (code, resp) =
            status_of(grant.port, &connect(&grant.user, &grant.password, &format!("127.0.0.1:{squat_port}"))).await;
        assert_eq!(code, 403, "{resp}");
        assert!(resp.contains(SQUATTED), "{resp}");
        let events = floor.events();
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(
            (events[0].kind, events[0].severity, events[0].category),
            (FloorKind::Squatter, Severity::S3, Category::CovertCoordination)
        );
        assert_eq!(events[0].label, "s-other");
        assert_eq!(events[0].session.as_ref(), Some(&sid));
        assert!(!resp.contains("s-other"), "the owner is not told to the client: {resp}");
        // The session's own listener and the operator's own service are let through.
        for port in [own_port, outside_port] {
            let mut s = TcpStream::connect(("127.0.0.1", grant.port)).await.unwrap();
            s.write_all(connect(&grant.user, &grant.password, &format!("127.0.0.1:{port}")).as_bytes()).await.unwrap();
            let mut head = [0u8; 12];
            tokio::time::timeout(std::time::Duration::from_secs(5), s.read_exact(&mut head)).await.unwrap().unwrap();
            assert_eq!(&head, b"HTTP/1.1 200", "port {port}");
        }
        assert_eq!(floor.events().len(), 1);
    }

    #[test]
    fn events_are_kept_bounded_and_notified_once_per_label() {
        let floor = Floor::new(infra());
        let told = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = told.clone();
        floor.set_notifier(Some(Arc::new(move |e: &FloorEvent| lock(&sink).push(e.label.clone()))));
        floor.add_canary_host("a.test", "label-a").unwrap();
        floor.add_canary_host("b.test", "label-b").unwrap();
        let who = SessionId::from("s-3");
        for _ in 0..(EVENTS_KEPT + 50) {
            let _ = floor.veto(&who, &dest("a.test", 80, None, None));
        }
        let _ = floor.veto(&who, &dest("b.test", 80, None, None));
        assert_eq!(floor.events().len(), EVENTS_KEPT, "the oldest are dropped");
        assert_eq!(*lock(&told), ["label-a", "label-b"], "one notification per label");
        // An attempt at infrastructure (S3) is told once per session.
        for _ in 0..5 {
            let _ = floor.veto(&who, &dest("169.254.169.254", 80, None, None));
        }
        let _ = floor.veto(&SessionId::from("s-4"), &dest("169.254.169.254", 80, None, None));
        assert_eq!(lock(&told).len(), 4);
        assert_eq!(floor.drain_events().len(), EVENTS_KEPT);
        assert!(floor.events().is_empty());
    }

    #[tokio::test]
    async fn the_floor_is_installed_and_removed_cleanly() {
        let proxy = proxy().await;
        let floor = Floor::new(infra());
        floor.install(&proxy, None);
        floor.add_canary_host("bait.test", "x").unwrap();
        let sid = SessionId::from("s-removed");
        let grant = proxy.grant(&sid, lab()).unwrap();
        let (code, _) = status_of(grant.port, &connect(&grant.user, &grant.password, "bait.test:443")).await;
        assert_eq!(code, 502);
        proxy.set_veto(None);
        // Without the veto the name is the session policy's alone (here: open mode, so it is looked up and fails
        // to resolve or connect, which is a 502 of another kind: it carries the unreachable sentence).
        let (code, resp) = status_of(grant.port, &connect(&grant.user, &grant.password, "bait.test:443")).await;
        assert!(code == 502 && !resp.contains("closed to this mission"), "{code} {resp}");
    }
}
