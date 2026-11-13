//! Operator-pinned mechanical acceptance checks.
//!
//! CONTRACT: configuration is `<workspace>/.loom/security-oracle.json`, protected from agent writes
//! by the sandbox. It is hash-pinned at first use in each session; subsequent changes require a new
//! session. Unsandboxed mode is refused. Model input is only a candidate BlobStore handle, never
//! an endpoint, expected answer, command, baseline or success rule. A passing receipt states exactly
//! which operator contract passed; it is not a universal proof of exploitability. Clean replay copies
//! only hash-pinned regular files into independent fresh attack/control directories, checks hashes
//! after execution and requires both the attack criterion and the benign control. Timeout/OOM/exit71
//! are never successes. Privilege checks require an HMAC-authenticated external supervisor response,
//! not a PTY marker. Secret keys must be unreadable to agent tools and are never included in receipts.

use crate::{
    params::{opt, spec},
    Body, Tool, ToolCtx, ToolOutput,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use loom_core::config::SandboxMode;
use loom_core::event::{ToolClass, ToolSpec};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::Read,
    os::fd::AsFd,
    os::unix::fs::PermissionsExt,
    path::{Component, Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

pub struct OracleCheck;
#[derive(Default)]
pub struct ContractCache(Mutex<Option<(String, Contract)>>);
#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Contract {
    FlagExact {
        sha256: String,
    },
    SignedSupervisor {
        endpoint: String,
        key_file: PathBuf,
        #[serde(default)]
        require_root: bool,
    },
    CleanReplay {
        files: Vec<PinnedFile>,
        argv: Vec<String>,
        baseline_base64: String,
        attack_exit: i32,
        attack_output_regex: String,
        #[serde(default = "default_control")]
        control_exit: i32,
        #[serde(default = "default_timeout")]
        timeout_s: u64,
    },
    DifferentialHttp {
        attack: Box<crate::http::Request>,
        control: Box<crate::http::Request>,
        success_body_regex: String,
        #[serde(default)]
        normalize_regex: Option<String>,
    },
}
fn default_control() -> i32 {
    0
}
fn default_timeout() -> u64 {
    30
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedFile {
    path: PathBuf,
    sha256: String,
    #[serde(default)]
    executable: bool,
}

fn load(ctx: &ToolCtx) -> Result<(String, Contract), String> {
    let path = ctx.workspace.join(".loom/security-oracle.json");
    let (mut file, meta) = crate::files::open_regular(&path).map_err(|e| {
        format!("The operator must install a protected .loom/security-oracle.json before verification: {e:?}.")
    })?;
    let real = crate::files::real_path(file.as_fd()).map_err(|e| e.to_string())?;
    if ctx.sandbox.check_write(&real).is_ok() {
        return Err("The oracle contract resolves to an actor-writable file. Ask the operator to install a regular protected contract.".into());
    }
    if meta.len() > 128 * 1024 {
        return Err("The oracle contract exceeds 128 KiB; ask the operator to reduce it.".into());
    }
    let mut bytes = Vec::new();
    file.by_ref().take(128 * 1024 + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    let hash = hex::encode(Sha256::digest(&bytes));
    let mut cache = ctx.capabilities.oracle_contract.0.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((pinned, contract)) = cache.as_ref() {
        if pinned != &hash {
            return Err("The operator oracle contract changed during this session. Start a fresh verifier; old receipts cannot establish the new contract.".into());
        }
        return Ok((hash, contract.clone()));
    }
    let contract: Contract =
        serde_json::from_slice(&bytes).map_err(|e| format!("The operator oracle contract is invalid: {e}."))?;
    *cache = Some((hash.clone(), contract.clone()));
    Ok((hash, contract))
}
pub fn contract_digest(ctx: &ToolCtx) -> Result<String, String> {
    load(ctx).map(|(hash, _)| hash)
}

fn relative(path: &Path) -> bool {
    !path.as_os_str().is_empty() && path.components().all(|c| matches!(c, Component::Normal(_)))
}
fn hash_ok(bytes: &[u8], expected: &str) -> bool {
    hex::encode(Sha256::digest(bytes)).eq_ignore_ascii_case(expected)
}
fn read_candidate(ctx: &ToolCtx, handle: &str) -> Result<Vec<u8>, String> {
    let id = ctx.blobs.resolve(handle).map_err(|e| format!("Use a complete candidate output handle: {e}."))?;
    if ctx.blobs.meta(&id).map_err(|e| e.to_string())?.bytes > 1_000_000 {
        return Err("Candidate exceeds one million bytes; store only the flag or PoC input in its blob.".into());
    }
    let bytes = ctx.blobs.read_all(&id).map_err(|e| e.to_string())?;
    if bytes.len() > 1_000_000 {
        return Err("Candidate exceeds one million bytes; store only the flag or PoC input in its blob.".into());
    }
    Ok(bytes)
}

fn read_candidate_file(ctx: &ToolCtx, given: &str) -> Result<Vec<u8>, String> {
    let path = ctx.sandbox.resolve(given);
    let judge = |p: &Path| ctx.sandbox.check_read(p).map(|_| ());
    let (mut file, meta) = crate::files::open_readable(&path, &judge)
        .map_err(|e| format!("Use a readable regular candidate file: {e:?}."))?;
    if meta.len() > 1_000_000 {
        return Err("Candidate file exceeds one million bytes.".into());
    }
    let mut bytes = Vec::new();
    file.by_ref().take(1_000_001).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() > 1_000_000 {
        return Err("Candidate file grew beyond its one-million-byte limit.".into());
    }
    ctx.files.note(&path, &bytes);
    Ok(bytes)
}

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn snapshot(ctx: &ToolCtx, files: &[PinnedFile], input: &[u8]) -> Result<Scratch, String> {
    if files.is_empty() || files.len() > 128 {
        return Err("Clean replay requires 1..128 operator-pinned files.".into());
    }
    let parent = ctx.sandbox.oracle_staging_root();
    let dir = parent.join(format!("oracle-{:032x}", rand::random::<u128>()));
    loom_core::config::ensure_private_dir(&dir).map_err(|e| e.to_string())?;
    let scratch = Scratch(dir);
    loom_core::config::ensure_private_dir(&scratch.0.join("workspace")).map_err(|e| e.to_string())?;
    loom_core::config::ensure_private_dir(&scratch.0.join("tmp")).map_err(|e| e.to_string())?;
    let mut total = 0u64;
    let mut seen = BTreeSet::new();
    for f in files {
        if !relative(&f.path) || !seen.insert(f.path.clone()) || f.path == Path::new(".loom-candidate") {
            return Err("Pinned files must have distinct normal relative paths, excluding .loom-candidate.".into());
        }
        let source = ctx.workspace.join(&f.path);
        let judge = |p: &Path| ctx.sandbox.check_read(p).map(|_| ());
        let (mut file, meta) = crate::files::open_readable(&source, &judge)
            .map_err(|e| format!("Cannot open pinned target {}: {e:?}.", source.display()))?;
        total = total.saturating_add(meta.len());
        if total > 256 * 1024 * 1024 || meta.len() > 64 * 1024 * 1024 {
            return Err("Clean replay exceeds its 256 MiB total/64 MiB file limit.".into());
        }
        let mut bytes = Vec::new();
        file.by_ref().take(64 * 1024 * 1024 + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        if !hash_ok(&bytes, &f.sha256) {
            return Err(format!(
                "Target {} differs from the operator's pinned hash; restore a clean target before verifying.",
                f.path.display()
            ));
        }
        let target = scratch.0.join("workspace").join(&f.path);
        if let Some(p) = target.parent() {
            std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        std::fs::write(&target, &bytes).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(if f.executable { 0o500 } else { 0o400 }))
            .map_err(|e| e.to_string())?;
    }
    std::fs::write(scratch.0.join("workspace/.loom-candidate"), input).map_err(|e| e.to_string())?;
    Ok(scratch)
}
fn unchanged(dir: &Path, files: &[PinnedFile]) -> bool {
    files.iter().all(|f| {
        let path = dir.join(&f.path);
        let Ok(meta) = std::fs::symlink_metadata(&path) else { return false };
        if !meta.is_file() || meta.len() > 64 * 1024 * 1024 {
            return false;
        }
        std::fs::read(path).is_ok_and(|b| hash_ok(&b, &f.sha256))
    })
}

async fn replay(
    ctx: &ToolCtx,
    files: &[PinnedFile],
    argv: &[String],
    input: &[u8],
    timeout: u64,
) -> Result<Value, String> {
    if argv.is_empty() || argv.len() > 32 || argv.iter().any(|a| a.len() > 8192) {
        return Err("The operator replay argv must have 1..32 bounded arguments.".into());
    }
    let dir = snapshot(ctx, files, input)?;
    let workspace = dir.0.join("workspace");
    let tmp = dir.0.join("tmp");
    let sandbox = ctx.sandbox.isolated_replay(&workspace, &tmp)?;
    let mut isolated = ctx.clone();
    isolated.workspace = workspace.clone();
    isolated.tmp_dir = tmp;
    isolated.sandbox = std::sync::Arc::new(sandbox);
    let mut expanded = argv
        .iter()
        .map(|a| {
            a.replace("{input}", &workspace.join(".loom-candidate").to_string_lossy())
                .replace("{snapshot}", &workspace.to_string_lossy())
        })
        .collect::<Vec<_>>();
    let executable = checked_executable(&isolated, files, expanded.first().map(String::as_str).unwrap_or_default())?;
    if let Some(first) = expanded.first_mut() {
        *first = executable.to_string_lossy().into_owned();
    }
    let args = expanded.iter().map(|a| crate::binary::quote(a)).collect::<Vec<_>>().join(" ");
    let script = format!("cd {} && {args}", crate::binary::quote(&workspace.to_string_lossy()));
    let result = crate::binary::command(&isolated, script, timeout).await?;
    let completed = result.completed;
    let stop_reason = result.stop_reason;
    let bytes = result.bytes;
    let status = result.ended;
    let code = match status {
        crate::proc::Ended::Exit(n) => Some(n),
        _ => None,
    };
    let clean = unchanged(&workspace, files);
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let disqualified = !completed
        || code == Some(71)
        || text.contains("ERROR: libFuzzer: out-of-memory")
        || text.contains("AddressSanitizer: out of memory");
    Ok(
        json!({"exit_code":code,"target_unchanged":clean,"disqualified":disqualified,"stop_reason":stop_reason,"output":text}),
    )
}

/// Resolve the executable without PATH lookup. A target is a manifest-pinned file; an external
/// interpreter must resolve to a regular, readable, actor-inaccessible host file under replay policy.
fn checked_executable(ctx: &ToolCtx, files: &[PinnedFile], given: &str) -> Result<PathBuf, String> {
    let path = Path::new(given);
    let local = if path.is_absolute() {
        path.strip_prefix(&ctx.workspace).ok()
    } else {
        Some(path.strip_prefix(".").unwrap_or(path))
    };
    if let Some(relative_path) = local {
        if !relative(relative_path) || !files.iter().any(|f| f.path == relative_path) {
            return Err("The replay executable must be a manifest-pinned target or an absolute immutable interpreter path; PATH lookup is refused.".into());
        }
        return Ok(ctx.workspace.join(relative_path));
    }
    let judge = |p: &Path| ctx.sandbox.check_read(p).map(|_| ());
    let (file, meta) = crate::files::open_readable(path, &judge).map_err(|e| {
        format!("The replay interpreter must be a readable regular file outside actor-writable roots: {e:?}.")
    })?;
    let real = crate::files::real_path(file.as_fd()).map_err(|e| e.to_string())?;
    if ctx.sandbox.check_write(&real).is_ok() || meta.permissions().mode() & 0o111 == 0 {
        return Err("The replay interpreter is writable or not executable. Pin a target or choose an immutable absolute interpreter.".into());
    }
    Ok(real)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedAnswer {
    nonce: String,
    candidate_sha256: String,
    accepted: bool,
    uid: Option<u64>,
    admin_enabled: Option<bool>,
    mac: String,
}
fn signed_message(a: &SignedAnswer) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}",
        a.nonce,
        a.candidate_sha256,
        a.accepted,
        a.uid.map(|n| n.to_string()).unwrap_or_default(),
        a.admin_enabled.map(|v| v.to_string()).unwrap_or_default()
    )
}
fn authenticate(a: &SignedAnswer, nonce: &str, candidate: &str, key: &[u8]) -> bool {
    if a.nonce != nonce || a.candidate_sha256 != candidate {
        return false;
    }
    let Ok(mac) = hex::decode(&a.mac) else { return false };
    let Ok(mut h) = Hmac::<Sha256>::new_from_slice(key) else { return false };
    h.update(signed_message(a).as_bytes());
    h.verify_slice(&mac).is_ok()
}

async fn check(ctx: &ToolCtx, contract: Contract, candidate: &[u8]) -> Result<Value, String> {
    Ok(match contract {
        Contract::FlagExact { sha256 } => {
            let flag = std::str::from_utf8(candidate).map_err(|_| "Flag candidate must be UTF-8.")?.trim();
            json!({"passed":hash_ok(flag.as_bytes(),&sha256),"kind":"flag_exact","measurement":"exact match to operator-pinned flag hash"})
        }
        Contract::SignedSupervisor { endpoint, key_file, require_root } => {
            let key_path = if key_file.is_absolute() { key_file } else { ctx.workspace.join(key_file) };
            if ctx.sandbox.check_read(&key_path).is_ok() {
                return Err("Supervisor key must be in an agent-unreadable path (for example .loom/oracle-secrets/key). Ask the operator to protect it before verifying.".into());
            }
            let (mut key, meta) =
                crate::files::open_regular(&key_path).map_err(|e| format!("Cannot read supervisor key: {e:?}."))?;
            if meta.len() > 4096 {
                return Err("Supervisor key exceeds 4096 bytes.".into());
            }
            let real = crate::files::real_path(key.as_fd()).map_err(|e| e.to_string())?;
            if ctx.sandbox.check_read(&real).is_ok() {
                return Err(
                    "The supervisor key resolves to an agent-readable file; protect the actual key before verifying."
                        .into(),
                );
            }
            let mut bytes = Vec::new();
            key.by_ref().take(4097).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
            if bytes.len() > 4096 {
                return Err("Supervisor key grew beyond its limit.".into());
            }
            if bytes.len() < 32 {
                return Err("Use a supervisor HMAC key of at least 32 bytes.".into());
            }
            let nonce = format!("{:032x}", rand::random::<u128>());
            let candidate_hash = hex::encode(Sha256::digest(candidate));
            let r:crate::http::Request=serde_json::from_value(json!({"url":endpoint,"method":"POST","json":{"nonce":nonce,"candidate_sha256":candidate_hash,"candidate_base64":STANDARD.encode(candidate)}})).map_err(|e|e.to_string())?;
            let client = crate::http::client(ctx, Default::default())?;
            let exchange = crate::http::one(ctx, &client, &r).await?;
            if exchange.truncated || exchange.read_error.is_some() || exchange.status != 200 {
                return Err("The trusted supervisor did not return a complete HTTP 200 response.".into());
            }
            let answer: SignedAnswer = serde_json::from_str(&exchange.body_text)
                .map_err(|e| format!("Supervisor response schema failed: {e}."))?;
            let authentic = authenticate(&answer, &nonce, &candidate_hash, &bytes);
            let privileged = answer.uid == Some(0) || answer.admin_enabled == Some(true);
            json!({"passed":authentic&&answer.accepted&&(!require_root||privileged),"kind":"signed_supervisor","signature_valid":authentic,"uid":answer.uid,"admin_enabled":answer.admin_enabled,"measurement":"operator-trusted supervisor, nonce/candidate bound HMAC; no PTY identity inference"})
        }
        Contract::CleanReplay {
            files,
            argv,
            baseline_base64,
            attack_exit,
            attack_output_regex,
            control_exit,
            timeout_s,
        } => {
            if attack_exit == 71 || attack_exit == control_exit {
                return Err("Attack and control exit criteria must differ; exit 71 is disqualified.".into());
            }
            let re =
                regex::Regex::new(&attack_output_regex).map_err(|e| format!("Invalid attack output regex: {e}."))?;
            if attack_output_regex.trim().is_empty() {
                return Err("Clean replay needs a target-specific attack output criterion.".into());
            }
            let baseline = STANDARD.decode(baseline_base64).map_err(|e| e.to_string())?;
            if baseline.len() > 1_000_000 {
                return Err("Baseline exceeds one million bytes.".into());
            }
            let attack = replay(ctx, &files, &argv, candidate, timeout_s).await?;
            let control = replay(ctx, &files, &argv, &baseline, timeout_s).await?;
            let passed = attack["exit_code"] == attack_exit
                && control["exit_code"] == control_exit
                && attack["target_unchanged"] == true
                && control["target_unchanged"] == true
                && attack["disqualified"] == false
                && control["disqualified"] == false
                && re.is_match(attack["output"].as_str().unwrap_or_default())
                && !re.is_match(control["output"].as_str().unwrap_or_default());
            json!({"passed":passed,"kind":"clean_replay","attack":attack,"control":control,"measurement":"independent fresh hash-pinned snapshots; operator-defined exit/output criteria"})
        }
        Contract::DifferentialHttp { mut attack, mut control, success_body_regex, normalize_regex } => {
            let candidate = std::str::from_utf8(candidate).map_err(|_| "HTTP differential candidate must be UTF-8.")?;
            attack.body = attack.body.replace("{{candidate}}", candidate);
            control.body = control.body.replace("{{candidate}}", candidate);
            let re = regex::Regex::new(&success_body_regex).map_err(|e| e.to_string())?;
            if success_body_regex.trim().is_empty() {
                return Err("Differential contract requires an operator-pinned success-body criterion.".into());
            }
            let client = crate::http::client(ctx, Default::default())?;
            let control_client = crate::http::client(ctx, Default::default())?;
            let a = crate::http::one(ctx, &client, &attack).await?;
            let c = crate::http::one(ctx, &control_client, &control).await?;
            let normalize = normalize_regex.map(|s| regex::Regex::new(&s)).transpose().map_err(|e| e.to_string())?;
            let normalized = |s: &str| {
                normalize.as_ref().map(|r| r.replace_all(s, "ID").into_owned()).unwrap_or_else(|| s.to_string())
            };
            let atext = normalized(&a.body_text);
            let ctext = normalized(&c.body_text);
            let aset: BTreeSet<_> = atext.split_whitespace().collect();
            let cset: BTreeSet<_> = ctext.split_whitespace().collect();
            let union = aset.union(&cset).count();
            let similarity = if union == 0 { 1.0 } else { aset.intersection(&cset).count() as f64 / union as f64 };
            json!({"passed":(200..300).contains(&a.status)&&[401,403,404].contains(&c.status)&&!a.truncated&&!c.truncated&&!a.proxy_generated&&!c.proxy_generated&&a.read_error.is_none()&&c.read_error.is_none()&&re.is_match(&a.body_text)&&!re.is_match(&c.body_text),"kind":"differential_http","attack_status":a.status,"control_status":c.status,"body_jaccard":similarity,"measurement":"operator-pinned requests and body criterion with independent denied control; similarity alone never accepts"})
        }
    })
}

#[async_trait]
impl Tool for OracleCheck {
    fn spec(&self) -> ToolSpec {
        spec("oracle_check","Evaluate a candidate against the operator's protected .loom/security-oracle.json contract. No model-supplied expected answer, endpoint, command or success rule. Passing results establish that contract only; unsupported/unconfigured checks fail closed.",ToolClass::Exec,&[opt("candidate","string","BlobStore handle containing only the candidate flag or PoC input; mutually exclusive with candidate_file."),opt("candidate_file","string","Readable regular candidate file (up to one million bytes); mutually exclusive with candidate.")])
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        if ctx.sandbox.mode() == SandboxMode::None {
            return ToolOutput::denied("Mechanical security verification requires an enforced OS sandbox. Unsandboxed mode cannot protect the oracle contract from the actor.");
        }
        let (hash, contract) = match load(ctx) {
            Ok(v) => v,
            Err(e) => return ToolOutput::error(e),
        };
        let candidate_handle = args.get("candidate").and_then(Value::as_str).unwrap_or_default();
        let given_file = args.get("candidate_file").and_then(Value::as_str);
        if candidate_handle.is_empty() == given_file.is_none() {
            return ToolOutput::error("Supply exactly one candidate output handle or candidate_file path.");
        }
        let candidate = match if let Some(path) = given_file {
            read_candidate_file(ctx, path)
        } else {
            read_candidate(ctx, candidate_handle)
        } {
            Ok(v) => v,
            Err(e) => return ToolOutput::error(e),
        };
        let result = tokio::select! {biased;_=ctx.cancel.cancelled()=>return ToolOutput::error("Oracle check cancelled; no acceptance receipt was issued."),v=tokio::time::timeout(Duration::from_secs(125),check(ctx,contract,&candidate))=>v};
        let mut value = match result {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return ToolOutput::error(e),
            Err(_) => return ToolOutput::error("Oracle timed out; no acceptance receipt was issued."),
        };
        value["contract_sha256"] = json!(hash);
        value["candidate_sha256"] = json!(hex::encode(Sha256::digest(&candidate)));
        value["candidate_handle"] = json!(candidate_handle);
        value["candidate_file"] = json!(given_file);
        value["session"] = json!(ctx.session);
        value["call_id"] = json!(ctx.call_id);
        value["receipt_nonce"] = json!(format!("{:032x}", rand::random::<u128>()));
        let passed = value["passed"] == true;
        ToolOutput::ok(
            if passed { "operator oracle passed" } else { "operator oracle did not pass" },
            Body::Raw(value.to_string().into_bytes()),
        )
        .with_meta("oracle_passed", json!(passed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nonce_candidate_and_signature_are_all_required() {
        let key = b"01234567890123456789012345678901";
        let mut a = SignedAnswer {
            nonce: "nonce".into(),
            candidate_sha256: "candidate".into(),
            accepted: true,
            uid: Some(0),
            admin_enabled: None,
            mac: String::new(),
        };
        let mut m = Hmac::<Sha256>::new_from_slice(key).unwrap();
        m.update(signed_message(&a).as_bytes());
        a.mac = hex::encode(m.finalize().into_bytes());
        assert!(authenticate(&a, "nonce", "candidate", key));
        assert!(!authenticate(&a, "old", "candidate", key));
        a.uid = Some(1000);
        assert!(!authenticate(&a, "nonce", "candidate", key));
    }
    #[tokio::test]
    async fn candidate_text_does_not_self_attest() {
        let env = crate::testutil::env();
        let c = Contract::FlagExact { sha256: hex::encode(Sha256::digest(b"flag{correct}")) };
        assert_eq!(check(&env.ctx, c.clone(), b"Goal met flag{fake}").await.unwrap()["passed"], false);
        assert_eq!(check(&env.ctx, c, b"flag{correct}\n").await.unwrap()["passed"], true);
    }
    #[tokio::test]
    async fn proxy_denied_control_is_not_an_authorization_control() {
        use axum::{
            body::Body as HttpBody,
            http::{Request, StatusCode},
            routing::any,
            Router,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().fallback(any(|r: Request<HttpBody>| async move {
            if r.uri().path() == "/control" {
                (StatusCode::FORBIDDEN, [("x-loom-proxy", "1")], "denied by proxy")
            } else {
                (StatusCode::OK, [("x-loom-proxy", "0")], "accepted_canary")
            }
        }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut env = crate::testutil::env();
        env.ctx.env =
            std::sync::Arc::new(std::collections::BTreeMap::from([("HTTP_PROXY".into(), format!("http://{addr}"))]));
        let request =
            |path: &str| Box::new(serde_json::from_value(json!({"url":format!("http://target.test/{path}")})).unwrap());
        let result = check(
            &env.ctx,
            Contract::DifferentialHttp {
                attack: request("attack"),
                control: request("control"),
                success_body_regex: "accepted_canary".into(),
                normalize_regex: None,
            },
            b"candidate",
        )
        .await
        .unwrap();
        assert_eq!(result["attack_status"], 200);
        assert_eq!(result["control_status"], 403);
        assert_eq!(result["passed"], false);
        server.abort();
    }
    #[test]
    fn contract_change_refuses_and_snapshot_hash_is_checked() {
        let env = crate::testutil::env();
        std::fs::create_dir_all(env.ctx.workspace.join(".loom")).unwrap();
        let p = env.ctx.workspace.join(".loom/security-oracle.json");
        std::fs::write(&p, json!({"kind":"flag_exact","sha256":"a"}).to_string()).unwrap();
        load(&env.ctx).unwrap();
        std::fs::write(p, json!({"kind":"flag_exact","sha256":"b"}).to_string()).unwrap();
        assert!(load(&env.ctx).is_err());
        std::fs::write(env.ctx.workspace.join("target"), b"changed").unwrap();
        assert!(snapshot(
            &env.ctx,
            &[PinnedFile {
                path: "target".into(),
                sha256: hex::encode(Sha256::digest(b"original")),
                executable: false
            }],
            b"candidate"
        )
        .is_err());
    }
    #[tokio::test]
    async fn replay_uses_separate_clean_control() {
        let linux = cfg!(target_os = "linux")
            && Path::new("/usr/bin/bwrap").exists()
            && std::env::var_os("LOOM_BWRAP_REQUIRED").is_some();
        if !Path::new("/usr/bin/sandbox-exec").exists() && !linux {
            return;
        }
        let mut env = crate::testutil::env();
        let home = env.dir.path().canonicalize().unwrap().join("home");
        let tmp = home.join("sessions/s-oracle/tmp");
        loom_core::config::ensure_private_dir(&tmp).unwrap();
        std::fs::create_dir_all(env.ctx.workspace.join(".loom")).unwrap();
        let mut cfg = loom_core::config::SandboxCfg::default();
        if linux {
            cfg.mode = SandboxMode::Bubblewrap;
        }
        env.ctx.sandbox =
            std::sync::Arc::new(crate::sandbox::Sandbox::new(&cfg, &env.ctx.workspace, &tmp, &home, None).unwrap());
        env.ctx.tmp_dir = tmp;
        let script = b"#!/bin/bash\nif grep -q attack \"$1\"; then echo target_sink_failure; exit 139; fi\nexit 0\n";
        std::fs::write(env.ctx.workspace.join("target"), script).unwrap();
        let c = Contract::CleanReplay {
            files: vec![PinnedFile {
                path: "target".into(),
                sha256: hex::encode(Sha256::digest(script)),
                executable: true,
            }],
            argv: vec!["./target".into(), "{input}".into()],
            baseline_base64: STANDARD.encode(b"benign"),
            attack_exit: 139,
            attack_output_regex: "target_sink_failure".into(),
            control_exit: 0,
            timeout_s: 2,
        };
        assert_eq!(check(&env.ctx, c, b"attack").await.unwrap()["passed"], true);
    }
}
