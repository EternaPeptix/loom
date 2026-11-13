//! Bounded binary inspection and optional local CLI adapters.
//!
//! CONTRACT: survey reads a descriptor-checked regular file (<=64 MiB), reports ELF/PE/Mach metadata
//! indicators separately from unverified runtime mitigations, and identifies universal Mach containers.
//! Unknown facts remain unknown; no guessed mitigation. Optional rizin decompilation/xrefs are bounded, content-hash
//! cached per query, sandboxed, and fail with installation guidance when the backend is absent.
//! They do not install/launch a daemon or modify targets. gdb_probe disables startup/auto-load files,
//! runs under the same sandbox with timeout/output/cancellation limits, and labels its observation as
//! debugger output rather than an independent privilege/success oracle. Backends use descriptor-hashed
//! staging outside actor write grants. Unconfined mode is explicitly labelled and never cached.
//! Every readable process observation, including failure/cancellation/timeout/limit prefixes, is Raw
//! output with completion/termination metadata. Read failures retain the protected output file.
//! ProducedView stores and indexes full normalized decompiler output while showing at most 120 lines.

use crate::{
    params::{opt, req, spec},
    Body, Tool, ToolCtx, ToolOutput,
};
use async_trait::async_trait;
use goblin::Object;
use loom_core::event::{ToolClass, ToolSpec, ToolStatus};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

pub struct BinSurvey;
pub struct BinDecompile;
pub struct BinXrefs;
pub struct GdbProbe;

pub(crate) fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
fn read_binary(ctx: &ToolCtx, given: &str) -> Result<(PathBuf, Vec<u8>, String), String> {
    let path = ctx.sandbox.resolve(given);
    let judge = |p: &Path| ctx.sandbox.check_read(p).map(|_| ());
    let (mut file, meta) = crate::files::open_readable(&path, &judge)
        .map_err(|e| format!("Cannot inspect {}: {e:?}. Use a readable regular file.", path.display()))?;
    if meta.len() > 64 * 1024 * 1024 {
        return Err("Binary exceeds the 64 MiB inspection limit; use a smaller extracted module.".into());
    }
    let mut bytes = Vec::new();
    file.by_ref().take(64 * 1024 * 1024 + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err("The binary grew beyond the inspection limit while being read.".into());
    }
    ctx.files.note(&path, &bytes);
    let hash = hex::encode(Sha256::digest(&bytes));
    Ok((path, bytes, hash))
}

fn survey(bytes: &[u8]) -> Result<Value, String> {
    let mut v = match Object::parse(bytes).map_err(|e| format!("Binary parse failed: {e}."))? {
        Object::Elf(elf) => {
            use goblin::elf::{header, program_header as ph};
            let imports: Vec<_> = elf
                .dynsyms
                .iter()
                .filter(|s| s.st_shndx == 0)
                .filter_map(|s| elf.dynstrtab.get_at(s.st_name))
                .filter(|s| !s.is_empty())
                .collect();
            let exports: Vec<_> = elf
                .dynsyms
                .iter()
                .filter(|s| s.st_shndx != 0 && s.is_function())
                .filter_map(|s| elf.dynstrtab.get_at(s.st_name))
                .take(40)
                .collect();
            let mut functions: Vec<_> = elf
                .syms
                .iter()
                .filter(|s| s.is_function() && s.st_size > 0)
                .filter_map(|s| {
                    elf.strtab.get_at(s.st_name).map(|name| {
                        (s.st_size, json!({"name":name,"address":format!("0x{:x}",s.st_value),"bytes":s.st_size}))
                    })
                })
                .collect();
            functions.sort_by_key(|b| std::cmp::Reverse(b.0));
            let mut grouped: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
            for name in &imports {
                let group = if ["exec", "system", "spawn"].iter().any(|p| name.contains(p)) {
                    "exec"
                } else if ["socket", "connect", "send", "recv", "listen"].iter().any(|p| name.contains(p)) {
                    "net"
                } else if ["crypt", "SHA", "EVP_", "AES"].iter().any(|p| name.contains(p)) {
                    "crypto"
                } else if ["alloc", "free"].iter().any(|p| name.contains(p)) {
                    "heap"
                } else if ["open", "read", "write", "stat"].iter().any(|p| name.contains(p)) {
                    "fs"
                } else {
                    "other"
                };
                let list = grouped.entry(group).or_default();
                if list.len() < 20 {
                    list.push(name);
                }
            }
            let stack =
                elf.program_headers.iter().find(|p| p.p_type == ph::PT_GNU_STACK).map(|p| p.p_flags & ph::PF_X == 0);
            let relro = elf.program_headers.iter().any(|p| p.p_type == ph::PT_GNU_RELRO);
            let shared = elf.header.e_type == header::ET_DYN && elf.entry == 0;
            let constructors: Vec<_> = elf
                .section_headers
                .iter()
                .filter(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".init_array"))
                .map(|s| json!({"address":format!("0x{:x}",s.sh_addr),"bytes":s.sh_size}))
                .collect();
            json!({"format":"ELF","bits":if elf.is_64{64}else{32},"entry":format!("0x{:x}",elf.entry),"shared_library":shared,
                "entry_strategy":if shared{"exports and init_array before main"}else{"entrypoint and functions"},"nx_stack":stack,"position_independent":elf.header.e_type==header::ET_DYN,
                "gnu_relro_segment":relro,"relro_binding":"unknown; segment presence alone does not establish full RELRO","stack_canary_import":imports.iter().any(|s|s.contains("__stack_chk_fail")),"seccomp":"unknown (requires runtime verification)",
                "exports":exports,"constructors":constructors,"functions_by_size":functions.into_iter().take(15).map(|(_,v)|v).collect::<Vec<_>>(),"imports":grouped,"xref_ranking":"not inferred by the static survey; use bin_xrefs with rizin"})
        }
        Object::PE(pe) => {
            use goblin::pe::dll_characteristic as flags;
            let dll = pe.header.optional_header.as_ref().map(|h| h.windows_fields.dll_characteristics);
            json!({"format":"PE","bits":if pe.is_64{64}else{32},"entry_rva":format!("0x{:x}",pe.entry),"image_base":format!("0x{:x}",pe.image_base),"shared_library":pe.is_lib,
                "entry_strategy":if pe.is_lib{"exports and DLL entrypoint before main"}else{"entrypoint and exports; no main assumption"},
                "nx_compatible_flag":dll.map(|n|n&flags::IMAGE_DLLCHARACTERISTICS_NX_COMPAT!=0),"dynamic_base_flag":dll.map(|n|n&flags::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE!=0),"control_flow_guard_flag":dll.map(|n|n&flags::IMAGE_DLLCHARACTERISTICS_GUARD_CF!=0),"runtime_mitigations":"unverified; header flags are metadata indicators only",
                "imports":pe.imports.iter().take(40).map(|i|json!({"name":i.name.to_string(),"library":i.dll})).collect::<Vec<_>>(),"exports":pe.exports.iter().filter_map(|e|e.name).take(40).collect::<Vec<_>>(),"libraries":pe.libraries.iter().take(40).collect::<Vec<_>>()})
        }
        Object::Mach(goblin::mach::Mach::Binary(mach)) => {
            use goblin::mach::header as flags;
            let shared = matches!(mach.header.filetype, flags::MH_DYLIB | flags::MH_BUNDLE | flags::MH_DYLIB_STUB);
            let imports = mach
                .imports()
                .map(|v| v.into_iter().take(40).map(|i| json!({"name":i.name,"library":i.dylib})).collect::<Vec<_>>())
                .ok();
            let exports = mach.exports().map(|v| v.into_iter().take(40).map(|e| e.name).collect::<Vec<_>>()).ok();
            json!({"format":"Mach-O","bits":if mach.is_64{64}else{32},"entry":format!("0x{:x}",mach.entry),"shared_library":shared,"pie_flag":mach.header.flags&flags::MH_PIE!=0,"allow_stack_execution_flag":mach.header.flags&flags::MH_ALLOW_STACK_EXECUTION!=0,
                "entry_strategy":if shared{"exports and constructors before main"}else{"entrypoint and exports; no main assumption"},"runtime_mitigations":"unverified; Mach header flags are metadata indicators only","imports":imports,"exports":exports,"libraries":mach.libs.iter().take(40).collect::<Vec<_>>()})
        }
        Object::Mach(goblin::mach::Mach::Fat(fat)) => {
            json!({"format":"Mach-O universal","architectures":fat.narches,"entry_strategy":"extract the intended architecture before decompiling","mitigations":"unknown until an architecture is selected"})
        }
        _ => {
            return Err(
                "This object format is not an executable ELF, PE or Mach-O file. Extract the target object first."
                    .into(),
            )
        }
    };
    let strings: Vec<_> = bytes
        .split(|b| !b.is_ascii_graphic() && *b != b' ')
        .filter(|s| (6..=160).contains(&s.len()))
        .map(String::from_utf8_lossy)
        .filter(|s| {
            ["flag", "password", "/bin/", "http", "usage", "%s"].iter().any(|p| s.to_ascii_lowercase().contains(p))
        })
        .take(40)
        .map(|s| s.into_owned())
        .collect();
    v["interesting_strings"] = json!(strings);
    Ok(v)
}

/// A completed observation, including partial output from a command the harness stopped. Only
/// failures before a readable observation exists use Err; backend failures retain their bytes.
#[derive(Clone, Debug)]
pub(crate) struct CommandOutcome {
    pub bytes: Vec<u8>,
    pub ended: crate::proc::Ended,
    pub completed: bool,
    pub stop_reason: Option<&'static str>,
    pub written: u64,
}
impl CommandOutcome {
    pub fn success(&self) -> bool {
        self.completed && self.ended == crate::proc::Ended::Exit(0)
    }
    pub fn into_tool_output(self, label: &str) -> ToolOutput {
        let status = if self.success() {
            ToolStatus::Ok
        } else {
            match self.stop_reason {
                Some("cancelled") => ToolStatus::Interrupted,
                Some("timeout") => ToolStatus::Timeout,
                _ => ToolStatus::Error,
            }
        };
        let mut meta = Map::new();
        meta.insert("analysis_completed".into(), json!(self.completed));
        meta.insert("analysis_stop_reason".into(), json!(self.stop_reason));
        meta.insert("analysis_written_bytes".into(), json!(self.written));
        meta.insert("analysis_truncated".into(), json!(self.written > self.bytes.len() as u64));
        match self.ended {
            crate::proc::Ended::Exit(n) => {
                meta.insert(loom_core::event::META_EXIT_CODE.into(), json!(n));
            }
            crate::proc::Ended::Signal(n) => {
                meta.insert(loom_core::event::META_SIGNAL.into(), json!(n));
            }
            _ => {}
        }
        let mut more = Vec::new();
        if let Some(why) = self.stop_reason {
            more.push(format!(
                "analysis stopped: {why}; partial output is stored and does not establish a completed run"
            ));
        }
        if self.written > self.bytes.len() as u64 {
            more.push(format!(
                "{} of {} written bytes retained under the output limit; the remainder was discarded",
                self.bytes.len(),
                self.written
            ));
        }
        ToolOutput {
            status,
            outcome: format!("{label}: {}", self.ended.outcome()),
            more,
            body: Body::Raw(self.bytes),
            meta,
        }
    }
}

pub(crate) async fn command(ctx: &ToolCtx, script: String, seconds: u64) -> Result<CommandOutcome, String> {
    use crate::proc::{self, Spawn, WaitEnd};
    let (_, out_path, exit_path) = ctx.jobs.allocate().await.map_err(|e| e.to_string())?;
    let parent = std::env::vars().collect();
    let mut env = ctx.sandbox.env(&parent);
    env.extend(ctx.env.iter().map(|(k, v)| (k.clone(), v.clone())));
    // Trusted analysis/oracle launchers must not source actor-controlled interpreter hooks,
    // even when the operator's general shell environment forwards them for ordinary bash calls.
    env.retain(|key, _| {
        let key = key.to_ascii_uppercase();
        ![
            "BASH_ENV",
            "ENV",
            "BASHOPTS",
            "SHELLOPTS",
            "PROMPT_COMMAND",
            "PYTHONPATH",
            "PYTHONHOME",
            "PYTHONSTARTUP",
            "PYTHONINSPECT",
            "RUBYOPT",
            "RUBYLIB",
            "PERL5OPT",
            "PERL5LIB",
            "PERLLIB",
            "NODE_OPTIONS",
            "JAVA_TOOL_OPTIONS",
            "_JAVA_OPTIONS",
            "CLASSPATH",
            "DOTNET_STARTUP_HOOKS",
        ]
        .contains(&key.as_str())
            && !key.starts_with("BASH_FUNC_")
            && !key.starts_with("LD_")
            && !key.starts_with("DYLD_")
    });
    let spec = Spawn { script, cwd: ctx.workspace.clone(), env, out_path, exit_path };
    let mut running =
        proc::spawn(&ctx.sandbox, &spec).map_err(|e| format!("The analysis command did not start: {e}."))?;
    let limit = ctx.cfg.max_output_bytes.min(2_000_000);
    let wait = running.wait(&ctx.cancel, Some(Duration::from_secs(seconds.clamp(1, 120))), limit).await;
    let background = matches!(wait, WaitEnd::Ended(_)) && running.group_alive();
    let ended = match &wait {
        WaitEnd::Ended(e) if !background => e.clone(),
        _ => running.terminate_within(Duration::from_secs(1), limit).await,
    };
    let(bytes,written)=running.read_output_capped(limit).map_err(|e|format!("Analysis ran but its output could not be read: {e}. Output is retained at {}; inspect that protected file before retrying.",spec.out_path.display()))?;
    let mut reason = match wait {
        WaitEnd::Cancelled => Some("cancelled"),
        WaitEnd::Deadline => Some("timeout"),
        WaitEnd::TooMuchOutput => Some("output limit"),
        _ if background => Some("leader left background processes"),
        _ => None,
    };
    if written > limit && reason.is_none() {
        reason = Some("output limit");
    }
    for p in [&spec.out_path, &spec.exit_path, &proc::pid_path(&spec.out_path)] {
        let _ = std::fs::remove_file(p);
    }
    Ok(CommandOutcome { bytes, ended, completed: reason.is_none(), stop_reason: reason, written })
}

/// Backends reopen this actor-unwritable copy, not the mutable workspace path hashed earlier.
/// Without an OS sandbox no such immutability can be promised and caching remains disabled.
struct BackendInput {
    path: PathBuf,
    root: PathBuf,
    hash: String,
    enforced: bool,
}
impl BackendInput {
    fn create(ctx: &ToolCtx, bytes: &[u8], hash: &str) -> Result<Self, String> {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let parent = ctx.tmp_dir.parent().ok_or("The session has no protected parent for analysis staging.")?;
        let root = parent.join(format!("analysis-{:032x}", rand::random::<u128>()));
        loom_core::config::ensure_private_dir(&root).map_err(|e| format!("Analysis input staging failed: {e}."))?;
        let path = root.join("target");
        let enforced = ctx.sandbox.mode() != loom_core::config::SandboxMode::None;
        let staged = Self { path, root, hash: hash.to_string(), enforced };
        if enforced && ctx.sandbox.check_write(&staged.path).is_ok() {
            return Err("Analysis staging is writable by the actor; no trusted cached analysis was produced.".into());
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staged.path)
            .map_err(|e| e.to_string())?;
        file.write_all(bytes).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&staged.path, std::fs::Permissions::from_mode(0o500)).map_err(|e| e.to_string())?;
        Ok(staged)
    }
    fn unchanged(&self) -> bool {
        std::fs::read(&self.path).is_ok_and(|b| hex::encode(Sha256::digest(&b)) == self.hash)
    }
}
impl Drop for BackendInput {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn selector(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 200 || !s.chars().all(|c| c.is_ascii_alphanumeric() || "_.$:@".contains(c)) {
        Err("Use a symbol or 0x address without command separators or whitespace.".into())
    } else {
        Ok(())
    }
}

async fn rizin(ctx: &ToolCtx, input: &BackendInput, hash: &str, query: &str) -> Result<CommandOutcome, String> {
    let key = format!("{hash}:{query}");
    if input.enforced {
        if let Some(bytes) = ctx.capabilities.binary_cache.lock().unwrap_or_else(|p| p.into_inner()).get(&key).cloned()
        {
            return Ok(CommandOutcome {
                written: bytes.len() as u64,
                bytes,
                ended: crate::proc::Ended::Exit(0),
                completed: true,
                stop_reason: None,
            });
        }
    }
    let script = format!(
        "rizin -N -q -e scr.color=false -e scr.interactive=false -A -c {} {}",
        quote(query),
        quote(&input.path.to_string_lossy())
    );
    let mut outcome = command(ctx, script, 60).await?;
    if !input.unchanged() {
        outcome.completed = false;
        outcome.stop_reason = Some("analysis input changed; result unknown");
    }
    if outcome.success() && input.enforced {
        let mut cache = ctx.capabilities.binary_cache.lock().unwrap_or_else(|p| p.into_inner());
        if cache.len() >= 256 {
            cache.clear();
        }
        cache.insert(key, outcome.bytes.clone());
    }
    Ok(outcome)
}

fn backend_failure(outcome: CommandOutcome) -> ToolOutput {
    outcome
        .into_tool_output("rizin backend did not produce a usable result")
        .with_more("Install rizin and a compatible pdg plugin for decompilation; no analysis was invented.")
}

fn xref_failure(rows: Vec<Value>, target: &str, result: Option<CommandOutcome>, message: String) -> ToolOutput {
    let (mut output, bytes) = match result {
        Some(result) => {
            let bytes = result.bytes.clone();
            (result.into_tool_output("xref backend failure"), bytes)
        }
        None => (ToolOutput::error(&message), Vec::new()),
    };
    if output.status == ToolStatus::Ok {
        output.status = ToolStatus::Error;
    }
    output.more.push(message.clone());
    output.body=Body::Raw(json!({"completed_queries":rows,"failed_target":target,"error":message,"backend_output":String::from_utf8_lossy(&bytes),"backend_output_base64":base64::Engine::encode(&base64::engine::general_purpose::STANDARD,&bytes)}).to_string().into_bytes());
    output
}

fn limited_backend_view(ctx: &ToolCtx, mut output: ToolOutput, bytes: &[u8]) -> ToolOutput {
    let (blob, normalized) = match crate::view::store_text(&ctx.blobs, bytes) {
        Ok(v) => v,
        Err(e) => {
            return output.with_more(format!(
                "The complete backend output could not be indexed: {e}; its bounded bytes are retained in this result."
            ))
        }
    };
    if normalized.changed {
        if let Ok(raw) = ctx.blobs.put_bytes(bytes) {
            output.meta.insert(loom_core::event::META_RAW_BLOB.into(), json!(raw.id.as_str()));
        }
    }
    let last = blob.lines.min(120);
    let text = if last == 0 {
        String::new()
    } else {
        match crate::view::numbered(&ctx.blobs, &blob.id, 1, last, 20_000) {
            Ok((text, _)) => text,
            Err(e) => {
                return output.with_more(format!(
                    "The bounded backend view could not be read: {e}; its bounded bytes are retained in this result."
                ))
            }
        }
    };
    output.more.push(format!(
        "complete backend output: {}; displayed first {last} of {} lines",
        blob.handle(),
        blob.lines
    ));
    output.body = Body::ProducedView { blob, text, shown: if last == 0 { vec![] } else { vec![(1, last)] } };
    output
}

#[async_trait]
impl Tool for BinSurvey {
    fn spec(&self) -> ToolSpec {
        spec("bin_survey","Inspect a bounded ELF/PE/Mach-O object without executing it. ELF/PE/Mach metadata flags, exports/imports, ELF constructors/large functions and interesting strings; unknown facts remain unknown.",ToolClass::Read,&[req("path","string","Binary path.")])
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let given = args.get("path").and_then(Value::as_str).unwrap_or_default();
        match read_binary(ctx, given).and_then(|(path, b, hash)| {
            let mut v = survey(&b)?;
            v["path"] = json!(path);
            v["sha256"] = json!(hash);
            Ok(v)
        }) {
            Ok(v) => ToolOutput::ok("binary survey", Body::Raw(v.to_string().into_bytes())),
            Err(e) => ToolOutput::error(e),
        }
    }
}
#[async_trait]
impl Tool for BinDecompile {
    fn spec(&self) -> ToolSpec {
        spec("bin_decompile","Ask an installed rizin/pdg backend for one function. Content-hash cached, max 120 displayed lines; missing backend is an explicit error. Output is analysis, not execution proof.",ToolClass::Exec,&[req("path","string","Binary path."),req("symbol_or_addr","string","Symbol or 0x address.")])
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let target = args.get("symbol_or_addr").and_then(Value::as_str).unwrap_or_default();
        if let Err(e) = selector(target) {
            return ToolOutput::error(e);
        }
        let (_, bytes, hash) = match read_binary(ctx, args.get("path").and_then(Value::as_str).unwrap_or_default()) {
            Ok(v) => v,
            Err(e) => return ToolOutput::error(e),
        };
        let input = match BackendInput::create(ctx, &bytes, &hash) {
            Ok(v) => v,
            Err(e) => return ToolOutput::error(e),
        };
        let result = match rizin(ctx, &input, &hash, &format!("pdg @ {target}")).await {
            Ok(v) => v,
            Err(e) => return ToolOutput::error(e),
        };
        if !result.success() {
            return backend_failure(result);
        }
        let invalid = {
            let text = String::from_utf8_lossy(&result.bytes);
            text.trim().is_empty() || text.contains("Cannot find") || text.contains("Unknown command")
        };
        let bytes = result.bytes.clone();
        let mut output = result.into_tool_output("decompiler output");
        if invalid {
            output.status = ToolStatus::Error;
            output.more.push("The backend returned no pseudocode or rejected the command; inspect the stored output and install a compatible pdg plugin.".into());
        }
        output.more.push(format!(
            "target sha256 {hash}; content-hash per-query cache; OS input isolation {}",
            if input.enforced { "enforced" } else { "not enforced; uncached observation only" }
        ));
        limited_backend_view(ctx, output, &bytes)
    }
}
#[async_trait]
impl Tool for BinXrefs {
    fn spec(&self) -> ToolSpec {
        spec("bin_xrefs","Bounded incoming-reference BFS using an installed rizin backend. Depth 1..4, at most 12 expanded nodes; cache keys include binary content hash.",ToolClass::Exec,&[req("path","string","Binary path."),req("target","string","Symbol or 0x address."),opt("depth","integer","BFS depth, default 1.").min(1).max(4)])
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let target = args.get("target").and_then(Value::as_str).unwrap_or_default();
        if let Err(e) = selector(target) {
            return ToolOutput::error(e);
        }
        let (_, bytes, hash) = match read_binary(ctx, args.get("path").and_then(Value::as_str).unwrap_or_default()) {
            Ok(v) => v,
            Err(e) => return ToolOutput::error(e),
        };
        let input = match BackendInput::create(ctx, &bytes, &hash) {
            Ok(v) => v,
            Err(e) => return ToolOutput::error(e),
        };
        let mut frontier = vec![target.to_string()];
        let mut seen = BTreeSet::new();
        let mut rows = Vec::new();
        let depth = args.get("depth").and_then(Value::as_u64).unwrap_or(1).clamp(1, 4);
        for d in 0..depth {
            let mut next = Vec::new();
            for t in frontier {
                if seen.len() >= 12 {
                    break;
                }
                if !seen.insert(t.clone()) {
                    continue;
                }
                let result = match rizin(ctx, &input, &hash, &format!("axtj @ {t}")).await {
                    Ok(v) => v,
                    Err(e) => return xref_failure(rows, &t, None, e),
                };
                if !result.success() {
                    return xref_failure(rows,&t,Some(result),"The backend did not complete a successful xref query; inspect its stored output before retrying.".into());
                }
                let v:Value=match serde_json::from_slice(&result.bytes){Ok(v)=>v,Err(e)=>return xref_failure(rows,&t,Some(result),format!("The xref backend did not return pure JSON: {e}. Its warnings/output are retained, not discarded."))};
                if let Some(a) = v.as_array() {
                    for x in a.iter().take(32) {
                        if let Some(from) = x.get("from").and_then(Value::as_u64) {
                            next.push(format!("0x{from:x}"));
                        }
                    }
                }
                rows.push(json!({"target":t,"depth":d+1,"references":v,"backend_output_base64":base64::Engine::encode(&base64::engine::general_purpose::STANDARD,&result.bytes)}));
            }
            frontier = next;
        }
        ToolOutput::ok(
            "xref query",
            Body::Raw(json!({"sha256":hash,"queries":rows,"bounded":seen.len()>=12,"input_isolation_enforced":input.enforced}).to_string().into_bytes()),
        )
    }
}

#[async_trait]
impl Tool for GdbProbe {
    fn spec(&self) -> ToolSpec {
        spec("gdb_probe","Run one bounded gdb batch with startup and auto-load disabled. Stop at a sink and inspect up to eight side-effect-free expressions; debugger measurements are observations, not independent success or privilege proof.",ToolClass::Exec,&[req("binary","string","Target binary."),req("sink","string","Function or file:line breakpoint."),opt("input_file","string","Existing regular input file for stdin."),opt("expressions","array","Variable/field/arithmetic expressions; function calls and command separators are refused.").items("string"),opt("timeout_s","integer","Timeout, default 30, maximum 120.").min(1).max(120)])
    }
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let (_, bytes, hash) = match read_binary(ctx, args.get("binary").and_then(Value::as_str).unwrap_or_default()) {
            Ok(v) => v,
            Err(e) => return ToolOutput::error(e),
        };
        let target = match BackendInput::create(ctx, &bytes, &hash) {
            Ok(v) => v,
            Err(e) => return ToolOutput::error(e),
        };
        let sink = args.get("sink").and_then(Value::as_str).unwrap_or_default();
        if sink.is_empty()
            || sink.len() > 256
            || !sink.chars().all(|c| c.is_ascii_alphanumeric() || "_./:-".contains(c))
        {
            return ToolOutput::error("Use a function name or file:line sink without command separators.");
        }
        let expressions: Vec<String> = args
            .get("expressions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        if expressions.len() > 8
            || expressions.iter().any(|s| {
                s.len() > 100
                    || s.is_empty()
                    || !s.chars().all(|c| c.is_ascii_alphanumeric() || "_ .->*+[]/".contains(c))
            })
        {
            return ToolOutput::error("Use at most eight simple variable/field/arithmetic expressions without calls, assignments or separators.");
        }
        let input = if let Some(given) = args.get("input_file").and_then(Value::as_str) {
            let p = ctx.sandbox.resolve(given);
            let judge = |p: &Path| ctx.sandbox.check_read(p).map(|_| ());
            if let Err(e) = crate::files::open_readable(&p, &judge) {
                return ToolOutput::error(format!("Input must be a readable regular file: {e:?}."));
            }
            format!(" < {}", quote(&p.to_string_lossy()))
        } else {
            String::new()
        };
        let inferior = ctx.tmp_dir.join(format!("probe-inferior-{:016x}.out", rand::random::<u64>()));
        let python=format!("python import gdb,json; print('__LOOM_PROBE__'+json.dumps({{'breakpoint_hits':sum(b.hit_count for b in (gdb.breakpoints() or [])), 'operands':{{s:str(gdb.parse_and_eval(s)) for s in {}}}}}))",json!(expressions));
        let commands = vec![
            "set auto-load off".into(),
            "set may-call-functions off".into(),
            "set debuginfod enabled off".into(),
            "set pagination off".into(),
            format!("file {}", quote(&target.path.to_string_lossy())),
            format!("break {sink}"),
            format!("run{input} > {} 2>&1", quote(&inferior.to_string_lossy())),
            python,
            "bt 12".into(),
        ];
        let file_limit = ctx.cfg.max_output_bytes.min(2_000_000) / 1024;
        let script = format!(
            "ulimit -f {file_limit}; gdb -nx -nh --batch {}",
            commands.into_iter().map(|s| format!("-ex {}", quote(&s))).collect::<Vec<_>>().join(" ")
        );
        match command(ctx, script, args.get("timeout_s").and_then(Value::as_u64).unwrap_or(30)).await {
            Ok(mut result) => {
                if !target.unchanged() {
                    result.completed = false;
                    result.stop_reason = Some("analysis input changed; result unknown");
                }
                let mut output = result.into_tool_output("gdb probe");
                let judge = |p: &Path| ctx.sandbox.check_read(p).map(|_| ());
                match crate::files::open_readable(&inferior, &judge) {
                    Ok((mut file, meta)) => {
                        let limit = ctx.cfg.max_output_bytes.min(2_000_000);
                        let mut data = Vec::new();
                        match file.by_ref().take(limit).read_to_end(&mut data) {
                            Ok(_) => {
                                let truncated = meta.len() > data.len() as u64;
                                output.meta.insert("inferior_written_bytes".into(), json!(meta.len()));
                                output.meta.insert("inferior_truncated".into(), json!(truncated));
                                if let Body::Raw(debugger) = &mut output.body {
                                    output.meta.insert("debugger_output_bytes".into(), json!(debugger.len()));
                                    debugger.extend_from_slice(
                                        b"\n=== inferior stdout/stderr (untrusted target output) ===\n",
                                    );
                                    output.meta.insert("inferior_output_offset".into(), json!(debugger.len()));
                                    debugger.extend_from_slice(&data);
                                }
                                if truncated {
                                    if output.status == ToolStatus::Ok {
                                        output.status = ToolStatus::Error;
                                    }
                                    output.meta.insert("analysis_completed".into(), json!(false));
                                    output.more.push("Inferior output exceeded its bounded view; this does not establish a complete run.".into());
                                }
                                let _ = std::fs::remove_file(&inferior);
                            }
                            Err(e) => {
                                if output.status == ToolStatus::Ok {
                                    output.status = ToolStatus::Error;
                                }
                                output.meta.insert("analysis_completed".into(), json!(false));
                                output.more.push(format!(
                                    "Inferior output read failed ({e}); file retained at {}",
                                    inferior.display()
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        output.more.push(format!("No readable inferior output was available ({e:?}); inspect the debugger output for startup failures."));
                    }
                }
                output.with_more(format!("target sha256 {hash}; debugger and inferior streams stored with explicit byte boundary metadata; observations are not independent proof; input isolation {}",if target.enforced{"enforced"}else{"not enforced"}))
            }
            Err(e) => ToolOutput::error(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_query_injection_and_nonbinary() {
        assert!(selector("sym.main;!id").is_err());
        assert!(selector("0x401020").is_ok());
        assert!(survey(b"not an executable").is_err());
        assert_eq!(quote("a'b"), "'a'\\''b'");
    }
    #[tokio::test]
    async fn descriptor_gate_refuses_fifo() {
        let env = crate::testutil::env();
        let path = env.ctx.workspace.join("fifo");
        let s = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(s.as_ptr(), 0o600) }, 0);
        assert!(read_binary(&env.ctx, "fifo").is_err());
    }
    #[tokio::test]
    async fn bounded_process_stops_on_timeout() {
        let env = crate::testutil::env();
        let result = command(&env.ctx, "printf before_timeout; sleep 60".into(), 1).await.unwrap();
        assert!(!result.completed);
        assert_eq!(result.stop_reason, Some("timeout"));
        let output = result.into_tool_output("analysis");
        assert_eq!(output.status, ToolStatus::Timeout);
        assert!(matches!(output.body,Body::Raw(ref b) if String::from_utf8_lossy(b).contains("before_timeout")));
    }
    #[tokio::test]
    async fn nonzero_and_cancelled_commands_retain_indexable_observations() {
        let env = crate::testutil::env();
        let result = command(&env.ctx, "printf stdout; printf stderr >&2; exit 17".into(), 2).await.unwrap();
        assert!(result.completed);
        let output = result.into_tool_output("backend");
        assert_eq!(output.status, ToolStatus::Error);
        assert_eq!(output.meta[loom_core::event::META_EXIT_CODE], 17);
        assert!(matches!(output.body,Body::Raw(ref b) if String::from_utf8_lossy(b).contains("stdoutstderr")));
        let marker = env.ctx.tmp_dir.join("ready");
        let token = env.ctx.cancel.clone();
        let seen = marker.clone();
        let cancel = tokio::spawn(async move {
            for _ in 0..200 {
                if seen.exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            token.cancel();
        });
        let result =
            command(&env.ctx, format!("printf before_cancel; touch {}; sleep 60", quote(&marker.to_string_lossy())), 3)
                .await
                .unwrap();
        cancel.await.unwrap();
        assert_eq!(result.stop_reason, Some("cancelled"));
        assert!(!result.completed);
        let output = result.into_tool_output("backend");
        assert_eq!(output.status, ToolStatus::Interrupted);
        assert!(matches!(output.body,Body::Raw(ref b) if String::from_utf8_lossy(b).contains("before_cancel")));
    }

    #[tokio::test]
    async fn an_output_limit_is_explicit_even_when_the_process_exits_before_polling() {
        let mut env = crate::testutil::env();
        let mut cfg = (*env.ctx.cfg).clone();
        cfg.max_output_bytes = 32;
        env.ctx.cfg = std::sync::Arc::new(cfg);
        let result = command(&env.ctx, "printf '%0100d' 1".into(), 2).await.unwrap();
        assert!(!result.completed);
        assert_eq!(result.stop_reason, Some("output limit"));
        assert!(result.written > 32);
        let output = result.into_tool_output("backend");
        assert_eq!(output.meta["analysis_truncated"], true);
        assert!(matches!(output.body,Body::Raw(ref b) if b.len()==32));
    }

    #[test]
    fn backend_staging_uses_the_hashed_bytes_and_uncached_none_mode_is_explicit() {
        let env = crate::testutil::env();
        let original = env.ctx.workspace.join("binary");
        std::fs::write(&original, b"original").unwrap();
        let (_, bytes, hash) = read_binary(&env.ctx, "binary").unwrap();
        let staged = BackendInput::create(&env.ctx, &bytes, &hash).unwrap();
        std::fs::write(original, b"changed").unwrap();
        assert_eq!(std::fs::read(&staged.path).unwrap(), b"original");
        assert!(staged.unchanged());
        assert!(!staged.enforced);
    }

    #[test]
    fn a_limited_backend_view_retains_the_full_normalized_producer_blob() {
        let env = crate::testutil::env();
        let bytes = (1..=130).map(|n| format!("line {n}\n")).collect::<String>().into_bytes();
        let result = CommandOutcome {
            written: bytes.len() as u64,
            bytes: bytes.clone(),
            ended: crate::proc::Ended::Exit(0),
            completed: true,
            stop_reason: None,
        };
        let output = limited_backend_view(&env.ctx, result.into_tool_output("backend"), &bytes);
        let record = crate::finalize(
            &env.ctx,
            &BinDecompile.spec(),
            output,
            &crate::Admission { policy: &env.policy, estimator: &env.estimator },
            std::time::Instant::now(),
        );
        let full = record.output.as_ref().unwrap();
        assert_eq!(full.lines, 130);
        assert!(record.cut);
        assert_eq!(record.meta[loom_core::event::META_SHOWN], json!([[1, 120]]));
        assert!(env.stored(&record).contains("line 130"));
        assert!(!record.text.contains("130\tline 130"));
    }

    #[test]
    fn an_xref_failure_retains_completed_queries_and_the_raw_failed_backend() {
        let result = CommandOutcome {
            bytes: b"invalid JSON \xff".to_vec(),
            ended: crate::proc::Ended::Exit(2),
            completed: true,
            stop_reason: None,
            written: 14,
        };
        let output = xref_failure(
            vec![json!({"target":"main","backend_output_base64":"previous"})],
            "other",
            Some(result),
            "parse failed".into(),
        );
        let Body::Raw(bytes) = output.body else { panic!() };
        let data: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(data["completed_queries"][0]["target"], "main");
        assert_eq!(output.status, ToolStatus::Error);
        assert!(data["backend_output_base64"].as_str().is_some_and(|s| !s.is_empty()));
    }

    #[test]
    fn synthetic_macho_metadata_does_not_claim_runtime_protection() {
        let mut bytes = Vec::new();
        for n in [0xfeedfacfu32, 0x0100000c, 0, goblin::mach::header::MH_DYLIB, 0, 0, goblin::mach::header::MH_PIE, 0] {
            bytes.extend_from_slice(&n.to_le_bytes());
        }
        let data = survey(&bytes).unwrap();
        assert_eq!(data["format"], "Mach-O");
        assert_eq!(data["shared_library"], true);
        assert_eq!(data["pie_flag"], true);
        assert!(data["runtime_mitigations"].as_str().unwrap().starts_with("unverified"));
    }

    #[test]
    fn generated_backend_views_normalize_lines_and_keep_original_bytes() {
        let env = crate::testutil::env();
        let bytes = b"\x1b[31mfirst\x1b[0m\n\xff\n".to_vec();
        let result = CommandOutcome {
            written: bytes.len() as u64,
            bytes: bytes.clone(),
            ended: crate::proc::Ended::Exit(0),
            completed: true,
            stop_reason: None,
        };
        let output = limited_backend_view(&env.ctx, result.into_tool_output("backend"), &bytes);
        let record = crate::finalize(
            &env.ctx,
            &BinDecompile.spec(),
            output,
            &crate::Admission { policy: &env.policy, estimator: &env.estimator },
            std::time::Instant::now(),
        );
        assert_eq!(record.output.as_ref().unwrap().lines, 2);
        let raw = record.meta[loom_core::event::META_RAW_BLOB].as_str().unwrap();
        assert_eq!(env.ctx.blobs.read_all(&loom_core::BlobId::from(raw)).unwrap(), bytes);
        assert!(!env.stored(&record).contains('\x1b'));
        let cancelled = CommandOutcome {
            bytes: b"partial".to_vec(),
            ended: crate::proc::Ended::Signal(15),
            completed: false,
            stop_reason: Some("cancelled"),
            written: 7,
        };
        assert_eq!(xref_failure(vec![], "target", Some(cancelled), "cancelled".into()).status, ToolStatus::Interrupted);
    }
    #[tokio::test]
    async fn trusted_commands_do_not_run_forwarded_bash_startup_hooks() {
        let mut env = crate::testutil::env();
        let hook = env.ctx.workspace.join("startup.sh");
        std::fs::write(&hook, b"printf forged_startup; exit 0\n").unwrap();
        let mut vars = (*env.ctx.env).clone();
        vars.insert("BASH_ENV".into(), hook.to_string_lossy().into_owned());
        vars.insert("ENV".into(), hook.to_string_lossy().into_owned());
        vars.insert("LD_PRELOAD".into(), "untrusted".into());
        env.ctx.env = std::sync::Arc::new(vars);
        let result = command(&env.ctx, "printf real_target".into(), 2).await.unwrap();
        assert!(result.success());
        assert_eq!(result.bytes, b"real_target");
    }
}
