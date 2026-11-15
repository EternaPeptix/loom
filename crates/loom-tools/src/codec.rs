//! Deterministic encoding and integer helpers.
//!
//! CONTRACT: `codec_calc` never starts a process or reaches the network. Unsigned 64-bit arithmetic is
//! checked; `rebase` subtracts a symbol offset from an observed address, requires power-of-two page
//! alignment (`>= 4096`, default `4096`), and resolves up to 32 named target offsets with checked
//! addition; JWT decoding is explicitly unverified; RFC 6238 TOTP uses HMAC-SHA1 with an explicit
//! timestamp (no hidden clock dependency). Cyclic patterns use a bounded De Bruijn sequence, n=2..6.
//! Inputs and results pass through normal tool logging: do not treat this as a secret vault.

use crate::{
    params::{opt, req, spec},
    Body, Tool, ToolCtx, ToolOutput,
};
use async_trait::async_trait;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use hmac::{Hmac, KeyInit, Mac};
use loom_core::event::{ToolClass, ToolSpec};
use serde_json::{json, Map, Value};
use sha1::Sha1;

pub struct CodecCalc;

fn number(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let result = match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16),
        None => s.parse(),
    };
    result.map_err(|_| "Use an unsigned decimal or 0x-prefixed 64-bit integer.".into())
}

fn base32(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let (mut bits, mut acc) = (0u32, 0u32);
    for c in s.trim_end_matches('=').chars().filter(|c| !c.is_whitespace()) {
        let c = c.to_ascii_uppercase();
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return Err("TOTP secret must be Base32 (A-Z and 2-7).".into()),
        };
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
        acc &= (1u32 << bits).saturating_sub(1);
    }
    if out.is_empty() || (bits > 0 && acc != 0) {
        return Err("The Base32 secret is empty or has invalid trailing bits.".into());
    }
    Ok(out)
}

fn totp(secret: &str, time: u64, step: u64, digits: u32) -> Result<String, String> {
    if step == 0 || !matches!(digits, 6 | 8) {
        return Err("Use a positive TOTP step and 6 or 8 digits.".into());
    }
    let key = base32(secret)?;
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).map_err(|_| "The TOTP key is not usable.")?;
    mac.update(&(time / step).to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest.last().copied().unwrap_or(0) & 15);
    let part: [u8; 4] = digest
        .get(offset..offset.saturating_add(4))
        .and_then(|s| s.try_into().ok())
        .ok_or("TOTP truncation failed; report a harness fault.")?;
    let code = (u32::from_be_bytes(part) & 0x7fff_ffff) % 10u32.pow(digits);
    Ok(format!("{code:0width$}", width = digits as usize))
}

fn cyclic(n: usize, limit: usize) -> Result<Vec<u8>, String> {
    if !(2..=6).contains(&n) || limit > 1_000_000 {
        return Err("Use cyclic width 2..6 and at most 1,000,000 bytes.".into());
    }
    fn visit(t: usize, p: usize, n: usize, a: &mut [usize], out: &mut Vec<u8>, limit: usize) {
        if out.len() >= limit {
            return;
        }
        if t > n {
            if n.is_multiple_of(p) {
                for j in 1..=p {
                    if out.len() < limit {
                        out.push(b'a'.saturating_add(a.get(j).copied().unwrap_or(0) as u8));
                    }
                }
            }
            return;
        }
        let value = a.get(t.saturating_sub(p)).copied().unwrap_or(0);
        if let Some(slot) = a.get_mut(t) {
            *slot = value;
        }
        visit(t.saturating_add(1), p, n, a, out, limit);
        for j in value.saturating_add(1)..26 {
            if let Some(slot) = a.get_mut(t) {
                *slot = j;
            }
            visit(t.saturating_add(1), t, n, a, out, limit);
            if out.len() >= limit {
                break;
            }
        }
    }
    let mut out = Vec::new();
    visit(1, 1, n, &mut vec![0; n.saturating_add(1)], &mut out, limit);
    Ok(out)
}

fn addr_json(a: u64) -> Value {
    json!({
        "decimal": a.to_string(),
        "hex": format!("0x{a:x}"),
        "le64": hex::encode(a.to_le_bytes()),
        "be64": hex::encode(a.to_be_bytes()),
    })
}

fn rebase(observed_str: &str, args: &Map<String, Value>) -> Result<Value, String> {
    let observed = number(observed_str)?;
    let symbol_offset = args
        .get("operand")
        .and_then(Value::as_str)
        .ok_or_else(|| "Supply operand as the known symbol offset for rebase.".to_string())
        .and_then(number)?;
    let page_size = args.get("page_size").and_then(Value::as_u64).unwrap_or(4096);
    if page_size < 4096 || !page_size.is_power_of_two() {
        return Err("Use a power-of-two page_size of at least 4096 bytes.".into());
    }
    let base = observed
        .checked_sub(symbol_offset)
        .ok_or("Observed address is smaller than the symbol offset; check the leaked value and symbol.")?;
    let rem = base % page_size;
    if rem != 0 {
        return Err(format!(
            "Rebased base 0x{base:x} is not aligned to page_size 0x{page_size:x} (remainder 0x{rem:x}); check the symbol offset, build, or leak width."
        ));
    }
    let mut resolved = Map::new();
    if let Some(targets_val) = args.get("targets") {
        let targets = targets_val
            .as_object()
            .ok_or("targets must be an object mapping symbol names to decimal or 0x offsets.")?;
        if targets.len() > 32 {
            return Err("Supply at most 32 target offsets in one rebase call.".into());
        }
        for (name, offset_val) in targets {
            if name.is_empty()
                || name.len() > 64
                || !name.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
            {
                return Err(format!(
                    "Invalid target name `{name}`; use 1..64 ASCII letters, digits, `_`, `.`, or `-`."
                ));
            }
            let offset_str = offset_val
                .as_str()
                .ok_or_else(|| format!("Offset for target `{name}` must be a decimal or 0x integer string."))?;
            let offset = number(offset_str)?;
            let addr = base
                .checked_add(offset)
                .ok_or_else(|| format!("Target `{name}` overflowed 64-bit address space from base 0x{base:x}."))?;
            resolved.insert(name.clone(), addr_json(addr));
        }
    }
    Ok(json!({
        "base": addr_json(base),
        "page_size": format!("0x{page_size:x}"),
        "page_aligned": true,
        "targets": resolved,
    }))
}

fn calculate(args: &Map<String, Value>) -> Result<Value, String> {
    let s = args.get("input").and_then(Value::as_str).unwrap_or_default();
    let op = args.get("op").and_then(Value::as_str).unwrap_or_default();
    Ok(match op {
        "int" => {
            let a = number(s)?;
            let b = args.get("operand").and_then(Value::as_str).map(number).transpose()?;
            let a = match (args.get("arithmetic").and_then(Value::as_str), b) {
                (None, _) => a,
                (Some("add"), Some(b)) => a.checked_add(b).ok_or("Unsigned addition overflowed.")?,
                (Some("sub"), Some(b)) => a.checked_sub(b).ok_or("Unsigned subtraction underflowed.")?,
                (Some("xor"), Some(b)) => a ^ b,
                (Some("and"), Some(b)) => a & b,
                (Some("or"), Some(b)) => a | b,
                _ => return Err("Supply operand with arithmetic add, sub, xor, and or or.".into()),
            };
            addr_json(a)
        }
        "rebase" => rebase(s, args)?,
        "unpack_le64" | "unpack_be64" => {
            let bytes: [u8; 8] = hex::decode(s)
                .map_err(|e| e.to_string())?
                .try_into()
                .map_err(|_| "Supply exactly 8 bytes as 16 hex digits.")?;
            let n = if op == "unpack_le64" { u64::from_le_bytes(bytes) } else { u64::from_be_bytes(bytes) };
            json!({"decimal":n.to_string(),"hex":format!("0x{n:x}")})
        }
        "hex_encode" => json!(hex::encode(s.as_bytes())),
        "hex_decode" => json!(String::from_utf8(hex::decode(s).map_err(|e| e.to_string())?)
            .map_err(|_| "Decoded bytes are not UTF-8; use int/unpack for pointers.")?),
        "base64_encode" => json!(STANDARD.encode(s)),
        "base64_decode" => json!(String::from_utf8(STANDARD.decode(s).map_err(|e| e.to_string())?)
            .map_err(|_| "Decoded bytes are not UTF-8.")?),
        "url_encode" => json!(url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>()),
        "url_decode" => json!(url::form_urlencoded::parse(format!("x={}", s.replace('&', "%26")).as_bytes())
            .next()
            .map(|(_, v)| v.to_string())
            .unwrap_or_default()),
        "jwt_decode" => {
            let parts: Vec<_> = s.split('.').collect();
            if parts.len() != 3 {
                return Err("Supply a three-part JWT. This decoder does not verify signatures.".into());
            }
            let decode = |i| -> Result<Value, String> {
                serde_json::from_slice(
                    &URL_SAFE_NO_PAD.decode(parts.get(i).copied().unwrap_or_default()).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())
            };
            json!({"header":decode(0)?,"payload":decode(1)?,"signature_verified":false})
        }
        "totp" => {
            json!({"code":totp(s, args.get("time_s").and_then(Value::as_u64).ok_or("Supply explicit time_s for TOTP.")?,args.get("step_s").and_then(Value::as_u64).unwrap_or(30),u32::try_from(args.get("digits").and_then(Value::as_u64).unwrap_or(6)).map_err(|_|"TOTP digits must be 6 or 8.")?)?,"algorithm":"SHA1"})
        }
        "cyclic" | "cyclic_find" => {
            let length = args.get("length").and_then(Value::as_u64).unwrap_or(10000).min(1_000_001) as usize;
            let n = args.get("width").and_then(Value::as_u64).unwrap_or(4).min(7) as usize;
            let pattern = cyclic(n, length)?;
            if op == "cyclic" {
                json!(String::from_utf8_lossy(&pattern))
            } else {
                let needle = s
                    .strip_prefix("hex:")
                    .map(hex::decode)
                    .transpose()
                    .map_err(|e| e.to_string())?
                    .unwrap_or_else(|| s.as_bytes().to_vec());
                if needle.len() != n {
                    return Err("Cyclic lookup input must have exactly width bytes (or hex:bytes).".into());
                }
                json!({"offset":pattern.windows(n).position(|w|w == needle),"searched_bytes":pattern.len()})
            }
        }
        _ => return Err("Unknown codec operation; use a value from the op schema.".into()),
    })
}

#[async_trait]
impl Tool for CodecCalc {
    fn spec(&self) -> ToolSpec {
        spec("codec_calc", "Calculate exact 64-bit pointer arithmetic/packing, page-aligned base rebasing, encodings, unverified JWT decoding, cyclic offsets, or reproducible SHA1 TOTP. Never infer signature validity from decoded JWT fields.", ToolClass::Read, &[
            req("op","string","Operation.").one_of(&["int","rebase","unpack_le64","unpack_be64","hex_encode","hex_decode","base64_encode","base64_decode","url_encode","url_decode","jwt_decode","totp","cyclic","cyclic_find"]),
            opt("input","string","Value, observed address, UTF-8 text, Base32 TOTP secret, JWT, or cyclic needle (hex: allowed)."),
            opt("arithmetic","string","Optional unsigned operation.").one_of(&["add","sub","xor","and","or"]), opt("operand","string","Decimal or 0x integer (symbol offset for rebase)."),
            opt("page_size","integer","Page alignment modulus in bytes for rebase, default 4096 (power of two >= 4096).").min(4096),
            opt("targets","object","Optional symbol name -> decimal or 0x offset map resolved from the rebased base.").with("additionalProperties",json!({"type":"string"})),
            opt("time_s","integer","Explicit Unix timestamp for TOTP.").min(0), opt("step_s","integer","TOTP interval, default 30.").min(1),opt("digits","integer","6 or 8."),
            opt("length","integer","Cyclic length/search bound, max one million.").min(1).max(1_000_000), opt("width","integer","Cyclic width, default 4.").min(2).max(6),
        ])
    }
    async fn run(&self, _: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        match calculate(args) {
            Ok(v) => ToolOutput::ok("calculated", Body::Raw(v.to_string().into_bytes())),
            Err(e) => ToolOutput::error(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc6238_and_checked_math() {
        assert_eq!(totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59, 30, 8).unwrap(), "94287082");
        assert_eq!(totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1_111_111_109, 30, 8).unwrap(), "07081804");
        assert!(calculate(
            json!({"op":"int","input":"0xffffffffffffffff","arithmetic":"add","operand":"1"}).as_object().unwrap()
        )
        .is_err());
    }
    #[test]
    fn cyclic_and_jwt_are_precise() {
        assert_eq!(&cyclic(4, 24).unwrap(), b"aaaabaaacaaadaaaeaaafaaa");
        let result = calculate(json!({"op":"cyclic_find","input":"baaa","length":100}).as_object().unwrap()).unwrap();
        assert_eq!(result["offset"], 4);
        let jwt = format!("{}.{}.x", URL_SAFE_NO_PAD.encode(b"{}"), URL_SAFE_NO_PAD.encode(b"{\"admin\":true}"));
        assert_eq!(
            calculate(json!({"op":"jwt_decode","input":jwt}).as_object().unwrap()).unwrap()["signature_verified"],
            false
        );
    }
    #[test]
    fn rebase_enforces_page_alignment_and_resolves_targets() {
        let ok = calculate(
            json!({
                "op": "rebase",
                "input": "0x7f4a12084420",
                "operand": "0x84420",
                "targets": { "sym_a": "0x52290", "sym_b": "4096" }
            })
            .as_object()
            .unwrap(),
        )
        .unwrap();
        assert_eq!(ok["base"]["hex"], "0x7f4a12000000");
        assert_eq!(ok["page_aligned"], true);
        assert_eq!(ok["targets"]["sym_a"]["hex"], "0x7f4a12052290");
        assert_eq!(ok["targets"]["sym_a"]["le64"], "902205124a7f0000");
        assert_eq!(ok["targets"]["sym_b"]["hex"], "0x7f4a12001000");

        let unaligned =
            calculate(json!({"op": "rebase", "input": "0x7f4a12084421", "operand": "0x84420"}).as_object().unwrap())
                .unwrap_err();
        assert!(unaligned.contains("not aligned to page_size 0x1000"), "{unaligned}");
        assert!(
            calculate(json!({"op": "rebase", "input": "0x1000", "operand": "0x2000"}).as_object().unwrap()).is_err()
        );
        assert!(calculate(
            json!({"op": "rebase", "input": "0x8000", "operand": "0x0", "page_size": 6000}).as_object().unwrap()
        )
        .is_err());
        assert!(calculate(
            json!({
                "op": "rebase",
                "input": "0xfffffffffffff000",
                "operand": "0x0",
                "targets": { "wrap": "0x2000" }
            })
            .as_object()
            .unwrap()
        )
        .is_err());
    }
}
