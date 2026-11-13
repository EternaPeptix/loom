//! Deterministic encoding and integer helpers.
//!
//! CONTRACT: `codec_calc` never starts a process or reaches the network. Unsigned 64-bit arithmetic is
//! checked; JWT decoding is explicitly unverified; RFC 6238 TOTP uses HMAC-SHA1 with an explicit
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
            json!({"decimal": a.to_string(), "hex":format!("0x{a:x}"), "le64":hex::encode(a.to_le_bytes()),"be64":hex::encode(a.to_be_bytes())})
        }
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
        spec("codec_calc", "Calculate exact 64-bit pointer arithmetic/packing, encodings, unverified JWT decoding, cyclic offsets, or reproducible SHA1 TOTP. Never infer signature validity from decoded JWT fields.", ToolClass::Read, &[
            req("op","string","Operation.").one_of(&["int","unpack_le64","unpack_be64","hex_encode","hex_decode","base64_encode","base64_decode","url_encode","url_decode","jwt_decode","totp","cyclic","cyclic_find"]),
            opt("input","string","Value, UTF-8 text, Base32 TOTP secret, JWT, or cyclic needle (hex: allowed)."),
            opt("arithmetic","string","Optional unsigned operation.").one_of(&["add","sub","xor","and","or"]), opt("operand","string","Decimal or 0x integer."),
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
}
