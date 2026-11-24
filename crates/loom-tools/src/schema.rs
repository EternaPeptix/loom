//! Checking a call's arguments against the tool's parameter schema.
//!
//! CONTRACT.
//!
//! The model writing the calls gets argument shapes slightly wrong fairly often. A call that is
//! unambiguous is repaired and the repair is reported; anything else is refused with a message that
//! names the argument, what was received, and what is expected — so the next attempt is right.
//!
//! Schemas are the subset built by [`crate::params`]: an object with `properties`, `required` and
//! `additionalProperties: false`; property types `string`, `integer`, `number`, `boolean`, `array`
//! (with `items`), `object`; optional `enum`, `minimum`, `maximum`, `default`, `description`.
//!
//! ## `check(schema, value)`
//! `value` must be an object (anything else: one problem saying so and showing what was received).
//! For each property, in schema order:
//! - missing and required → problem `missing required argument `name` (type): description`;
//! - missing with a `default` → the default is inserted (no note);
//! - `null` for an optional argument → treated as missing;
//! - present with the right type → kept exactly as given (strings are never trimmed or altered);
//! - repairs, each adding a note ``argument `name`: read "12" as the integer 12``:
//!   string → integer/number when the whole string parses as one; string `"true"`/`"false"` →
//!   boolean; number with zero fraction → integer; integer → number; a string holding JSON of the
//!   expected kind → array/object; a single value of the item type where an array is expected →
//!   one-element array;
//! - anything else → problem ``argument `name` must be TYPE; received KIND: PREVIEW`` (preview ≤ 80
//!   characters);
//! - `enum`, `minimum`, `maximum` violations → problems that state the allowed values / bound.
//!
//! Arguments not in the schema → problem ``unknown argument `nam` — did you mean `name`?`` when
//! exactly one property is within edit distance 2 (or is a prefix/suffix match), otherwise
//! ``unknown argument `x`; this tool takes: a, b, c``. Unknown arguments are never silently dropped.
//! All problems are collected (not just the first). Notes are returned only on success.
//! The order of `args` is the schema's property order.
//!
//! ## `describe(schema)`
//! One line per property: ``- `name` (type, required|optional[, default X]): description``.
//!
//! ## `distance(a, b)`
//! Levenshtein distance over characters, case-insensitive.
//!
//! Tests required: every rule above, accepted and refused; several problems reported together;
//! strings preserved byte-for-byte (leading/trailing whitespace, unicode, embedded newlines); nested
//! arrays of strings; `describe` output; `distance`.

use serde_json::{Map, Number, Value};

#[derive(Clone, Debug, PartialEq)]
pub struct Checked {
    pub args: Map<String, Value>,
    /// Repairs that were made, as sentences. Shown to the model in the result header.
    pub notes: Vec<String>,
}

/// Largest magnitude below which every integer is exactly representable as an `f64`.
const EXACT_F64_INT: f64 = 9_007_199_254_740_992.0;
/// Maximum `idle_timeout_s` accepted by `bash` (`Bash::spec()`).
const BASH_IDLE_TIMEOUT_MAX_S: i64 = 300;

/// Strip vendor token delimiters (such as `<|open|>argument key="..."<|sep|>42`) when a string
/// wraps a trailing numeric literal with `<|...|>` delimiters. Returns `None` if no `<|...|>`
/// delimiters exist.
fn strip_vendor_number_delimiter(s: &str) -> Option<&str> {
    if !(s.contains("<|") && s.contains("|>")) {
        return None;
    }
    let mut cur = s.trim();
    while cur.ends_with("|>") {
        let Some(open) = cur.rfind("<|") else { break };
        if cur.get(open..).is_some_and(|tail| tail.match_indices("|>").count() == 1) {
            cur = cur.get(..open).unwrap_or("").trim_end();
        } else {
            break;
        }
    }
    if let Some((_, tail)) = cur.rsplit_once("|>") {
        Some(tail.trim())
    } else {
        Some(cur.trim())
    }
}

fn parse_i64_like(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| {
            n.as_f64().filter(|f| f.is_finite() && f.fract() == 0.0 && f.abs() < EXACT_F64_INT).map(|f| f as i64)
        }),
        Value::String(s) => {
            let candidate = strip_vendor_number_delimiter(s).unwrap_or(s.as_str());
            candidate.parse::<i64>().ok().or_else(|| {
                candidate
                    .parse::<f64>()
                    .ok()
                    .filter(|f| f.is_finite() && f.fract() == 0.0 && f.abs() < EXACT_F64_INT)
                    .map(|f| f as i64)
            })
        }
        _ => None,
    }
}

fn parse_f64_like(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64().filter(|f| f.is_finite()),
        Value::String(s) => {
            let candidate = strip_vendor_number_delimiter(s).unwrap_or(s.as_str());
            candidate.parse::<f64>().ok().filter(|f| f.is_finite())
        }
        _ => None,
    }
}

fn ms_to_ceil_secs(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                return Some(u.div_ceil(1000).max(1));
            }
            if let Some(i) = n.as_i64() {
                return (i >= 0).then(|| (i as u64).div_ceil(1000).max(1));
            }
            let f = n.as_f64().filter(|f| f.is_finite() && *f >= 0.0)?;
            let secs = (f / 1000.0).ceil();
            (secs <= u64::MAX as f64).then(|| (secs as u64).max(1))
        }
        Value::String(s) => {
            let candidate = strip_vendor_number_delimiter(s).unwrap_or(s.as_str());
            if let Ok(u) = candidate.parse::<u64>() {
                return Some(u.div_ceil(1000).max(1));
            }
            let f = candidate.parse::<f64>().ok().filter(|f| f.is_finite() && *f >= 0.0)?;
            let secs = (f / 1000.0).ceil();
            (secs <= u64::MAX as f64).then(|| (secs as u64).max(1))
        }
        _ => None,
    }
}

fn is_absent_or_null(map: &Map<String, Value>, key: &str) -> bool {
    map.get(key).is_none_or(Value::is_null)
}

fn alias_key(map: &mut Map<String, Value>, canon: &str, aliases: &[&str], notes: &mut Vec<String>) {
    if !is_absent_or_null(map, canon) {
        return;
    }
    let chosen = aliases
        .iter()
        .copied()
        .find(|a| map.get(*a).is_some_and(|v| !v.is_null()))
        .or_else(|| aliases.iter().copied().find(|a| map.contains_key(*a)));
    let Some(alias) = chosen else { return };
    if let Some(val) = map.remove(alias) {
        map.insert(canon.to_string(), val);
        notes.push(format!("argument alias: `{alias}` -> `{canon}`"));
    }
}

fn clamp_max_value(
    map: &mut Map<String, Value>,
    key: &str,
    max_val: &Value,
    is_integer: bool,
    notes: &mut Vec<String>,
) {
    let Some(cur) = map.get(key) else { return };
    let Some(max_f) = max_val.as_f64().filter(|f| f.is_finite()) else { return };
    if is_integer {
        if let Some(max_i) = max_val.as_i64() {
            if let Some(n) = parse_i64_like(cur) {
                if n > max_i {
                    map.insert(key.to_string(), Value::from(max_i));
                    notes.push(format!("argument `{key}`: clamped {n} down to maximum {max_i}"));
                }
                return;
            }
        }
    }
    if let Some(f) = parse_f64_like(cur) {
        if f > max_f {
            let clamped = if is_integer {
                max_val.as_i64().map(Value::from).unwrap_or_else(|| max_val.clone())
            } else {
                max_val.clone()
            };
            map.insert(key.to_string(), clamped);
            notes.push(format!("argument `{key}`: clamped {f} down to maximum {max_val}"));
        }
    }
}

/// `limit` (or `num_lines`) is a count of lines, as in the trained read tools: with `start` (default 1)
/// it becomes `end = start + limit - 1`. Used where no `end` was given; a `limit` below 1 or not a number
/// is left for the schema check to refuse.
fn limit_to_end(map: &mut Map<String, Value>, notes: &mut Vec<String>) {
    if !is_absent_or_null(map, "end") {
        return;
    }
    let Some(limit_key) = ["limit", "num_lines"].into_iter().find(|k| map.contains_key(*k)) else { return };
    let Some(limit) = map.get(limit_key).and_then(parse_i64_like).filter(|n| *n >= 1) else { return };
    let start = map.get("start").and_then(parse_i64_like).unwrap_or(1).max(1);
    let end = start.saturating_add(limit - 1);
    map.remove(limit_key);
    map.insert("end".to_string(), Value::from(end));
    notes.push(format!("argument alias: `{limit_key}` ({limit}) -> `end` ({end})"));
}

/// Normalize well-known model parameter habits for `tool` before [`check`] runs.
/// Only inserts or renames keys when the canonical key is absent or `null`, and returns a repair
/// sentence for every transformation applied.
pub fn normalize_for_tool(tool: &str, value: &mut Value) -> Vec<String> {
    let Some(map) = value.as_object_mut() else {
        return Vec::new();
    };
    let mut notes = Vec::new();
    match tool {
        "read" | "write" | "edit" => {
            alias_key(map, "path", &["file_path", "filepath", "filename"], &mut notes);
            alias_key(map, "start", &["offset", "start_line", "from_line"], &mut notes);
            alias_key(map, "end", &["end_line", "to_line"], &mut notes);
            limit_to_end(map, &mut notes);
            alias_key(map, "old", &["old_string", "old_text", "old_str", "target"], &mut notes);
            alias_key(map, "new", &["new_string", "new_text", "new_str", "replacement"], &mut notes);
            alias_key(map, "all", &["replace_all"], &mut notes);
            alias_key(map, "content", &["contents", "text", "file_text"], &mut notes);
        }
        "bash" => {
            alias_key(map, "command", &["cmd"], &mut notes);
            alias_key(map, "timeout_s", &["timeout"], &mut notes);
            if is_absent_or_null(map, "timeout_s") {
                if let Some(secs) = map.get("timeout_ms").and_then(ms_to_ceil_secs) {
                    map.remove("timeout_ms");
                    map.insert("timeout_s".to_string(), Value::from(secs));
                    notes.push(format!("argument alias: `timeout_ms` -> `timeout_s` ({secs})"));
                }
            }
            if is_absent_or_null(map, "idle_timeout_s") {
                if let Some(secs) = map.get("idle_timeout_ms").and_then(ms_to_ceil_secs) {
                    map.remove("idle_timeout_ms");
                    map.insert("idle_timeout_s".to_string(), Value::from(secs));
                    notes.push(format!("argument alias: `idle_timeout_ms` -> `idle_timeout_s` ({secs})"));
                }
            }
            clamp_max_value(map, "idle_timeout_s", &Value::from(BASH_IDLE_TIMEOUT_MAX_S), true, &mut notes);
        }
        "grep" | "out_grep" => {
            alias_key(map, "pattern", &["query", "regex"], &mut notes);
            alias_key(map, "path", &["dir", "directory", "file_path"], &mut notes);
            alias_key(map, "max", &["max_results", "limit"], &mut notes);
        }
        "glob" => {
            alias_key(map, "path", &["dir", "directory"], &mut notes);
            alias_key(map, "pattern", &["glob", "query"], &mut notes);
        }
        "out_read" => {
            if map.remove("total_lines").is_some() {
                notes.push("stripped harmless extra `total_lines` argument".to_string());
            }
            alias_key(map, "start", &["offset", "start_line"], &mut notes);
            alias_key(map, "end", &["end_line"], &mut notes);
            limit_to_end(map, &mut notes);
        }
        "claim_update" => {
            alias_key(map, "id", &["claim", "claim_id"], &mut notes);
        }
        "claim" => {
            alias_key(map, "text", &["claim", "statement"], &mut notes);
        }
        "finish" => {
            alias_key(map, "answer", &["summary", "answer_note", "result"], &mut notes);
        }
        "agent_spawn" | "agent_fanout" => {
            alias_key(map, "question", &["task", "prompt"], &mut notes);
            alias_key(map, "max_steps", &["steps"], &mut notes);
            if tool == "agent_fanout" {
                if let Some(Value::Array(items)) = map.get_mut("agents") {
                    for item in items {
                        if let Some(item_map) = item.as_object_mut() {
                            alias_key(item_map, "question", &["task", "prompt"], &mut notes);
                            alias_key(item_map, "max_steps", &["steps"], &mut notes);
                        }
                    }
                }
            }
        }
        "plan" | "step" => {
            alias_key(map, "id", &["step_id"], &mut notes);
        }
        "security_record" if is_absent_or_null(map, "operation") && !is_absent_or_null(map, "action") => {
            if map.get("operation").is_some_and(Value::is_null) {
                map.remove("operation");
            }
            let inner = Value::Object(std::mem::take(map));
            map.insert("operation".to_string(), inner);
            notes.push("wrapped top-level `action` payload under `operation`".to_string());
        }
        _ => {}
    }
    notes
}

/// Schema-aware pre-check normalization: strips vendor token delimiters from integer/number string
/// fields when trailing numeric values parse cleanly, and clamps `timeout_s` / `idle_timeout_s`
/// above the schema's `maximum` down to `maximum`.
pub(crate) fn prepare_for_spec(schema: &Value, value: &mut Value) -> Vec<String> {
    let Some(map) = value.as_object_mut() else {
        return Vec::new();
    };
    let Some(props) = schema.get("properties").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut notes = Vec::new();
    for (name, prop_spec) in props {
        let Some(ty) = prop_spec.get("type").and_then(Value::as_str) else { continue };
        if !matches!(ty, "integer" | "number") {
            continue;
        }
        let Some(Value::String(s)) = map.get(name) else { continue };
        let Some(stripped) = strip_vendor_number_delimiter(s) else { continue };
        let original_preview = crate::preview(s, 60);
        if ty == "integer" {
            let parsed = stripped.parse::<i64>().ok().or_else(|| {
                stripped
                    .parse::<f64>()
                    .ok()
                    .filter(|f| f.is_finite() && f.fract() == 0.0 && f.abs() < EXACT_F64_INT)
                    .map(|f| f as i64)
            });
            if let Some(i) = parsed {
                map.insert(name.clone(), Value::from(i));
                notes.push(format!("argument `{name}`: stripped vendor delimiter from \"{original_preview}\" -> {i}"));
            }
        } else if let Some(num) = stripped.parse::<f64>().ok().filter(|f| f.is_finite()).and_then(Number::from_f64) {
            notes.push(format!("argument `{name}`: stripped vendor delimiter from \"{original_preview}\" -> {num}"));
            map.insert(name.clone(), Value::Number(num));
        }
    }
    for key in ["timeout_s", "idle_timeout_s"] {
        if let Some(prop_spec) = props.get(key) {
            if let Some(max_val) = prop_spec.get("maximum") {
                let is_integer = prop_spec.get("type").and_then(Value::as_str) == Some("integer");
                clamp_max_value(map, key, max_val, is_integer, &mut notes);
            }
        }
    }
    notes
}

/// True when `schema` uses only the keywords [`check`] understands (the module doc's list), so an MCP
/// server's `inputSchema` can be checked here; otherwise the server validates (CONTRACTS-MCP M5).
pub fn checkable(schema: &Value) -> bool {
    let _ = schema;
    todo!("CONTRACTS-MCP M5")
}

pub fn check(schema: &Value, value: &Value) -> Result<Checked, Vec<String>> {
    let Some(given) = value.as_object() else {
        return Err(vec![format!(
            "the arguments must be a JSON object of named arguments; received {}: {}",
            kind(value),
            crate::preview(&value.to_string(), 80)
        )]);
    };
    let empty = Map::new();
    let props = schema.get("properties").and_then(Value::as_object).unwrap_or(&empty);
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    let mut args = Map::new();
    let mut notes = Vec::new();
    let mut problems = Vec::new();

    for (name, spec) in props {
        match given.get(name) {
            None | Some(Value::Null) => {
                if required.contains(&name.as_str()) {
                    let mut p = format!("missing required argument `{name}` ({})", type_label(spec));
                    if let Some(d) = spec.get("description").and_then(Value::as_str) {
                        p.push_str(": ");
                        p.push_str(d);
                    }
                    problems.push(p);
                } else if let Some(d) = spec.get("default") {
                    args.insert(name.clone(), d.clone());
                }
            }
            Some(v) => match coerce(name, spec, v, &mut notes) {
                Ok(fixed) => {
                    args.insert(name.clone(), fixed);
                }
                Err(mut p) => problems.append(&mut p),
            },
        }
    }

    for key in given.keys().filter(|k| !props.contains_key(k.as_str())) {
        problems.push(unknown_argument(key, props));
    }

    if problems.is_empty() {
        Ok(Checked { args, notes })
    } else {
        Err(problems)
    }
}

pub fn describe(schema: &Value) -> String {
    let Some(props) = schema.get("properties").and_then(Value::as_object) else {
        return String::new();
    };
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut lines = Vec::new();
    for (name, spec) in props {
        let mut line = format!(
            "- `{name}` ({}, {}",
            spec.get("type").and_then(Value::as_str).unwrap_or("any"),
            if required.contains(&name.as_str()) { "required" } else { "optional" }
        );
        if let Some(d) = spec.get("default") {
            line.push_str(&format!(", default {d}"));
        }
        line.push(')');
        if let Some(d) = spec.get("description").and_then(Value::as_str) {
            line.push_str(": ");
            line.push_str(d);
        }
        lines.push(line);
    }
    lines.join("\n")
}

/// Levenshtein distance over characters, ignoring case.
pub fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().flat_map(char::to_lowercase).collect();
    let b: Vec<char> = b.chars().flat_map(char::to_lowercase).collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = Vec::with_capacity(b.len() + 1);
        cur.push(i + 1);
        for (j, cb) in b.iter().enumerate() {
            let sub = prev.get(j).copied().unwrap_or(0) + usize::from(ca != cb);
            let del = prev.get(j + 1).copied().unwrap_or(0) + 1;
            let ins = cur.get(j).copied().unwrap_or(0) + 1;
            cur.push(sub.min(del).min(ins));
        }
        prev = cur;
    }
    prev.last().copied().unwrap_or(0)
}

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// The type as shown in a refusal: `array of string` for arrays with a typed item.
fn type_label(spec: &Value) -> String {
    let ty = spec.get("type").and_then(Value::as_str).unwrap_or("any");
    match (ty, spec.get("items").and_then(|i| i.get("type")).and_then(Value::as_str)) {
        ("array", Some(item)) => format!("array of {item}"),
        _ => ty.to_string(),
    }
}

fn wrong_type(name: &str, spec: &Value, v: &Value) -> Vec<String> {
    vec![format!(
        "argument `{name}` must be {}; received {}: {}",
        type_label(spec),
        kind(v),
        crate::preview(&v.to_string(), 80)
    )]
}

fn unknown_argument(key: &str, props: &Map<String, Value>) -> String {
    let near: Vec<&String> = props
        .keys()
        .filter(|p| {
            !key.is_empty()
                && (distance(key, p) <= 2
                    || p.starts_with(key)
                    || key.starts_with(p.as_str())
                    || p.ends_with(key)
                    || key.ends_with(p.as_str()))
        })
        .collect();
    match near.as_slice() {
        [one] => format!("unknown argument `{key}` — did you mean `{one}`?"),
        _ => {
            let names: Vec<&str> = props.keys().map(String::as_str).collect();
            if names.is_empty() {
                format!("unknown argument `{key}`; this tool takes no arguments")
            } else {
                format!("unknown argument `{key}`; this tool takes: {}", names.join(", "))
            }
        }
    }
}

/// Does `v` already have the type `spec` asks for, with no repair?
fn has_type(spec: &Value, v: &Value) -> bool {
    match spec.get("type").and_then(Value::as_str) {
        Some("string") => v.is_string(),
        Some("integer") => v.is_i64() || v.is_u64(),
        Some("number") => v.is_number(),
        Some("boolean") => v.is_boolean(),
        Some("array") => v.is_array(),
        Some("object") => v.is_object(),
        _ => false,
    }
}

/// Bring `v` to the type `spec` asks for, noting each repair; then apply `enum`/`minimum`/`maximum`.
fn coerce(name: &str, spec: &Value, v: &Value, notes: &mut Vec<String>) -> Result<Value, Vec<String>> {
    let fixed = match spec.get("type").and_then(Value::as_str) {
        Some("string") => match v {
            Value::String(_) => v.clone(),
            _ => return Err(wrong_type(name, spec, v)),
        },
        Some("integer") => match v {
            Value::Number(n) if n.is_i64() || n.is_u64() => v.clone(),
            Value::Number(n) => match n.as_f64() {
                Some(f) if f.is_finite() && f.fract() == 0.0 && f.abs() < EXACT_F64_INT => {
                    let i = f as i64;
                    notes.push(format!("argument `{name}`: read {n} as the integer {i}"));
                    Value::from(i)
                }
                _ => return Err(wrong_type(name, spec, v)),
            },
            Value::String(s) => match s.parse::<i64>() {
                Ok(i) => {
                    notes.push(format!("argument `{name}`: read \"{s}\" as the integer {i}"));
                    Value::from(i)
                }
                Err(_) => return Err(wrong_type(name, spec, v)),
            },
            _ => return Err(wrong_type(name, spec, v)),
        },
        Some("number") => match v {
            Value::Number(n) if n.is_f64() => v.clone(),
            Value::Number(n) => match n.as_f64().and_then(Number::from_f64) {
                Some(f) => {
                    notes.push(format!("argument `{name}`: read the integer {n} as the number {f}"));
                    Value::Number(f)
                }
                None => return Err(wrong_type(name, spec, v)),
            },
            Value::String(s) => match s.parse::<f64>().ok().and_then(Number::from_f64) {
                Some(f) => {
                    notes.push(format!("argument `{name}`: read \"{s}\" as the number {f}"));
                    Value::Number(f)
                }
                None => return Err(wrong_type(name, spec, v)),
            },
            _ => return Err(wrong_type(name, spec, v)),
        },
        Some("boolean") => match v {
            Value::Bool(_) => v.clone(),
            Value::String(s) if s == "true" || s == "false" => {
                notes.push(format!("argument `{name}`: read \"{s}\" as the boolean {s}"));
                Value::Bool(s == "true")
            }
            _ => return Err(wrong_type(name, spec, v)),
        },
        Some("array") => coerce_array(name, spec, v, notes)?,
        Some("object") => match v {
            Value::Object(_) => v.clone(),
            Value::String(s) => match serde_json::from_str::<Value>(s) {
                Ok(parsed @ Value::Object(_)) => {
                    notes.push(format!("argument `{name}`: read the text as a JSON object"));
                    parsed
                }
                _ => return Err(wrong_type(name, spec, v)),
            },
            _ => return Err(wrong_type(name, spec, v)),
        },
        _ => v.clone(),
    };
    constrain(name, spec, &fixed)?;
    Ok(fixed)
}

fn coerce_array(name: &str, spec: &Value, v: &Value, notes: &mut Vec<String>) -> Result<Value, Vec<String>> {
    let item_spec = spec.get("items");
    let elements: Vec<Value> = match v {
        Value::Array(a) => a.clone(),
        Value::String(s) => match serde_json::from_str::<Value>(s) {
            Ok(Value::Array(a)) => {
                notes.push(format!("argument `{name}`: read the text as a JSON array"));
                a
            }
            _ => wrap_single(name, spec, item_spec, v, notes)?,
        },
        _ => wrap_single(name, spec, item_spec, v, notes)?,
    };
    let Some(item_spec) = item_spec else {
        return Ok(Value::Array(elements));
    };
    let mut out = Vec::with_capacity(elements.len());
    let mut problems = Vec::new();
    for (i, el) in elements.iter().enumerate() {
        match coerce(&format!("{name}[{i}]"), item_spec, el, notes) {
            Ok(fixed) => out.push(fixed),
            Err(mut p) => problems.append(&mut p),
        }
    }
    if problems.is_empty() {
        Ok(Value::Array(out))
    } else {
        Err(problems)
    }
}

/// A lone value of the item type where a list is expected becomes a one-element list.
fn wrap_single(
    name: &str,
    spec: &Value,
    item_spec: Option<&Value>,
    v: &Value,
    notes: &mut Vec<String>,
) -> Result<Vec<Value>, Vec<String>> {
    match item_spec {
        Some(item) if has_type(item, v) => {
            notes.push(format!("argument `{name}`: wrapped the single value in a list"));
            Ok(vec![v.clone()])
        }
        _ => Err(wrong_type(name, spec, v)),
    }
}

/// `enum`, `minimum` and `maximum` on an already well-typed value.
fn constrain(name: &str, spec: &Value, v: &Value) -> Result<(), Vec<String>> {
    if let Some(allowed) = spec.get("enum").and_then(Value::as_array) {
        if !allowed.contains(v) {
            let list: Vec<String> = allowed
                .iter()
                .map(|a| match a {
                    Value::String(s) => format!("`{s}`"),
                    other => format!("`{other}`"),
                })
                .collect();
            return Err(vec![format!(
                "argument `{name}` must be one of {}; received {}",
                list.join(", "),
                crate::preview(&v.to_string(), 80)
            )]);
        }
    }
    if let Some(n) = v.as_f64() {
        if let Some(min) = spec.get("minimum") {
            if min.as_f64().is_some_and(|m| n < m) {
                return Err(vec![format!("argument `{name}` must be at least {min}; received {v}")]);
            }
        }
        if let Some(max) = spec.get("maximum") {
            if max.as_f64().is_some_and(|m| n > m) {
                return Err(vec![format!("argument `{name}` must be at most {max}; received {v}")]);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File to read"},
                "start": {"type": "integer", "description": "First line", "minimum": 1},
                "limit": {"type": "integer", "description": "Max lines", "default": 200, "maximum": 1000},
                "ratio": {"type": "number", "description": "A ratio"},
                "force": {"type": "boolean", "description": "Overwrite"},
                "mode": {"type": "string", "description": "How", "enum": ["fast", "slow"]},
                "names": {"type": "array", "description": "Names", "items": {"type": "string"}},
                "opts": {"type": "object", "description": "Options"}
            },
            "required": ["path"],
            "additionalProperties": false
        })
    }

    fn ok(v: Value) -> Checked {
        check(&schema(), &v).unwrap()
    }

    fn bad(v: Value) -> Vec<String> {
        check(&schema(), &v).unwrap_err()
    }

    #[test]
    fn right_types_pass_unchanged_with_default_and_order() {
        let c = ok(json!({"force": true, "start": 3, "path": "a.txt"}));
        assert!(c.notes.is_empty());
        let keys: Vec<&str> = c.args.keys().map(String::as_str).collect();
        assert_eq!(keys, ["path", "start", "limit", "force"]);
        assert_eq!(c.args["limit"], json!(200));
    }

    #[test]
    fn null_optional_is_missing() {
        let c = ok(json!({"path": "p", "start": null, "limit": null, "mode": null}));
        assert_eq!(c.args.get("start"), None);
        assert_eq!(c.args["limit"], json!(200));
        assert_eq!(c.args.get("mode"), None);
    }

    #[test]
    fn missing_required_names_type_and_description() {
        let p = bad(json!({}));
        assert_eq!(p, ["missing required argument `path` (string): File to read"]);
        let p = bad(json!({"path": null}));
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn non_object_is_one_problem() {
        let p = check(&schema(), &json!("hello")).unwrap_err();
        assert_eq!(p.len(), 1);
        assert!(p[0].contains("JSON object") && p[0].contains("string") && p[0].contains("\"hello\""), "{p:?}");
        assert_eq!(check(&schema(), &json!([1])).unwrap_err().len(), 1);
    }

    #[test]
    fn string_to_integer_number_boolean() {
        let c = ok(json!({"path": "p", "start": "12", "ratio": "0.5", "force": "true"}));
        assert_eq!(c.args["start"], json!(12));
        assert_eq!(c.args["ratio"], json!(0.5));
        assert_eq!(c.args["force"], json!(true));
        assert_eq!(c.notes[0], "argument `start`: read \"12\" as the integer 12");
        assert_eq!(c.notes.len(), 3);
        assert_eq!(ok(json!({"path": "p", "force": "false"})).args["force"], json!(false));
    }

    #[test]
    fn float_with_zero_fraction_to_integer_and_integer_to_number() {
        let c = ok(json!({"path": "p", "start": 4.0, "ratio": 2}));
        assert_eq!(c.args["start"], json!(4));
        assert!(c.args["start"].is_i64());
        assert!(c.args["ratio"].is_f64());
        assert_eq!(c.notes.len(), 2);
        assert!(c.notes[0].starts_with("argument `start`: read 4.0 as the integer 4"), "{:?}", c.notes);
    }

    #[test]
    fn fractional_or_unparsable_numbers_are_refused() {
        let p = bad(json!({"path": "p", "start": 1.5}));
        assert_eq!(p, ["argument `start` must be integer; received number: 1.5"]);
        let p = bad(json!({"path": "p", "start": "twelve"}));
        assert_eq!(p, ["argument `start` must be integer; received string: \"twelve\""]);
        let p = bad(json!({"path": "p", "start": " 12"}));
        assert_eq!(p.len(), 1);
        let p = bad(json!({"path": "p", "force": "yes"}));
        assert!(p[0].starts_with("argument `force` must be boolean; received string"), "{p:?}");
        let p = bad(json!({"path": 5}));
        assert_eq!(p, ["argument `path` must be string; received integer: 5"]);
    }

    #[test]
    fn json_text_to_array_and_object() {
        let c = ok(json!({"path": "p", "names": "[\"a\", \"b\"]", "opts": "{\"k\": 1}"}));
        assert_eq!(c.args["names"], json!(["a", "b"]));
        assert_eq!(c.args["opts"], json!({"k": 1}));
        assert_eq!(c.notes.len(), 2);
        let p = bad(json!({"path": "p", "opts": "[1]"}));
        assert!(p[0].contains("must be object"), "{p:?}");
        let p = bad(json!({"path": "p", "opts": 3}));
        assert!(p[0].contains("must be object"), "{p:?}");
    }

    #[test]
    fn single_value_becomes_one_element_array() {
        let c = ok(json!({"path": "p", "names": "solo"}));
        assert_eq!(c.args["names"], json!(["solo"]));
        assert_eq!(c.notes.len(), 1);
        let p = bad(json!({"path": "p", "names": 7}));
        assert_eq!(p, ["argument `names` must be array of string; received integer: 7"]);
    }

    #[test]
    fn nested_array_items_are_checked_with_their_index() {
        let c = ok(json!({"path": "p", "names": ["a", "", " b "]}));
        assert_eq!(c.args["names"], json!(["a", "", " b "]));
        let p = bad(json!({"path": "p", "names": ["a", 2, null, "c"]}));
        assert_eq!(p.len(), 2);
        assert!(p[0].starts_with("argument `names[1]` must be string"), "{p:?}");
        assert!(p[1].starts_with("argument `names[2]` must be string; received null"), "{p:?}");
    }

    #[test]
    fn strings_are_preserved_byte_for_byte() {
        let s = "  héllo\n\twörld ✓ \r\n  ";
        let c = ok(json!({"path": s, "names": [s]}));
        assert_eq!(c.args["path"], json!(s));
        assert_eq!(c.args["names"], json!([s]));
        assert!(c.notes.is_empty());
    }

    #[test]
    fn enum_and_bounds() {
        let p = bad(json!({"path": "p", "mode": "medium"}));
        assert_eq!(p, ["argument `mode` must be one of `fast`, `slow`; received \"medium\""]);
        assert_eq!(ok(json!({"path": "p", "mode": "slow"})).args["mode"], json!("slow"));
        let p = bad(json!({"path": "p", "start": 0}));
        assert_eq!(p, ["argument `start` must be at least 1; received 0"]);
        let p = bad(json!({"path": "p", "limit": "5000"}));
        assert_eq!(p, ["argument `limit` must be at most 1000; received 5000"]);
        assert_eq!(ok(json!({"path": "p", "start": 1, "limit": 1000})).args["limit"], json!(1000));
    }

    #[test]
    fn unknown_arguments_suggest_or_list() {
        let p = bad(json!({"path": "p", "pat": "x"}));
        assert_eq!(p, ["unknown argument `pat` — did you mean `path`?"]);
        // Two properties within distance 2 of `pth` (`path`, `opts`): ambiguous, so the list is given.
        let p = bad(json!({"path": "p", "pth": "x"}));
        assert!(p[0].starts_with("unknown argument `pth`; this tool takes: path"), "{p:?}");
        let p = bad(json!({"path": "p", "star": 1}));
        assert_eq!(p, ["unknown argument `star` — did you mean `start`?"]);
        let p = bad(json!({"path": "p", "zzzzzzzz": 1}));
        assert_eq!(
            p,
            ["unknown argument `zzzzzzzz`; this tool takes: path, start, limit, ratio, force, mode, names, opts"]
        );
        let p = check(&json!({"properties": {"a": {"type": "string"}, "b": {"type": "string"}}}), &json!({"c": 1}))
            .unwrap_err();
        assert_eq!(p, ["unknown argument `c`; this tool takes: a, b"]);
    }

    #[test]
    fn all_problems_are_reported_together() {
        let p = bad(json!({"start": "x", "mode": "no", "bogus": 1}));
        assert_eq!(p.len(), 4, "{p:?}");
        assert!(p[0].starts_with("missing required argument `path`"));
        assert!(p[1].contains("`start`"));
        assert!(p[2].contains("`mode`"));
        assert!(p[3].contains("`bogus`"));
    }

    #[test]
    fn preview_is_at_most_80_characters_plus_marker() {
        let long = "é".repeat(200);
        let p = bad(json!({"path": 1, "start": long}));
        let line = &p[1];
        assert!(line.contains("…[+"), "{line}");
        assert!(line.chars().count() < 200, "{line}");
    }

    #[test]
    fn describe_lines() {
        let d = describe(&schema());
        let lines: Vec<&str> = d.lines().collect();
        assert_eq!(lines.len(), 8);
        assert_eq!(lines[0], "- `path` (string, required): File to read");
        assert_eq!(lines[1], "- `start` (integer, optional): First line");
        assert_eq!(lines[2], "- `limit` (integer, optional, default 200): Max lines");
        assert_eq!(lines[6], "- `names` (array, optional): Names");
    }

    #[test]
    fn distance_is_levenshtein_case_insensitive() {
        assert_eq!(distance("", ""), 0);
        assert_eq!(distance("abc", ""), 3);
        assert_eq!(distance("", "abc"), 3);
        assert_eq!(distance("kitten", "sitting"), 3);
        assert_eq!(distance("Path", "path"), 0);
        assert_eq!(distance("héllo", "hello"), 1);
        assert_eq!(distance("flaw", "lawn"), 2);
    }

    #[test]
    fn normalize_for_tool_covers_all_tool_aliases_and_preserves_canonical() {
        let mut r = json!({"file_path": "x.rs", "offset": 10, "limit": 25});
        let notes = normalize_for_tool("read", &mut r);
        assert!(!notes.is_empty());
        assert_eq!(r, json!({"path": "x.rs", "start": 10, "end": 34}));

        // Explicit canonical key wins and stays intact.
        let mut r2 = json!({"path": "keep.rs", "file_path": "ignored.rs", "start": 1, "limit": 5, "end": 9});
        let _ = normalize_for_tool("read", &mut r2);
        assert_eq!(r2["path"], "keep.rs");
        assert_eq!(r2["end"], 9);

        let mut e = json!({"filepath": "a.rs", "old_str": "a", "new_string": "b", "replace_all": true});
        assert!(!normalize_for_tool("edit", &mut e).is_empty());
        assert_eq!(e, json!({"path": "a.rs", "old": "a", "new": "b", "all": true}));

        let mut w = json!({"filename": "w.txt", "file_text": "hi"});
        assert!(!normalize_for_tool("write", &mut w).is_empty());
        assert_eq!(w, json!({"path": "w.txt", "content": "hi"}));

        let mut b = json!({"cmd": "echo hi", "timeout_ms": 1500, "idle_timeout_ms": 1});
        assert!(!normalize_for_tool("bash", &mut b).is_empty());
        assert_eq!(b["command"], "echo hi");
        assert_eq!(b["timeout_s"], 2);
        assert_eq!(b["idle_timeout_s"], 1);

        let mut g = json!({"query": "foo", "dir": "src", "max_results": 20});
        assert!(!normalize_for_tool("grep", &mut g).is_empty());
        assert_eq!(g, json!({"pattern": "foo", "path": "src", "max": 20}));

        let mut gl = json!({"directory": "src", "glob": "*.rs"});
        assert!(!normalize_for_tool("glob", &mut gl).is_empty());
        assert_eq!(gl, json!({"path": "src", "pattern": "*.rs"}));

        let mut or = json!({"handle": "out:1", "total_lines": 500, "offset": 5, "limit": 25});
        let or_notes = normalize_for_tool("out_read", &mut or);
        assert!(or_notes.iter().any(|n| n.contains("total_lines")), "{or_notes:?}");
        assert_eq!(or, json!({"handle": "out:1", "start": 5, "end": 29}), "`limit` is a count of lines");
        // The case that was refused: lines 100 to 149, not an end before the start.
        let mut or2 = json!({"handle": "out:1", "offset": 100, "limit": 50});
        let notes2 = normalize_for_tool("out_read", &mut or2);
        assert_eq!(or2, json!({"handle": "out:1", "start": 100, "end": 149}));
        assert!(notes2.iter().any(|n| n.contains("`limit` (50) -> `end` (149)")), "{notes2:?}");
        // A given `end` wins, and a `limit` alone counts from line 1.
        let mut or3 = json!({"handle": "out:1", "start": 3, "end_line": 9, "limit": 50});
        normalize_for_tool("out_read", &mut or3);
        assert_eq!(or3["end"], json!(9));
        let mut or4 = json!({"handle": "out:1", "limit": 20});
        normalize_for_tool("out_read", &mut or4);
        assert_eq!(or4, json!({"handle": "out:1", "end": 20}));

        let mut cu = json!({"claim_id": "c1"});
        assert!(!normalize_for_tool("claim_update", &mut cu).is_empty());
        assert_eq!(cu, json!({"id": "c1"}));

        let mut cl = json!({"statement": "fact"});
        assert!(!normalize_for_tool("claim", &mut cl).is_empty());
        assert_eq!(cl, json!({"text": "fact"}));

        let mut fin = json!({"summary": "done"});
        assert!(!normalize_for_tool("finish", &mut fin).is_empty());
        assert_eq!(fin, json!({"answer": "done"}));

        let mut sp = json!({"task": "check auth", "steps": 6});
        assert!(!normalize_for_tool("agent_spawn", &mut sp).is_empty());
        assert_eq!(sp, json!({"question": "check auth", "max_steps": 6}));

        let mut fo = json!({"agents": [{"prompt": "scan", "steps": 4}]});
        assert!(!normalize_for_tool("agent_fanout", &mut fo).is_empty());
        assert_eq!(fo["agents"][0], json!({"question": "scan", "max_steps": 4}));

        let mut st = json!({"step_id": "s1"});
        assert!(!normalize_for_tool("step", &mut st).is_empty());
        assert_eq!(st, json!({"id": "s1"}));

        let mut sec = json!({"action": "asset_upsert", "kind": "endpoint"});
        assert!(!normalize_for_tool("security_record", &mut sec).is_empty());
        assert_eq!(sec, json!({"operation": {"action": "asset_upsert", "kind": "endpoint"}}));
    }

    #[test]
    fn prepare_for_spec_strips_vendor_delimiters_and_clamps_max() {
        let s = crate::params::spec(
            "bash",
            "run",
            crate::ToolClass::Write,
            &[
                crate::params::req("command", "string", "cmd"),
                crate::params::opt("timeout_s", "integer", "timeout").min(1).max(600),
            ],
        )
        .parameters;
        let mut args = json!({
            "cmd": "echo ok",
            "timeout_s": "<|open|>argument key=\"timeout_s\"<|sep|>1200"
        });
        let mut notes = normalize_for_tool("bash", &mut args);
        notes.extend(prepare_for_spec(&s, &mut args));
        let checked = check(&s, &args).unwrap();
        assert_eq!(checked.args["timeout_s"], 600);
        assert!(notes.len() >= 2, "{notes:?}");
    }
}
