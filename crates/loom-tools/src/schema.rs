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
        assert_eq!(p, ["unknown argument `zzzzzzzz`; this tool takes: path, start, limit, ratio, force, mode, names, opts"]);
        let p = check(&json!({"properties": {"a": {"type": "string"}, "b": {"type": "string"}}}), &json!({"c": 1})).unwrap_err();
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
}
