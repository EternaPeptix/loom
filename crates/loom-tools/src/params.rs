//! Building tool specs. Descriptions are part of the request prefix: they must not vary.

use loom_core::event::{ToolClass, ToolSpec};
use serde_json::{json, Map, Value};

#[derive(Clone, Debug)]
pub struct Param {
    name: String,
    required: bool,
    schema: Map<String, Value>,
}

fn param(name: &str, kind: &str, description: &str, required: bool) -> Param {
    let mut schema = Map::new();
    schema.insert("type".into(), json!(kind));
    schema.insert("description".into(), json!(description));
    Param { name: name.to_string(), required, schema }
}

/// A required argument.
pub fn req(name: &str, kind: &str, description: &str) -> Param {
    param(name, kind, description, true)
}

/// An optional argument.
pub fn opt(name: &str, kind: &str, description: &str) -> Param {
    param(name, kind, description, false)
}

impl Param {
    pub fn min(mut self, n: i64) -> Param {
        self.schema.insert("minimum".into(), json!(n));
        self
    }

    pub fn max(mut self, n: i64) -> Param {
        self.schema.insert("maximum".into(), json!(n));
        self
    }

    pub fn default(mut self, v: Value) -> Param {
        self.schema.insert("default".into(), v);
        self
    }

    pub fn one_of(mut self, values: &[&str]) -> Param {
        self.schema.insert("enum".into(), json!(values));
        self
    }

    /// For `array` arguments: the type of each element.
    pub fn items(mut self, kind: &str) -> Param {
        self.schema.insert("items".into(), json!({ "type": kind }));
        self
    }

    /// For `array`/`object` arguments: a full schema for the elements or the object.
    pub fn with(mut self, key: &str, v: Value) -> Param {
        self.schema.insert(key.to_string(), v);
        self
    }
}

/// The parameter schema for a list of arguments.
pub fn object(params: &[Param]) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for p in params {
        properties.insert(p.name.clone(), Value::Object(p.schema.clone()));
        if p.required {
            required.push(json!(p.name));
        }
    }
    json!({ "type": "object", "properties": properties, "required": required, "additionalProperties": false })
}

pub fn spec(name: &str, description: &str, class: ToolClass, params: &[Param]) -> ToolSpec {
    ToolSpec { name: name.to_string(), description: description.to_string(), parameters: object(params), class }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_shape_and_order() {
        let s = spec("t", "d", ToolClass::Read, &[req("b", "string", "B"), opt("a", "integer", "A").min(1)]);
        assert_eq!(
            s.parameters.to_string(),
            r#"{"type":"object","properties":{"b":{"type":"string","description":"B"},"a":{"type":"integer","description":"A","minimum":1}},"required":["b"],"additionalProperties":false}"#
        );
    }
}
