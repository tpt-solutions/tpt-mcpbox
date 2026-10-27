// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! JSON Schema emission for editor completion and CI validation.
//!
//! `tpt-mcpbox schema` writes this to stdout so `yaml-language-server` (or any
//! other editor) can validate `tpt-mcpbox.yaml` while it is being written. The
//! schema is derived from the same types the loader uses, so it cannot drift
//! from the parser: `deny_unknown_fields` on the model means the schema also
//! rejects unknown keys.
//!
//! ```console
//! tpt-mcpbox schema > tpt-mcpbox.schema.json
//! ```

use schemars::{Schema, SchemaGenerator, generate::SchemaSettings};

use crate::model::Config;

/// JSON Schema `$schema` value.
pub const SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

/// `$id` written into the generated document.
pub const SCHEMA_ID: &str = "https://tpt-solutions.github.io/tpt-mcpbox/schema.json";

/// Build the root JSON Schema for [`Config`], including `$defs`.
///
/// The root schema (not the bare type schema) is what an editor needs: it
/// carries the shared definitions that the type schemas `$ref` into.
///
/// `schemars` does not infer `additionalProperties: false` from
/// `#[serde(deny_unknown_fields)]`, so [`json_schema`] closes the objects
/// itself; the loader remains the enforcement point either way.
#[must_use]
pub fn config_schema() -> Schema {
    let generator = SchemaGenerator::new(SchemaSettings::draft2020_12());
    generator.into_root_schema_for::<Config>()
}

/// Mark every object that declares `properties` as closed, unless it already
/// describes open keys (`patternProperties` / `additionalProperties`).
fn close_objects(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let declares_properties = map
                .get("properties")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|properties| !properties.is_empty());
            let describes_open_keys =
                map.contains_key("patternProperties") || map.contains_key("additionalProperties");
            if declares_properties && !describes_open_keys {
                map.insert(
                    "additionalProperties".to_owned(),
                    serde_json::Value::Bool(false),
                );
            }
            for child in map.values_mut() {
                close_objects(child);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                close_objects(item);
            }
        }
        _ => {}
    }
}

/// The schema as a JSON value, ready to serialize.
#[must_use]
pub fn json_schema() -> serde_json::Value {
    let mut schema =
        serde_json::to_value(config_schema()).unwrap_or_else(|_| serde_json::json!({}));
    close_objects(&mut schema);
    if let Some(object) = schema.as_object_mut() {
        object.insert(
            "$schema".to_owned(),
            serde_json::Value::String(SCHEMA_DIALECT.to_owned()),
        );
        object.insert(
            "$id".to_owned(),
            serde_json::Value::String(SCHEMA_ID.to_owned()),
        );
        object.insert(
            "title".to_owned(),
            serde_json::Value::String("tpt-mcpbox configuration".to_owned()),
        );
        object.insert(
            "description".to_owned(),
            serde_json::Value::String(
                "Local-first, zero-trust MCP proxy configuration. Unknown keys are rejected: a \
                 capability typo must fail loudly rather than silently widen authority."
                    .to_owned(),
            ),
        );
    }
    schema
}

/// The schema rendered as pretty-printed JSON.
#[must_use]
pub fn json_schema_string() -> String {
    serde_json::to_string_pretty(&json_schema()).unwrap_or_else(|_| "{}".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Follow `$ref` / single-element `allOf` chains into `$defs`.
    fn resolve<'a>(
        root: &'a serde_json::Value,
        schema: &'a serde_json::Value,
    ) -> serde_json::Value {
        fn lookup<'a>(root: &'a serde_json::Value, reference: &str) -> &'a serde_json::Value {
            reference
                .strip_prefix("#/")
                .map(|path| {
                    path.split('/')
                        .fold(root, |current, segment| &current[segment])
                })
                .unwrap_or(root)
        }

        let mut node: &'a serde_json::Value = schema;
        for _ in 0..8 {
            if let Some(reference) = node.get("$ref").and_then(serde_json::Value::as_str) {
                node = lookup(root, reference);
                continue;
            }
            if let Some(items) = node.get("allOf").and_then(serde_json::Value::as_array)
                && items.len() == 1
            {
                node = &items[0];
                continue;
            }
            break;
        }
        node.clone()
    }

    #[test]
    fn schema_declares_the_documented_sections() {
        let schema = json_schema();
        let properties = &schema["properties"];
        for section in [
            "version",
            "server",
            "tools",
            "upstreams",
            "policy",
            "audit",
            "metrics",
            "logging",
        ] {
            assert!(
                properties.get(section).is_some(),
                "missing `{section}` in schema"
            );
        }
    }

    #[test]
    fn tool_sections_reject_unknown_keys() {
        let schema = json_schema();
        let tools = resolve(&schema, &schema["properties"]["tools"]["items"]);
        assert_eq!(
            tools["additionalProperties"],
            serde_json::json!(false),
            "tools must reject unknown fields"
        );
        assert!(tools["properties"]["wasm_path"].is_object());
        assert!(tools["properties"]["capabilities"].is_object());
    }

    #[test]
    fn capabilities_expose_the_spec_fields() {
        let schema = json_schema();
        let tools = resolve(&schema, &schema["properties"]["tools"]["items"]);
        let capabilities = resolve(&schema, &tools["properties"]["capabilities"]);
        for field in ["network", "filesystem", "memory_limit", "time_limit", "env"] {
            assert!(
                capabilities["properties"].get(field).is_some(),
                "missing `{field}`"
            );
        }
    }

    #[test]
    fn the_schema_is_draft_2020_12() {
        let schema = json_schema();
        assert_eq!(schema["$schema"], SCHEMA_DIALECT);
        assert_eq!(schema["$id"], SCHEMA_ID);
    }

    #[test]
    fn open_keyed_objects_stay_open() {
        let schema = json_schema();
        let policy = resolve(&schema, &schema["properties"]["policy"]);
        let rules = resolve(&schema, &policy["properties"]["rules"]["items"]);
        // `args` is a free-form map: it must not be closed.
        assert_ne!(
            rules["properties"]["args"]["additionalProperties"],
            serde_json::json!(false)
        );
    }

    #[test]
    fn the_schema_carries_definitions() {
        let schema = json_schema();
        assert!(
            schema["$defs"]["ToolConfig"].is_object(),
            "root schema must carry $defs"
        );
    }

    #[test]
    fn the_schema_is_valid_json() {
        let rendered = json_schema_string();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
        assert!(parsed["properties"].is_object());
    }
}
