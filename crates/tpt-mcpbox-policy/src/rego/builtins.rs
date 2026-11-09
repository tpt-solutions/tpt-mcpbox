// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! The builtins available to the Rego subset.
//!
//! A call with the wrong argument types is an error, which fails the request
//! closed. A value that cannot be produced, such as a normalisation that
//! rejects its input, is undefined: the expression is then false and an allow
//! built on it does not fire.

use serde_json::Value;

use crate::normalize::{normalize_host, normalize_path, normalize_uri};

/// The number of arguments a builtin takes, or `None` for an unknown name.
pub(crate) fn arity(name: &str) -> Option<usize> {
    match name {
        "startswith" | "endswith" | "contains" => Some(2),
        "lower" | "upper" | "count" | "is_string" | "is_number" | "is_boolean" | "is_array"
        | "is_object" | "is_null" | "tpt.normalize_host" | "tpt.normalize_path"
        | "tpt.normalize_uri" => Some(1),
        _ => None,
    }
}

/// Calls a builtin. `Ok(None)` means undefined; `Err` is a type error.
pub(crate) fn call(name: &str, args: &[Value]) -> Result<Option<Value>, String> {
    let string = |index: usize| -> Result<&str, String> {
        args.get(index)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("`{name}` needs a string argument"))
    };
    let boolean = |value: bool| Ok(Some(Value::Bool(value)));
    match name {
        "startswith" => boolean(string(0)?.starts_with(string(1)?)),
        "endswith" => boolean(string(0)?.ends_with(string(1)?)),
        "contains" => boolean(string(0)?.contains(string(1)?)),
        "lower" => Ok(Some(Value::String(string(0)?.to_lowercase()))),
        "upper" => Ok(Some(Value::String(string(0)?.to_uppercase()))),
        "count" => {
            let count = match args.first() {
                Some(Value::Array(items)) => items.len(),
                Some(Value::Object(map)) => map.len(),
                Some(Value::String(text)) => text.chars().count(),
                _ => return Err("`count` needs an array, object or string".to_owned()),
            };
            Ok(Some(Value::from(count)))
        }
        "is_string" => boolean(matches!(args.first(), Some(Value::String(_)))),
        "is_number" => boolean(matches!(args.first(), Some(Value::Number(_)))),
        "is_boolean" => boolean(matches!(args.first(), Some(Value::Bool(_)))),
        "is_array" => boolean(matches!(args.first(), Some(Value::Array(_)))),
        "is_object" => boolean(matches!(args.first(), Some(Value::Object(_)))),
        "is_null" => boolean(matches!(args.first(), Some(Value::Null))),
        "tpt.normalize_host" => Ok(normalised(args, normalize_host)),
        "tpt.normalize_path" => Ok(normalised(args, normalize_path)),
        "tpt.normalize_uri" => Ok(normalised(args, normalize_uri)),
        _ => Err(format!("unknown builtin `{name}`")),
    }
}

/// The normalised string, or undefined for a non-string or a value that the
/// normaliser rejects.
fn normalised(args: &[Value], normalise: fn(&str) -> Option<String>) -> Option<Value> {
    args.first()
        .and_then(Value::as_str)
        .and_then(normalise)
        .map(Value::String)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::call;

    #[test]
    fn string_builtins_check_their_types() {
        assert_eq!(
            call("startswith", &[json!("secret/a"), json!("secret/")]).unwrap(),
            Some(json!(true))
        );
        assert!(call("startswith", &[json!(1), json!("x")]).is_err());
    }

    #[test]
    fn normalisers_are_undefined_when_they_cannot_normalise() {
        assert_eq!(
            call("tpt.normalize_host", &[json!("API.GitHub.com.")]).unwrap(),
            Some(json!("api.github.com"))
        );
        assert_eq!(call("tpt.normalize_host", &[json!("")]).unwrap(), None);
        assert_eq!(call("tpt.normalize_path", &[json!(7)]).unwrap(), None);
    }
}
