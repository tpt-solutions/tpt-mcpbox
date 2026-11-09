// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Evaluation of a compiled module against one input.
//!
//! Each statement maps one variable environment to the environments it
//! produces. An expression with several values, such as `input.uris[_]`,
//! produces several environments, and a body holds when at least one survives
//! every statement. Undefined values produce no environment, so they make the
//! expression false, as in Rego. Type errors stop the query with an error, and
//! every error is a refusal.

use std::cell::{Cell, RefCell};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

use serde_json::{Number, Value};

use super::builtins;
use super::parse::{Access, Base, Body, Module, Op, Statement, Term};

/// Upper bound on evaluation steps for one request. A module that iterates
/// over large input cannot run unbounded.
const STEP_LIMIT: u64 = 1_000_000;

type Env = BTreeMap<String, Value>;

/// Evaluates `allow` against `input`. An undefined `allow` (no default and no
/// true body) is an error, so the request is refused.
pub(crate) fn allows(module: &Module, input: &Value) -> Result<bool, String> {
    let machine = Machine {
        module,
        input,
        steps: Cell::new(0),
        cache: RefCell::new(HashMap::new()),
    };
    match machine.rule("allow")? {
        Some(allowed) => Ok(allowed),
        None => Err("`allow` is undefined".to_owned()),
    }
}

struct Machine<'m> {
    module: &'m Module,
    input: &'m Value,
    steps: Cell<u64>,
    /// Results of rules already evaluated for this input.
    cache: RefCell<HashMap<String, Option<bool>>>,
}

impl Machine<'_> {
    /// The value of a boolean rule: `Some(true)` when a body holds, the default
    /// otherwise, and `None` when it is undefined.
    fn rule(&self, name: &str) -> Result<Option<bool>, String> {
        let cached = self.cache.borrow().get(name).copied();
        if let Some(value) = cached {
            return Ok(value);
        }
        let mut value = None;
        if let Some(bodies) = self.module.rules.get(name) {
            for body in bodies {
                if !self.body(body, Env::new())?.is_empty() {
                    value = Some(true);
                    break;
                }
            }
        }
        if value.is_none() {
            value = self.module.defaults.get(name).copied();
        }
        self.cache.borrow_mut().insert(name.to_owned(), value);
        Ok(value)
    }

    /// The value of a rule named by a bare identifier, if it is one.
    fn rule_value(&self, name: &str) -> Result<Option<bool>, String> {
        if self.module.rules.contains_key(name) {
            self.rule(name)
        } else {
            Ok(None)
        }
    }

    fn tick(&self) -> Result<(), String> {
        let steps = self.steps.get() + 1;
        self.steps.set(steps);
        if steps > STEP_LIMIT {
            Err("the evaluation budget is exhausted".to_owned())
        } else {
            Ok(())
        }
    }

    /// The environments under which every statement of `body` holds.
    fn body(&self, body: &Body, env: Env) -> Result<Vec<Env>, String> {
        let mut envs = vec![env];
        for statement in &body.statements {
            let mut next = Vec::new();
            for env in envs {
                next.extend(self.statement(statement, env)?);
            }
            if next.is_empty() {
                return Ok(next);
            }
            envs = next;
        }
        Ok(envs)
    }

    fn statement(&self, statement: &Statement, env: Env) -> Result<Vec<Env>, String> {
        self.tick()?;
        match statement {
            Statement::Term(term) => Ok(self
                .term(term, &env)?
                .into_iter()
                .filter(|(value, _)| *value != Value::Bool(false))
                .map(|(_, env)| env)
                .collect()),
            Statement::Not(inner) => {
                let found = self.statement(inner, env.clone())?;
                Ok(if found.is_empty() {
                    vec![env]
                } else {
                    Vec::new()
                })
            }
            Statement::Compare { op, left, right } => {
                let mut out = Vec::new();
                for (lhs, env) in self.term(left, &env)? {
                    for (rhs, env) in self.term(right, &env)? {
                        if compare(*op, &lhs, &rhs) {
                            out.push(env);
                        }
                    }
                }
                Ok(out)
            }
            Statement::Unify { left, right } => self.unify(left, right, env),
            Statement::In { member, collection } => {
                let mut out = Vec::new();
                for (items, env) in self.term(collection, &env)? {
                    let Value::Array(items) = items else {
                        return Err("`in` needs an array on its right".to_owned());
                    };
                    for (value, env) in self.term(member, &env)? {
                        if items.iter().any(|item| equal(item, &value)) {
                            out.push(env);
                        }
                    }
                }
                Ok(out)
            }
            Statement::SomeIn { name, collection } => {
                let mut out = Vec::new();
                for (items, env) in self.term(collection, &env)? {
                    let Value::Array(items) = items else {
                        return Err("`some ... in` needs an array".to_owned());
                    };
                    for item in items {
                        let mut bound = env.clone();
                        bound.insert(name.clone(), item);
                        out.push(bound);
                    }
                }
                Ok(out)
            }
        }
    }

    /// `left = right`. An unbound variable on either side is bound to the other
    /// side's values; otherwise the two sides must be equal.
    fn unify(&self, left: &Term, right: &Term, env: Env) -> Result<Vec<Env>, String> {
        for (target, source) in [(left, right), (right, left)] {
            if let Term::Var(name) = target
                && !env.contains_key(name)
                && !self.module.rules.contains_key(name)
            {
                let mut out = Vec::new();
                for (value, env) in self.term(source, &env)? {
                    let mut bound = env;
                    bound.insert(name.clone(), value);
                    out.push(bound);
                }
                return Ok(out);
            }
        }
        let mut out = Vec::new();
        for (lhs, env) in self.term(left, &env)? {
            for (rhs, env) in self.term(right, &env)? {
                if equal(&lhs, &rhs) {
                    out.push(env);
                }
            }
        }
        Ok(out)
    }

    /// Every value a term can take, each with the environment it was found in.
    fn term(&self, term: &Term, env: &Env) -> Result<Vec<(Value, Env)>, String> {
        self.tick()?;
        match term {
            Term::Null => Ok(vec![(Value::Null, env.clone())]),
            Term::Bool(value) => Ok(vec![(Value::Bool(*value), env.clone())]),
            Term::Num(value) => {
                let number = Number::from_f64(*value)
                    .ok_or_else(|| "a number literal is not finite".to_owned())?;
                Ok(vec![(Value::Number(number), env.clone())])
            }
            Term::Str(text) => Ok(vec![(Value::String(text.clone()), env.clone())]),
            Term::Array(items) => {
                let combined = self.combine(items, env)?;
                Ok(combined
                    .into_iter()
                    .map(|(values, env)| (Value::Array(values), env))
                    .collect())
            }
            Term::Var(name) => match env.get(name) {
                Some(value) => Ok(vec![(value.clone(), env.clone())]),
                // Not a local: the name is a rule of the module (checked at load).
                None => Ok(self
                    .rule_value(name)?
                    .map(|value| (Value::Bool(value), env.clone()))
                    .into_iter()
                    .collect()),
            },
            Term::Wildcard => Err("`_` can only be used as an index".to_owned()),
            Term::Call { name, args } => {
                let mut out = Vec::new();
                for (values, env) in self.combine(args, env)? {
                    if let Some(value) = builtins::call(name, &values)? {
                        out.push((value, env));
                    }
                }
                Ok(out)
            }
            Term::Ref { base, path } => self.reference(base, path, env),
        }
    }

    /// The cartesian product of the values of `terms`, threading environments.
    fn combine(&self, terms: &[Term], env: &Env) -> Result<Vec<(Vec<Value>, Env)>, String> {
        let mut partial = vec![(Vec::new(), env.clone())];
        for term in terms {
            let mut next = Vec::new();
            for (values, env) in partial {
                for (value, env) in self.term(term, &env)? {
                    let mut values = values.clone();
                    values.push(value);
                    next.push((values, env));
                }
            }
            partial = next;
        }
        Ok(partial)
    }

    fn reference(
        &self,
        base: &Base,
        path: &[Access],
        env: &Env,
    ) -> Result<Vec<(Value, Env)>, String> {
        if let Base::Data = base {
            // The compiler guarantees the shape `data.tpt.mcpbox.NAME`.
            let Some(Access::Field(name)) = path.get(2) else {
                return Err("malformed data reference".to_owned());
            };
            return Ok(match self.rule(name)? {
                Some(value) => vec![(Value::Bool(value), env.clone())],
                None => Vec::new(),
            });
        }
        let start = match base {
            Base::Input => self.input.clone(),
            Base::Var(name) => match env.get(name) {
                Some(value) => value.clone(),
                None => match self.rule_value(name)? {
                    Some(value) => Value::Bool(value),
                    None => return Ok(Vec::new()),
                },
            },
            Base::Data => unreachable!("handled above"),
        };
        let mut current = vec![(start, env.clone())];
        for access in path {
            let mut next = Vec::new();
            for (value, env) in current {
                match access {
                    Access::Field(field) => {
                        if let Value::Object(map) = &value
                            && let Some(child) = map.get(field)
                        {
                            next.push((child.clone(), env));
                        }
                    }
                    Access::Index(index) => next.extend(self.index(&value, index, env)?),
                }
            }
            current = next;
        }
        Ok(current)
    }

    /// `container[index]`. An unbound variable or `_` iterates over the
    /// container instead, binding the variable to each index or key.
    fn index(
        &self,
        container: &Value,
        index: &Term,
        env: Env,
    ) -> Result<Vec<(Value, Env)>, String> {
        match index {
            Term::Wildcard => Ok(elements(container)
                .into_iter()
                .map(|(_, value)| (value.clone(), env.clone()))
                .collect()),
            Term::Var(name) if !env.contains_key(name) => Ok(elements(container)
                .into_iter()
                .map(|(key, value)| {
                    let mut bound = env.clone();
                    bound.insert(name.clone(), key);
                    (value.clone(), bound)
                })
                .collect()),
            _ => {
                let mut out = Vec::new();
                for (key, env) in self.term(index, &env)? {
                    if let Some(value) = lookup(container, &key) {
                        out.push((value.clone(), env));
                    }
                }
                Ok(out)
            }
        }
    }
}

/// `(key, value)` pairs of an array (keys are indices) or an object (keys are
/// names). Other values have no elements.
fn elements(container: &Value) -> Vec<(Value, &Value)> {
    match container {
        Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(i, item)| (Value::from(i), item))
            .collect(),
        Value::Object(map) => map
            .iter()
            .map(|(key, item)| (Value::String(key.clone()), item))
            .collect(),
        _ => Vec::new(),
    }
}

/// The element at `key`, if the container has one.
fn lookup<'v>(container: &'v Value, key: &Value) -> Option<&'v Value> {
    match (container, key) {
        (Value::Array(items), Value::Number(number)) => {
            let index = number.as_f64()?;
            if index.fract() != 0.0 || index < 0.0 {
                return None;
            }
            items.get(index as usize)
        }
        (Value::Object(map), Value::String(name)) => map.get(name),
        _ => None,
    }
}

/// Rego equality: numbers compare by value, and arrays and objects compare
/// element by element.
fn equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(a), Value::Number(b)) => a.as_f64() == b.as_f64(),
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| equal(x, y))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, value)| b.get(key).is_some_and(|other| equal(value, other)))
        }
        _ => left == right,
    }
}

/// A comparison. Ordering is defined for two numbers or two strings; for other
/// types it is undefined, which is false.
fn compare(op: Op, left: &Value, right: &Value) -> bool {
    match op {
        Op::Eq => equal(left, right),
        Op::Ne => !equal(left, right),
        Op::Lt | Op::Le | Op::Gt | Op::Ge => {
            let ordering = match (left, right) {
                (Value::Number(a), Value::Number(b)) => a.as_f64().partial_cmp(&b.as_f64()),
                (Value::String(a), Value::String(b)) => Some(a.cmp(b)),
                _ => None,
            };
            match (ordering, op) {
                (Some(o), Op::Lt) => o == Ordering::Less,
                (Some(o), Op::Le) => o != Ordering::Greater,
                (Some(o), Op::Gt) => o == Ordering::Greater,
                (Some(o), Op::Ge) => o != Ordering::Less,
                _ => false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{allows, equal};
    use crate::rego::parse::compile;

    fn decide(source: &str, input: serde_json::Value) -> Result<bool, String> {
        allows(&compile(source).expect("compiles"), &input)
    }

    #[test]
    fn numbers_compare_by_value() {
        assert!(equal(&json!(1), &json!(1.0)));
        assert!(!equal(&json!(1), &json!("1")));
    }

    #[test]
    fn iteration_is_existential() {
        let source = "package tpt.mcpbox\nallow if { input.uris[_] == \"file:///b\" }";
        assert_eq!(
            decide(source, json!({"uris": ["file:///a", "file:///b"]})),
            Ok(true)
        );
        assert_eq!(
            decide(source, json!({"uris": ["file:///a"]})),
            Err("`allow` is undefined".to_owned())
        );
    }

    #[test]
    fn a_bound_index_variable_is_usable() {
        let source = "package tpt.mcpbox\nallow if { some u in input.uris\n u == \"x\" }";
        assert_eq!(decide(source, json!({"uris": ["x"]})), Ok(true));
    }

    #[test]
    fn not_negates_undefined_and_false() {
        let source = "package tpt.mcpbox\ndefault allow := false\nallow if { not input.secret }";
        assert_eq!(decide(source, json!({})), Ok(true));
        assert_eq!(decide(source, json!({"secret": true})), Ok(false));
    }

    #[test]
    fn a_missing_field_makes_a_comparison_false() {
        let source = "package tpt.mcpbox\ndefault allow := false\nallow if { input.tool == \"x\" }";
        assert_eq!(decide(source, json!({})), Ok(false));
    }

    #[test]
    fn a_type_error_is_an_error_not_an_allow() {
        let source =
            "package tpt.mcpbox\ndefault allow := false\nallow if { startswith(input.n, \"a\") }";
        assert!(decide(source, json!({"n": 3})).is_err());
    }

    #[test]
    fn rules_can_use_other_rules_and_defaults_apply() {
        let source = "package tpt.mcpbox\ndefault allow := false\nallow if { helper }\nhelper if { input.ok == true }";
        assert_eq!(decide(source, json!({"ok": true})), Ok(true));
        assert_eq!(decide(source, json!({"ok": false})), Ok(false));
    }

    #[test]
    fn a_body_with_a_false_statement_does_not_hold() {
        let source = "package tpt.mcpbox\ndefault allow := false\nallow if {\n  1 < 2\n  2 < 1\n}";
        assert_eq!(decide(source, json!({})), Ok(false));
    }

    #[test]
    fn assignment_binds_for_later_statements() {
        let source = "package tpt.mcpbox\ndefault allow := false\nallow if {\n  t := input.tool\n  t == \"read\"\n}";
        assert_eq!(decide(source, json!({"tool": "read"})), Ok(true));
    }

    #[test]
    fn membership_checks_an_array() {
        let source =
            "package tpt.mcpbox\ndefault allow := false\nallow if { input.tool in [\"a\", \"b\"] }";
        assert_eq!(decide(source, json!({"tool": "b"})), Ok(true));
        assert_eq!(decide(source, json!({"tool": "c"})), Ok(false));
    }
}
