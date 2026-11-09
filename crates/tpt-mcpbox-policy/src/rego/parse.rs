// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Parser and compile-time checks for the Rego subset.
//!
//! The subset, in Rego v1 syntax:
//!
//! * `package tpt.mcpbox`, and `import rego.v1` or `import future.keywords...`;
//! * `default NAME := true|false`;
//! * boolean rules: `NAME if { ... }`, `NAME if EXPR`, or `NAME { ... }`, with
//!   several definitions of one name allowed (any true body makes it true);
//! * statements, separated by newlines or `;`: `not S`, `TERM`, `==`, `!=`,
//!   `<`, `<=`, `>`, `>=`, `=` (unifies, binding an unbound variable), `:=`
//!   (binds), `X in COLLECTION`, and `some X in COLLECTION`;
//! * terms: strings, numbers, `true`, `false`, `null`, arrays, `input` and
//!   `data.tpt.mcpbox.NAME` references, variables, `_` and bracket indexing
//!   (`input.uris[_]`), and calls to the builtins in [`super::builtins`].
//!
//! Statements run in the order written. A variable must be bound by an earlier
//! statement, and a reference to a rule must name a rule of this module. Rules
//! may not refer to each other in a cycle. Anything else is a compile error, so
//! a module that uses an unsupported form is refused when it loads, not at the
//! first request.

use std::collections::{BTreeMap, BTreeSet};

use super::builtins;
use super::lex::{Kind, Token, tokenize};

/// A compiled module.
#[derive(Debug)]
pub(crate) struct Module {
    /// Boolean rules by name, each with all its bodies.
    pub(crate) rules: BTreeMap<String, Vec<Body>>,
    /// Defaults for rules, used when no body is true.
    pub(crate) defaults: BTreeMap<String, bool>,
}

/// One body: statements that must all hold.
#[derive(Debug)]
pub(crate) struct Body {
    pub(crate) statements: Vec<Statement>,
}

/// One statement of a body.
#[derive(Debug)]
pub(crate) enum Statement {
    /// True unless it evaluates to `false` or is undefined.
    Term(Term),
    /// Holds when the inner statement has no solution.
    Not(Box<Statement>),
    /// Comparison with `==`, `!=`, `<`, `<=`, `>` or `>=`.
    Compare { op: Op, left: Term, right: Term },
    /// `=` and `:=`: unifies, binding an unbound variable on either side.
    Unify { left: Term, right: Term },
    /// `member in collection`.
    In { member: Term, collection: Term },
    /// `some name in collection`: binds `name` to each element in turn.
    SomeIn { name: String, collection: Term },
}

/// Comparison operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// A term.
#[derive(Debug, Clone)]
pub(crate) enum Term {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Array(Vec<Term>),
    Var(String),
    Wildcard,
    Ref { base: Base, path: Vec<Access> },
    Call { name: String, args: Vec<Term> },
}

/// What a reference starts from.
#[derive(Debug, Clone)]
pub(crate) enum Base {
    Input,
    /// `data.tpt.mcpbox...`. The path must be exactly `tpt.mcpbox.NAME`.
    Data,
    Var(String),
}

/// One step of a reference.
#[derive(Debug, Clone)]
pub(crate) enum Access {
    Field(String),
    Index(Term),
}

/// Parses and checks a module. `package` must be `tpt.mcpbox`.
pub(crate) fn compile(source: &str) -> Result<Module, String> {
    let tokens = tokenize(source)?;
    let mut parser = Parser {
        tokens,
        pos: 0,
        module: Module {
            rules: BTreeMap::new(),
            defaults: BTreeMap::new(),
        },
        free: Vec::new(),
    };
    parser.module()?;
    let module = parser.module;
    // A name used before any binding must name a rule of this module.
    for (line, name) in &parser.free {
        if !module.rules.contains_key(name) {
            return Err(format!(
                "line {line}: variable `{name}` is used before it is bound (statements run in order)"
            ));
        }
    }
    check_references(&module)?;
    Ok(module)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    module: Module,
    /// Names used by a statement without being bound. Each must be a rule name,
    /// which is only known once the whole module has been read.
    free: Vec<(usize, String)>,
}

/// Variables a statement may use, and the ones it introduces.
#[derive(Default)]
struct Scope {
    /// Bound by an earlier statement of the same body.
    bound: BTreeSet<String>,
}

/// Per-statement bookkeeping: variables it uses and binds.
#[derive(Default)]
struct Usage {
    used: Vec<String>,
    binds: BTreeSet<String>,
}

impl Parser {
    fn peek(&self) -> &Kind {
        &self.tokens[self.pos].kind
    }

    fn line(&self) -> usize {
        self.tokens[self.pos].line
    }

    fn advance(&mut self) -> Kind {
        let kind = self.tokens[self.pos].kind.clone();
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
        kind
    }

    fn error<T>(&self, message: &str) -> Result<T, String> {
        Err(format!("line {}: {message}", self.line()))
    }

    fn at_punct(&self, punct: &str) -> bool {
        matches!(self.peek(), Kind::Punct(p) if *p == punct)
    }

    fn at_word(&self, word: &str) -> bool {
        matches!(self.peek(), Kind::Ident(w) if w == word)
    }

    fn expect_punct(&mut self, punct: &str) -> Result<(), String> {
        if self.at_punct(punct) {
            self.advance();
            Ok(())
        } else {
            self.error(&format!("expected `{punct}`"))
        }
    }

    fn skip_newlines(&mut self) {
        while matches!(self.peek(), Kind::Newline) {
            self.advance();
        }
    }

    fn skip_separators(&mut self) {
        while matches!(self.peek(), Kind::Newline) || self.at_punct(";") {
            self.advance();
        }
    }

    fn identifier(&mut self) -> Result<String, String> {
        match self.peek().clone() {
            Kind::Ident(name) => {
                self.advance();
                Ok(name)
            }
            _ => self.error("expected a name"),
        }
    }

    /// `package`, `import`, `default` and rules, until the end of the file.
    fn module(&mut self) -> Result<(), String> {
        self.skip_separators();
        if !self.at_word("package") {
            return self.error("a module must start with `package tpt.mcpbox`");
        }
        self.advance();
        let mut name = vec![self.identifier()?];
        while self.at_punct(".") {
            self.advance();
            name.push(self.identifier()?);
        }
        if name != ["tpt", "mcpbox"] {
            return self.error("the package must be `tpt.mcpbox`");
        }
        self.skip_separators();

        while !matches!(self.peek(), Kind::Eof) {
            if self.at_word("import") {
                self.import()?;
            } else if self.at_word("default") {
                self.default_rule()?;
            } else {
                self.rule()?;
            }
            self.skip_separators();
        }
        Ok(())
    }

    fn import(&mut self) -> Result<(), String> {
        self.advance();
        let mut path = vec![self.identifier()?];
        while self.at_punct(".") {
            self.advance();
            path.push(self.identifier()?);
        }
        let allowed = path == ["rego", "v1"] || path.first().map(String::as_str) == Some("future");
        if allowed {
            Ok(())
        } else {
            self.error("only `import rego.v1` and `import future.keywords` are supported")
        }
    }

    fn default_rule(&mut self) -> Result<(), String> {
        self.advance();
        let name = self.identifier()?;
        if self.at_punct(":=") || self.at_punct("=") {
            self.advance();
        } else {
            return self.error("expected `:=` after `default` rule name");
        }
        let value = match self.advance() {
            Kind::Ident(word) if word == "true" => true,
            Kind::Ident(word) if word == "false" => false,
            _ => return self.error("a default must be `true` or `false`"),
        };
        if self.module.defaults.insert(name.clone(), value).is_some() {
            return self.error(&format!("rule `{name}` has two defaults"));
        }
        Ok(())
    }

    fn rule(&mut self) -> Result<(), String> {
        let name = self.identifier()?;
        if self.at_punct("(") || self.at_punct("[") || self.at_punct(".") {
            return self.error("only rules with no arguments and a boolean value are supported");
        }
        if self.at_punct(":=") || self.at_punct("=") {
            return self.error("only boolean rules are supported; write `NAME if { ... }`");
        }
        if self.at_word("if") {
            self.advance();
        }
        let body = if self.at_punct("{") {
            self.block()?
        } else {
            // Single-statement form: `allow if input.tool == "x"`.
            let mut scope = Scope::default();
            let statement = self.statement(&mut scope)?;
            Body {
                statements: vec![statement],
            }
        };
        if self.at_word("else") {
            return self.error("`else` is not supported");
        }
        self.module.rules.entry(name).or_default().push(body);
        Ok(())
    }

    /// `{ statement ... }`
    fn block(&mut self) -> Result<Body, String> {
        self.expect_punct("{")?;
        let mut scope = Scope::default();
        let mut statements = Vec::new();
        loop {
            self.skip_separators();
            if self.at_punct("}") {
                self.advance();
                break;
            }
            if matches!(self.peek(), Kind::Eof) {
                return self.error("unclosed `{`");
            }
            statements.push(self.statement(&mut scope)?);
            if !(self.at_punct("}") || self.at_punct(";") || matches!(self.peek(), Kind::Newline)) {
                return self.error("expected a newline, `;` or `}` after a statement");
            }
        }
        Ok(Body { statements })
    }

    fn statement(&mut self, scope: &mut Scope) -> Result<Statement, String> {
        let mut usage = Usage::default();
        let statement = self.statement_inner(scope, &mut usage)?;
        // Every variable the statement uses must be bound by it or earlier.
        for name in &usage.used {
            if !scope.bound.contains(name) && !usage.binds.contains(name) {
                self.free.push((self.line(), name.clone()));
            }
        }
        scope.bound.extend(usage.binds);
        Ok(statement)
    }

    fn statement_inner(
        &mut self,
        scope: &mut Scope,
        usage: &mut Usage,
    ) -> Result<Statement, String> {
        if self.at_word("not") {
            self.advance();
            let inner = self.statement_inner(scope, usage)?;
            return Ok(Statement::Not(Box::new(inner)));
        }
        if self.at_word("some") {
            self.advance();
            let name = self.identifier()?;
            if !self.at_word("in") {
                return self.error("`some` is only supported as `some NAME in COLLECTION`");
            }
            if scope.bound.contains(&name) {
                return self.error(&format!("variable `{name}` is already bound"));
            }
            self.advance();
            let collection = self.term(usage)?;
            usage.binds.insert(name.clone());
            return Ok(Statement::SomeIn { name, collection });
        }

        let left = self.term(usage)?;
        if self.at_punct(":=") {
            self.advance();
            let Term::Var(name) = left else {
                return self.error("the left side of `:=` must be a variable");
            };
            if scope.bound.contains(&name) {
                return self.error(&format!("variable `{name}` is already bound"));
            }
            usage.binds.insert(name.clone());
            let right = self.term(usage)?;
            return Ok(Statement::Unify {
                left: Term::Var(name),
                right,
            });
        }
        if self.at_punct("=") {
            self.advance();
            let right = self.term(usage)?;
            // An unbound variable on either side is bound by unification.
            for side in [&left, &right] {
                if let Term::Var(name) = side
                    && !scope.bound.contains(name)
                {
                    usage.binds.insert(name.clone());
                }
            }
            return Ok(Statement::Unify { left, right });
        }
        if self.at_word("in") {
            self.advance();
            let collection = self.term(usage)?;
            return Ok(Statement::In {
                member: left,
                collection,
            });
        }
        let op = match self.peek() {
            Kind::Punct("==") => Some(Op::Eq),
            Kind::Punct("!=") => Some(Op::Ne),
            Kind::Punct("<") => Some(Op::Lt),
            Kind::Punct("<=") => Some(Op::Le),
            Kind::Punct(">") => Some(Op::Gt),
            Kind::Punct(">=") => Some(Op::Ge),
            _ => None,
        };
        if let Some(op) = op {
            self.advance();
            let right = self.term(usage)?;
            return Ok(Statement::Compare { op, left, right });
        }
        Ok(Statement::Term(left))
    }

    /// A term, recording the variables it uses in `usage`.
    fn term(&mut self, usage: &mut Usage) -> Result<Term, String> {
        match self.advance() {
            Kind::Str(text) => Ok(Term::Str(text)),
            Kind::Num(value) => Ok(Term::Num(value)),
            Kind::Punct("-") => match self.advance() {
                Kind::Num(value) => Ok(Term::Num(-value)),
                _ => self.error("`-` is only supported before a number"),
            },
            Kind::Punct("[") => self.array(usage),
            Kind::Punct("(") => {
                self.skip_newlines();
                let inner = self.term(usage)?;
                self.skip_newlines();
                self.expect_punct(")")?;
                Ok(inner)
            }
            Kind::Ident(word) => self.word_term(word, usage),
            _ => self.error("expected a value"),
        }
    }

    fn array(&mut self, usage: &mut Usage) -> Result<Term, String> {
        let mut items = Vec::new();
        loop {
            self.skip_newlines();
            if self.at_punct("]") {
                self.advance();
                break;
            }
            items.push(self.term(usage)?);
            self.skip_newlines();
            if self.at_punct(",") {
                self.advance();
            } else {
                self.skip_newlines();
                self.expect_punct("]")?;
                break;
            }
        }
        Ok(Term::Array(items))
    }

    fn word_term(&mut self, word: String, usage: &mut Usage) -> Result<Term, String> {
        match word.as_str() {
            "true" => return Ok(Term::Bool(true)),
            "false" => return Ok(Term::Bool(false)),
            "null" => return Ok(Term::Null),
            "_" => return Ok(Term::Wildcard),
            "not" | "some" | "in" | "if" | "default" | "else" | "with" | "every" | "package"
            | "import" => {
                return self.error(&format!("`{word}` cannot be used here"));
            }
            _ => {}
        }

        // Dotted names: `input.x`, `data.tpt.mcpbox.x`, or a builtin such as
        // `tpt.normalize_host`.
        let mut names = vec![word.clone()];
        if word != "input" && word != "data" {
            while self.at_punct(".")
                && matches!(
                    self.tokens.get(self.pos + 1).map(|t| &t.kind),
                    Some(Kind::Ident(_))
                )
            {
                self.advance();
                names.push(self.identifier()?);
            }
        }

        if self.at_punct("(") {
            let name = names.join(".");
            return self.call(name, usage);
        }
        if names.len() > 1 {
            return self.error(&format!("unknown reference `{}`", names.join(".")));
        }

        let base = match word.as_str() {
            "input" => Base::Input,
            "data" => Base::Data,
            _ => {
                usage.used.push(word.clone());
                Base::Var(word)
            }
        };
        let path = self.accesses(usage)?;
        if let Base::Var(_) = base
            && path.is_empty()
        {
            return Ok(match base {
                Base::Var(name) => Term::Var(name),
                _ => unreachable!("matched above"),
            });
        }
        Ok(Term::Ref { base, path })
    }

    fn call(&mut self, name: String, usage: &mut Usage) -> Result<Term, String> {
        self.advance(); // (
        let mut args = Vec::new();
        loop {
            self.skip_newlines();
            if self.at_punct(")") {
                self.advance();
                break;
            }
            args.push(self.term(usage)?);
            self.skip_newlines();
            if self.at_punct(",") {
                self.advance();
            } else {
                self.skip_newlines();
                self.expect_punct(")")?;
                break;
            }
        }
        match builtins::arity(&name) {
            Some(expected) if expected == args.len() => Ok(Term::Call { name, args }),
            Some(expected) => self.error(&format!(
                "`{name}` takes {expected} argument(s), not {}",
                args.len()
            )),
            None => self.error(&format!("unknown builtin `{name}`")),
        }
    }

    /// `.field` and `[term]` steps after a base.
    fn accesses(&mut self, usage: &mut Usage) -> Result<Vec<Access>, String> {
        let mut path = Vec::new();
        loop {
            if self.at_punct(".") {
                self.advance();
                path.push(Access::Field(self.identifier()?));
            } else if self.at_punct("[") {
                self.advance();
                let index = self.index_term(usage)?;
                self.expect_punct("]")?;
                path.push(Access::Index(index));
            } else {
                return Ok(path);
            }
        }
    }

    /// An index. An unbound variable here iterates, so it is a binder rather
    /// than a use.
    fn index_term(&mut self, usage: &mut Usage) -> Result<Term, String> {
        let before = usage.used.len();
        let term = self.term(usage)?;
        if let Term::Var(name) = &term {
            // Assume a binder; `statement` checks it against the scope.
            usage.used.truncate(before);
            usage.binds.insert(name.clone());
        }
        Ok(term)
    }
}

/// Checks that every `data` reference names a rule of the module, and that no
/// rule refers back to itself.
fn check_references(module: &Module) -> Result<(), String> {
    let mut graph: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for (name, bodies) in &module.rules {
        let mut targets = BTreeSet::new();
        for body in bodies {
            for statement in &body.statements {
                statement_refs(statement, &mut targets)?;
            }
        }
        for target in &targets {
            if !module.rules.contains_key(target) {
                return Err(format!("rule `{name}` refers to unknown rule `{target}`"));
            }
        }
        graph.insert(name, targets);
    }
    // Depth-first search for a cycle.
    fn visit<'a>(
        node: &'a str,
        graph: &'a BTreeMap<&str, BTreeSet<String>>,
        done: &mut BTreeSet<&'a str>,
        stack: &mut Vec<&'a str>,
    ) -> Result<(), String> {
        if let Some(index) = stack.iter().position(|n| *n == node) {
            let cycle: Vec<&str> = stack[index..].to_vec();
            return Err(format!("rules refer to each other: {}", cycle.join(" -> ")));
        }
        if done.contains(node) {
            return Ok(());
        }
        stack.push(node);
        if let Some(targets) = graph.get(node) {
            for target in targets {
                let target: &str = graph
                    .get_key_value(target.as_str())
                    .map_or(target.as_str(), |(k, _)| k);
                visit(target, graph, done, stack)?;
            }
        }
        stack.pop();
        done.insert(node);
        Ok(())
    }
    let mut done = BTreeSet::new();
    for node in graph.keys() {
        visit(node, &graph, &mut done, &mut Vec::new())?;
    }
    Ok(())
}

fn statement_refs(statement: &Statement, out: &mut BTreeSet<String>) -> Result<(), String> {
    match statement {
        Statement::Term(term) => term_refs(term, out),
        Statement::Not(inner) => statement_refs(inner, out),
        Statement::Compare { left, right, .. } | Statement::Unify { left, right } => {
            term_refs(left, out)?;
            term_refs(right, out)
        }
        Statement::In { member, collection } => {
            term_refs(member, out)?;
            term_refs(collection, out)
        }
        Statement::SomeIn { collection, .. } => term_refs(collection, out),
    }
}

/// Collects the rule names a term refers to, refusing any `data` reference that
/// is not exactly `data.tpt.mcpbox.NAME`.
fn term_refs(term: &Term, out: &mut BTreeSet<String>) -> Result<(), String> {
    match term {
        Term::Array(items) => items.iter().try_for_each(|item| term_refs(item, out)),
        Term::Call { args, .. } => args.iter().try_for_each(|arg| term_refs(arg, out)),
        Term::Ref { base, path } => {
            if let Base::Data = base {
                match path.as_slice() {
                    [Access::Field(a), Access::Field(b), Access::Field(rule)]
                        if a == "tpt" && b == "mcpbox" =>
                    {
                        out.insert(rule.clone());
                    }
                    _ => {
                        return Err(
                            "only `data.tpt.mcpbox.NAME` references are supported".to_owned()
                        );
                    }
                }
            }
            for access in path {
                if let Access::Index(index) = access {
                    term_refs(index, out)?;
                }
            }
            Ok(())
        }
        Term::Null
        | Term::Bool(_)
        | Term::Num(_)
        | Term::Str(_)
        | Term::Var(_)
        | Term::Wildcard => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::compile;

    #[test]
    fn a_policy_in_the_documented_form_compiles() {
        let module = compile(
            "package tpt.mcpbox\n\ndefault allow := false\n\nallow if {\n    input.tool == \"x\"\n    not startswith(input.fs_path, \"secret/\")\n}\n",
        )
        .expect("compiles");
        assert_eq!(module.defaults.get("allow"), Some(&false));
        assert_eq!(module.rules["allow"].len(), 1);
    }

    #[test]
    fn unsupported_forms_are_refused_at_load() {
        for source in [
            "package other\nallow if { true }",
            "package tpt.mcpbox\nallow if {",
            "package tpt.mcpbox\nallow if { x == 1 }",
            "package tpt.mcpbox\nallow if { input.a + 1 == 2 }",
            "package tpt.mcpbox\nf(x) if { true }",
            "package tpt.mcpbox\nallow if { true } else if { false }",
            "package tpt.mcpbox\nallow if { nosuch(1) }",
            "package tpt.mcpbox\nallow if { startswith(\"a\") }",
            "package tpt.mcpbox\nallow if { data.tpt.mcpbox.missing }",
            "package tpt.mcpbox\na if { data.tpt.mcpbox.b }\nb if { data.tpt.mcpbox.a }",
            "package tpt.mcpbox\nallow if { import_x }",
            "package tpt.mcpbox\nimport data.other\nallow if { true }",
            "package tpt.mcpbox\ndefault allow := \"yes\"",
            "package tpt.mcpbox\nallow if { some x }",
            "package tpt.mcpbox\nallow := true if { true }",
        ] {
            assert!(compile(source).is_err(), "accepted: {source}");
        }
    }

    #[test]
    fn a_variable_must_be_bound_before_it_is_used() {
        assert!(
            compile("package tpt.mcpbox\nallow if { input.uris[i] == \"a\" }").is_ok(),
            "an index variable binds"
        );
        assert!(compile("package tpt.mcpbox\nallow if { x := input.tool\n x == \"a\" }").is_ok());
        assert!(compile("package tpt.mcpbox\nallow if { x == input.tool }").is_err());
        assert!(
            compile("package tpt.mcpbox\nallow if { x := 1\n x := 2 }").is_err(),
            "rebinding is refused"
        );
    }
}
