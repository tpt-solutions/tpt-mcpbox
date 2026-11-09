// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Tokeniser for the Rego subset. Anything it does not recognise is an error,
//! so no source text is silently skipped.

/// A token and the line it starts on.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Token {
    pub(crate) kind: Kind,
    pub(crate) line: usize,
}

/// The kinds of token the parser sees.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Kind {
    Ident(String),
    Str(String),
    Num(f64),
    /// Punctuation and operators, spelled as in the source.
    Punct(&'static str),
    Newline,
    Eof,
}

/// Operators, longest first so that `:=` is not read as `:` and `=`.
const PUNCT: &[&str] = &[
    ":=", "==", "!=", "<=", ">=", "(", ")", "[", "]", "{", "}", ",", ";", ".", "=", "<", ">", "-",
];

/// Splits `source` into tokens. Comments run from `#` to the end of the line.
pub(crate) fn tokenize(source: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut line = 1;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\n' {
            tokens.push(Token {
                kind: Kind::Newline,
                line,
            });
            line += 1;
            i += 1;
        } else if c.is_whitespace() {
            i += 1;
        } else if c == '#' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '"' {
            let (text, next) = quoted(&chars, i, line)?;
            tokens.push(Token {
                kind: Kind::Str(text),
                line,
            });
            i = next;
        } else if c == '`' {
            let start = i + 1;
            let end = chars[start..]
                .iter()
                .position(|&c| c == '`')
                .ok_or_else(|| format!("line {line}: unterminated raw string"))?
                + start;
            let text: String = chars[start..end].iter().collect();
            if text.contains('\n') {
                return Err(format!("line {line}: raw strings cannot span lines"));
            }
            tokens.push(Token {
                kind: Kind::Str(text),
                line,
            });
            i = end + 1;
        } else if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            if i + 1 < chars.len() && chars[i] == '.' && chars[i + 1].is_ascii_digit() {
                i += 1;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
            }
            let text: String = chars[start..i].iter().collect();
            let value = text
                .parse::<f64>()
                .map_err(|_| format!("line {line}: invalid number `{text}`"))?;
            tokens.push(Token {
                kind: Kind::Num(value),
                line,
            });
        } else if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let text: String = chars[start..i].iter().collect();
            tokens.push(Token {
                kind: Kind::Ident(text),
                line,
            });
        } else if let Some(punct) = PUNCT.iter().find(|p| starts_with(&chars, i, p)) {
            tokens.push(Token {
                kind: Kind::Punct(punct),
                line,
            });
            i += punct.chars().count();
        } else {
            return Err(format!("line {line}: unexpected character `{c}`"));
        }
    }
    tokens.push(Token {
        kind: Kind::Eof,
        line,
    });
    Ok(tokens)
}

fn starts_with(chars: &[char], at: usize, text: &str) -> bool {
    text.chars()
        .enumerate()
        .all(|(offset, c)| chars.get(at + offset) == Some(&c))
}

/// Reads a double-quoted string starting at `start` (the opening quote).
/// Returns the decoded text and the index after the closing quote.
fn quoted(chars: &[char], start: usize, line: usize) -> Result<(String, usize), String> {
    let mut out = String::new();
    let mut i = start + 1;
    while i < chars.len() {
        match chars[i] {
            '"' => return Ok((out, i + 1)),
            '\n' => return Err(format!("line {line}: unterminated string")),
            '\\' => {
                let escape = *chars
                    .get(i + 1)
                    .ok_or_else(|| format!("line {line}: unterminated string"))?;
                i += 2;
                match escape {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    'u' => {
                        let hex: String = chars
                            .get(i..i + 4)
                            .ok_or_else(|| format!("line {line}: bad \\u escape"))?
                            .iter()
                            .collect();
                        let code = u32::from_str_radix(&hex, 16)
                            .map_err(|_| format!("line {line}: bad \\u escape"))?;
                        out.push(
                            char::from_u32(code)
                                .ok_or_else(|| format!("line {line}: bad \\u escape"))?,
                        );
                        i += 4;
                    }
                    other => return Err(format!("line {line}: unknown escape `\\{other}`")),
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Err(format!("line {line}: unterminated string"))
}

#[cfg(test)]
mod tests {
    use super::{Kind, tokenize};

    #[test]
    fn operators_and_strings_tokenise() {
        let kinds: Vec<Kind> = tokenize("x := \"a\\n\" # note\n")
            .unwrap()
            .into_iter()
            .map(|t| t.kind)
            .collect();
        assert_eq!(
            kinds,
            vec![
                Kind::Ident("x".into()),
                Kind::Punct(":="),
                Kind::Str("a\n".into()),
                Kind::Newline,
                Kind::Eof,
            ]
        );
    }

    #[test]
    fn unknown_characters_are_errors() {
        assert!(tokenize("allow if { a + b }").is_err());
        assert!(tokenize("\"open").is_err());
    }
}
