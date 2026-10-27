// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Parsing for human-friendly configuration values: byte sizes (`"64MB"`) and
//! durations (`"500ms"`).
//!
//! Configuration is written by humans, so units are accepted with any casing
//! and with a space (`"64 MB"`). Anything ambiguous is rejected rather than
//! guessed: a memory limit silently read as bytes instead of mebibytes is a
//! security bug, not a convenience.

use std::time::Duration;

/// Failure while parsing a unit-bearing value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnitError {
    /// The value was not `<number><unit>`.
    #[error("expected a value like `64MB` or `2s`, got `{0}`")]
    Malformed(String),
    /// The unit is not recognised.
    #[error("unknown unit `{unit}` in `{input}` (expected B, KB, MB, GB, TB, KiB, MiB, GiB)")]
    UnknownUnit {
        /// The offending unit.
        unit: String,
        /// The full input, for context.
        input: String,
    },
    /// A duration was given a non-time unit.
    #[error("unit `{unit}` is not a valid duration unit (expected ns, us, ms, s, m, h)")]
    InvalidDurationUnit {
        /// The offending unit.
        unit: String,
    },
    /// The numeric part was missing or unparsable.
    #[error("expected a number before the unit in `{0}`")]
    MissingNumber(String),
}

/// Multipliers are binary for `KiB`-style units and decimal for `KB`-style.
///
/// A bare number means bytes, which is what an operator writing `1024` expects.
fn byte_multiplier(unit: &str) -> Option<u64> {
    Some(match unit {
        "" | "B" => 1,
        "KB" => 1_000,
        "MB" => 1_000_000,
        "GB" => 1_000_000_000,
        "TB" => 1_000_000_000_000,
        "KIB" => 1 << 10,
        "MIB" => 1 << 20,
        "GIB" => 1 << 30,
        "TIB" => 1u64 << 40,
        _ => return None,
    })
}

fn duration_multiplier(unit: &str) -> Option<Duration> {
    Some(match unit {
        "NS" => Duration::from_nanos(1),
        "US" => Duration::from_micros(1),
        "MS" => Duration::from_millis(1),
        "S" => Duration::from_secs(1),
        "M" => Duration::from_secs(60),
        "H" => Duration::from_secs(3600),
        _ => return None,
    })
}

/// Parse a byte size such as `64MB`, `512 KiB` or `1024`.
///
/// # Errors
/// Returns [`UnitError`] when the value is not a non-negative number followed by
/// a known unit.
pub fn parse_byte_size(input: &str) -> Result<u64, UnitError> {
    let trimmed = input.trim();
    let split = trimmed
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(trimmed.len());
    let (number, rest) = trimmed.split_at(split);
    let unit = rest.trim().to_ascii_uppercase();

    if number.is_empty() {
        return Err(UnitError::MissingNumber(trimmed.to_owned()));
    }
    let value: f64 = number
        .parse()
        .map_err(|_| UnitError::Malformed(trimmed.to_owned()))?;
    if !value.is_finite() || value < 0.0 {
        return Err(UnitError::Malformed(trimmed.to_owned()));
    }

    let factor = byte_multiplier(&unit).ok_or_else(|| UnitError::UnknownUnit {
        unit,
        input: trimmed.to_owned(),
    })?;

    let bytes = value * factor as f64;
    if bytes > u64::MAX as f64 {
        return Err(UnitError::Malformed(trimmed.to_owned()));
    }
    Ok(bytes as u64)
}

/// Render a byte size back into the compact form used in configuration.
#[must_use]
pub fn format_byte_size(bytes: u64) -> String {
    const UNITS: [(u64, &str); 4] = [
        (1 << 30, "GiB"),
        (1 << 20, "MiB"),
        (1 << 10, "KiB"),
        (1, "B"),
    ];
    for (factor, suffix) in UNITS {
        if bytes >= factor && bytes.is_multiple_of(factor) {
            return format!("{}{suffix}", bytes / factor);
        }
    }
    format!("{bytes}B")
}

/// Parse a duration such as `2s`, `500ms` or `1m30s`.
///
/// # Errors
/// Returns [`UnitError`] when the value is not a sum of `<number><time-unit>`
/// pairs.
pub fn parse_duration(input: &str) -> Result<Duration, UnitError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(UnitError::Malformed(trimmed.to_owned()));
    }

    let mut total = Duration::ZERO;
    let mut rest = trimmed;

    while !rest.trim().is_empty() {
        rest = rest.trim_start();
        let number_end = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(rest.len());
        if number_end == 0 {
            return Err(UnitError::Malformed(trimmed.to_owned()));
        }
        let (number, remainder) = rest.split_at(number_end);
        let unit_end = remainder
            .find(|c: char| !c.is_ascii_alphabetic())
            .unwrap_or(remainder.len());
        let (unit, remainder) = remainder.split_at(unit_end);

        let value: f64 = number
            .parse()
            .map_err(|_| UnitError::Malformed(trimmed.to_owned()))?;
        let factor = duration_multiplier(&unit.to_ascii_uppercase()).ok_or_else(|| {
            UnitError::InvalidDurationUnit {
                unit: unit.to_owned(),
            }
        })?;

        let nanos = value * factor.as_nanos() as f64;
        if !nanos.is_finite() || nanos < 0.0 {
            return Err(UnitError::Malformed(trimmed.to_owned()));
        }
        total = total
            .checked_add(Duration::from_nanos(nanos as u64))
            .ok_or_else(|| UnitError::Malformed(trimmed.to_owned()))?;
        rest = remainder;
    }

    Ok(total)
}

/// Render a duration in the compact form used in configuration.
#[must_use]
pub fn format_duration(duration: Duration) -> String {
    if duration.subsec_nanos() != 0 {
        format!("{}ms", duration.as_millis())
    } else {
        format!("{}s", duration.as_secs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_sizes_parse_decimal_and_binary_units() {
        assert_eq!(parse_byte_size("1024").expect("parses"), 1024);
        assert_eq!(parse_byte_size("1KB").expect("parses"), 1_000);
        assert_eq!(parse_byte_size("64MB").expect("parses"), 64_000_000);
        assert_eq!(parse_byte_size("64MiB").expect("parses"), 64 << 20);
        assert_eq!(parse_byte_size("512 KiB").expect("parses"), 512 << 10);
        assert_eq!(parse_byte_size("2gib").expect("parses"), 2 << 30);
        assert_eq!(parse_byte_size("1.5MB").expect("parses"), 1_500_000);
    }

    #[test]
    fn byte_sizes_reject_nonsense() {
        assert!(matches!(
            parse_byte_size("64 furlongs"),
            Err(UnitError::UnknownUnit { .. })
        ));
        assert!(matches!(
            parse_byte_size("MB"),
            Err(UnitError::MissingNumber(_))
        ));
        assert!(parse_byte_size("").is_err());
        assert!(parse_byte_size("-5MB").is_err());
    }

    #[test]
    fn byte_sizes_round_trip_through_formatting() {
        for value in [1024_u64, 64 << 20, 1 << 30, 4096] {
            let formatted = format_byte_size(value);
            assert_eq!(parse_byte_size(&formatted).expect("parses"), value);
        }
    }

    #[test]
    fn durations_parse_single_and_compound_units() {
        assert_eq!(
            parse_duration("2s").expect("parses"),
            Duration::from_secs(2)
        );
        assert_eq!(
            parse_duration("500ms").expect("parses"),
            Duration::from_millis(500)
        );
        assert_eq!(
            parse_duration("1m").expect("parses"),
            Duration::from_secs(60)
        );
        assert_eq!(
            parse_duration("1h").expect("parses"),
            Duration::from_secs(3600)
        );
        assert_eq!(
            parse_duration("1m30s").expect("parses"),
            Duration::from_secs(90)
        );
        assert_eq!(
            parse_duration(" 250us ").expect("parses"),
            Duration::from_micros(250)
        );
    }

    #[test]
    fn durations_reject_byte_units_and_garbage() {
        assert!(matches!(
            parse_duration("64MB"),
            Err(UnitError::InvalidDurationUnit { .. })
        ));
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn durations_round_trip_through_formatting() {
        assert_eq!(format_duration(parse_duration("2s").expect("parses")), "2s");
        assert_eq!(
            format_duration(parse_duration("750ms").expect("parses")),
            "750ms"
        );
    }
}
