// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! The guest probe that the startup self-test runs.
//!
//! The probe is a prebuilt component from `tests/guest`, committed under
//! `assets/`. Its SHA-256 is pinned in `assets/probe.sha256`, and a test checks
//! the two agree, so a changed binary cannot pass unnoticed. To rebuild it:
//!
//! ```text
//! cd crates/tpt-mcpbox-runtime/tests/guest
//! cargo build --release --target wasm32-wasip2 --target-dir ../../../../target/guest
//! cp ../../../../target/guest/wasm32-wasip2/release/tpt_mcpbox_test_guest.wasm ../../assets/probe.wasm
//! sha256sum ../../assets/probe.wasm   # update probe.sha256 to match
//! ```

/// The probe component.
pub const PROBE_WASM: &[u8] = include_bytes!("../assets/probe.wasm");

/// Lowercase hex SHA-256 of [`PROBE_WASM`], as recorded in `assets/probe.sha256`.
pub const PROBE_SHA256: &str = include_str!("../assets/probe.sha256");

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn probe_matches_its_pinned_digest() {
        let digest = hex::encode(Sha256::digest(PROBE_WASM));
        assert_eq!(digest, PROBE_SHA256.trim());
    }
}
