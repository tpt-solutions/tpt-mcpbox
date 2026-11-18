// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! The TLS client configuration shared by outbound requests and OCI pulls.
//!
//! Crypto comes from `tpt-crypto-rustls`, which is pure Rust and client-only. The
//! `ring` provider is not used anywhere in the dependency tree (todo.md, Phase 13).
//! Trust roots are the bundled Mozilla set, so results do not depend on the
//! host's certificate store.

use std::sync::{Arc, OnceLock};

use rustls::{ClientConfig, RootCertStore};

/// The shared client configuration, built once.
pub(crate) fn client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };
        let config = ClientConfig::builder_with_provider(Arc::new(tpt_crypto_rustls::provider()))
            .with_safe_default_protocol_versions()
            // The provider supports the default protocol versions by construction.
            .unwrap_or_else(|error| panic!("TLS provider lacks default versions: {error}"))
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(config)
    }))
}
