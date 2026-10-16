// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Host-side bindings for the `tpt:mcpbox/tool` world in `wit/tool.wit`.

wasmtime::component::bindgen!({
    path: "wit",
    world: "tool",
});
