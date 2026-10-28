// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Loading tools and running invocations through a warm instance pool.
//!
//! A pool holds instantiated components ready to run. A call checks one out,
//! runs it under the tool's time and memory limits, and checks it back in. An
//! instance that trapped, timed out, was cancelled, or hit the host's panic
//! boundary is discarded, and so is one that has served its recycle quota.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tpt_mcpbox_config::{SecretStore, ToolConfig};
use wasmtime::Store;
use wasmtime::component::Component;
use wasmtime_wasi::ResourceTable;
use wasmtime_wasi_http::WasiHttpCtx;

use crate::bindings::Tool as Bindings;
use crate::error::ToolError;
use crate::module;
use crate::outbound::{HostCheck, HttpPolicy, PolicyHooks};
use crate::runtime::{CallControl, CancelToken, HostState, Runtime};
use crate::sandbox::{self, WasiPlan};

/// Time limit when a tool does not set one.
pub const DEFAULT_TIME_LIMIT: Duration = Duration::from_secs(10);

/// Linear memory ceiling when a tool does not set one.
pub const DEFAULT_MEMORY_BYTES: usize = 64 * 1024 * 1024;

/// Concurrent invocations when a tool does not set a cap.
pub const DEFAULT_MAX_CONCURRENT: usize = 4;

/// Argument and result payload ceiling when a tool does not set one.
pub const DEFAULT_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Invocations an instance serves before it is recycled. Bounding this limits
/// how long guest memory from one call can be seen by the next.
pub const DEFAULT_RECYCLE_AFTER: u32 = 256;

/// A tool that has been compiled, instantiated once, and is ready to call.
#[derive(Debug)]
pub struct LoadedTool {
    name: String,
    digest: String,
    descriptors: String,
    time_limit: Duration,
    max_argument_bytes: usize,
    max_result_bytes: usize,
    pool: Pool,
}

/// How busy one tool's instance pool is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolUsage {
    /// Instances checked out for a call right now.
    pub leased: usize,
    /// The most instances the pool will hold at once.
    pub capacity: usize,
}

impl LoadedTool {
    /// How many instances are in use, against the pool's cap.
    #[must_use]
    pub fn pool_usage(&self) -> PoolUsage {
        self.pool.usage()
    }

    /// The configured tool name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Lowercase hex SHA-256 of the module that was loaded. Recorded in the
    /// audit log so an invocation can be tied to the exact bytes that ran.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The JSON descriptors the component reported at load time.
    #[must_use]
    pub fn descriptors(&self) -> &str {
        &self.descriptors
    }

    /// Run one of the component's tools.
    ///
    /// `tool` is the name the component advertises, `arguments` the JSON object
    /// from `tools/call`.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::ToolFailed`] when the tool reports an error, which
    /// leaves the instance healthy. Other variants mean the call could not be
    /// completed, and the instance was discarded where appropriate.
    pub fn call(
        &self,
        tool: &str,
        arguments: &str,
        cancel: &CancelToken,
    ) -> Result<String, ToolError> {
        self.call_checked(tool, arguments, cancel, None)
    }

    /// Like [`LoadedTool::call`], with a check on every outbound request the
    /// call makes. A request the check refuses fails inside the guest, as an
    /// `wasi:http` error, and the call goes on.
    ///
    /// # Errors
    ///
    /// As [`LoadedTool::call`].
    pub fn call_checked(
        &self,
        tool: &str,
        arguments: &str,
        cancel: &CancelToken,
        check: Option<HostCheck>,
    ) -> Result<String, ToolError> {
        if arguments.len() > self.max_argument_bytes {
            return Err(ToolError::ArgumentsTooLarge {
                tool: self.name.clone(),
                size: arguments.len(),
                limit: self.max_argument_bytes,
            });
        }
        let outcome = self.run(cancel, check, |store, bindings| {
            bindings.call_call(store, tool, arguments)
        })?;
        match outcome {
            Err(message) => Err(ToolError::ToolFailed {
                tool: self.name.clone(),
                message,
            }),
            Ok(text) if text.len() > self.max_result_bytes => Err(ToolError::ResultTooLarge {
                tool: self.name.clone(),
                size: text.len(),
                limit: self.max_result_bytes,
            }),
            Ok(text) => Ok(text),
        }
    }

    /// Run one operation on a pooled instance under this tool's limits.
    fn run<R>(
        &self,
        cancel: &CancelToken,
        check: Option<HostCheck>,
        op: impl FnOnce(&mut Store<HostState>, &Bindings) -> wasmtime::Result<R>,
    ) -> Result<R, ToolError> {
        let mut lease = self.pool.checkout()?;
        let control = Arc::new(CallControl {
            deadline: Instant::now() + self.time_limit,
            cancel: cancel.clone(),
        });
        let slot = lease.slot_mut();
        slot.store.data_mut().control = Arc::clone(&control);
        slot.store.data_mut().hooks.deadline = Some(control.deadline);
        slot.store.data_mut().hooks.check = check;
        slot.store.set_epoch_deadline(1);

        let outcome = catch_unwind(AssertUnwindSafe(|| op(&mut slot.store, &slot.bindings)));
        match outcome {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(trap)) => {
                lease.discard();
                Err(self.classify(&trap, &control))
            }
            Err(_) => {
                lease.discard();
                tracing::error!(tool = %self.name, "host panicked while running a tool");
                Err(ToolError::HostPanic {
                    tool: self.name.clone(),
                })
            }
        }
    }

    /// Turn a trap into the error the caller can act on. The trap text is kept
    /// to its first line, since a backtrace is not useful to an agent.
    fn classify(&self, trap: &wasmtime::Error, control: &CallControl) -> ToolError {
        if control.cancel.is_cancelled() {
            return ToolError::Cancelled {
                tool: self.name.clone(),
            };
        }
        if Instant::now() >= control.deadline {
            return ToolError::TimedOut {
                tool: self.name.clone(),
                limit: self.time_limit,
            };
        }
        let text = format!("{trap:#}");
        let first = text.lines().next().unwrap_or("trap").to_owned();
        tracing::warn!(tool = %self.name, trap = %first, "tool trapped");
        ToolError::Trapped {
            tool: self.name.clone(),
            message: first,
        }
    }
}

impl Runtime {
    /// Load a tool from its configuration.
    ///
    /// The module is read once, checked against `sha256` when it is pinned, and
    /// compiled from those same bytes. Secrets are resolved here, so a missing
    /// secret fails the load rather than the first call. `base` anchors relative
    /// paths in the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError`] for an unreadable or unpinned-mismatched module, an
    /// invalid capability or secret binding, a module that is not a tool
    /// component, or a module source that is not supported yet (OCI references).
    pub fn load_tool(
        &self,
        config: &ToolConfig,
        secrets: &SecretStore,
        base: &Path,
    ) -> Result<LoadedTool, ToolError> {
        let name = config.name.as_str();
        let Some(relative) = config.wasm_path.as_deref() else {
            let message = if config.oci_ref.is_some() {
                "OCI pulls are not implemented yet; set `wasm_path` to a local component".to_owned()
            } else {
                "no `wasm_path` is set".to_owned()
            };
            return Err(ToolError::Unsupported {
                tool: name.to_owned(),
                message,
            });
        };
        let path = base.join(relative);
        let module = module::load_file(name, &path, config.sha256.as_deref())?;
        self.build_tool(name, &module.bytes, &module.digest, config, secrets, base)
    }

    /// Run the sandbox self-test against a probe component.
    ///
    /// The probe is loaded with no grants at all and asked to read `probe_path`,
    /// reach `https://example.invalid/`, and report its environment. The sandbox
    /// is sound only if every one of those is refused. Run this at startup, before
    /// serving any tool.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::SelfTestFailed`] when the sandbox exposes something it
    /// should not, and the usual load errors when the probe cannot be run.
    pub fn self_test(&self, probe_wasm: &[u8], probe_path: &Path) -> Result<(), ToolError> {
        let config = ToolConfig {
            name: "selftest".to_owned(),
            description: None,
            wasm_path: None,
            oci_ref: None,
            sha256: None,
            enabled: true,
            capabilities: tpt_mcpbox_config::Capabilities::default(),
            secrets: Vec::new(),
            limits: tpt_mcpbox_config::Limits::default(),
            rate_limit: tpt_mcpbox_config::RateLimit::default(),
        };
        let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(probe_wasm));
        let tool = self.build_tool(
            "selftest",
            probe_wasm,
            &digest,
            &config,
            &SecretStore::new(),
            Path::new("."),
        )?;

        let args = serde_json::json!({
            "path": probe_path.display().to_string(),
            "url": "https://example.invalid/",
        })
        .to_string();
        let raw = tool.call("probe", &args, &CancelToken::new())?;
        let report: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
            ToolError::SelfTestFailed(format!("probe returned unparseable output: {e}"))
        })?;

        let mut failures = Vec::new();
        if report["fs"] != "denied" {
            failures.push(format!(
                "filesystem read of {} was not denied",
                probe_path.display()
            ));
        }
        if report["net"] != "denied" {
            failures.push("outbound request to an ungranted host was not denied".to_owned());
        }
        if report["env_count"] != 0 || report["env_home"] != false {
            failures.push(format!(
                "environment leaked: {} variable(s) visible",
                report["env_count"]
            ));
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(ToolError::SelfTestFailed(failures.join("; ")))
        }
    }

    /// Shared construction path for files and self-test bytes.
    fn build_tool(
        &self,
        name: &str,
        bytes: &[u8],
        digest: &str,
        config: &ToolConfig,
        secrets: &SecretStore,
        base: &Path,
    ) -> Result<LoadedTool, ToolError> {
        let caps = &config.capabilities;
        let memory_bytes = match caps.memory_limit {
            Some(limit) => usize::try_from(limit).unwrap_or(usize::MAX),
            None => DEFAULT_MEMORY_BYTES,
        };
        if memory_bytes > crate::runtime::MAX_MEMORY_BYTES {
            return Err(ToolError::InvalidConfig {
                tool: name.to_owned(),
                message: format!(
                    "`memory_limit` of {memory_bytes} bytes is above the runtime maximum of {} bytes",
                    crate::runtime::MAX_MEMORY_BYTES
                ),
            });
        }
        let time_limit = caps.time_limit.unwrap_or(DEFAULT_TIME_LIMIT);
        let plan = sandbox::plan(name, caps, base)?;

        let headers =
            secrets
                .resolve(&config.secrets)
                .map_err(|missing| ToolError::InvalidConfig {
                    tool: name.to_owned(),
                    message: format!("secret `{}` is not set", missing.name),
                })?;
        let http = Arc::new(HttpPolicy::new(
            name,
            &caps.network,
            &headers,
            time_limit,
            None,
        )?);

        let component =
            Component::new(&self.shared.engine, bytes).map_err(|e| ToolError::Compile {
                tool: name.to_owned(),
                message: format!("{e:#}"),
            })?;

        let max_concurrent = config
            .limits
            .max_concurrent_calls
            .map_or(DEFAULT_MAX_CONCURRENT, |n| n.max(1) as usize);
        let pool = Pool {
            runtime: self.clone(),
            tool: name.to_owned(),
            component,
            plan,
            http,
            memory_bytes,
            time_limit,
            max: max_concurrent,
            recycle_after: DEFAULT_RECYCLE_AFTER,
            state: Mutex::new(PoolState::default()),
        };

        // Instantiate one instance now, so the first call is warm and a broken
        // component fails at load rather than on first use.
        let mut tool = LoadedTool {
            name: name.to_owned(),
            digest: digest.to_owned(),
            descriptors: String::new(),
            time_limit,
            max_argument_bytes: config
                .limits
                .max_argument_bytes
                .map_or(DEFAULT_PAYLOAD_BYTES, |b| {
                    usize::try_from(b).unwrap_or(usize::MAX)
                }),
            max_result_bytes: config
                .limits
                .max_result_bytes
                .map_or(DEFAULT_PAYLOAD_BYTES, |b| {
                    usize::try_from(b).unwrap_or(usize::MAX)
                }),
            pool,
        };
        tool.descriptors = tool.run(&CancelToken::new(), None, |store, bindings| {
            bindings.call_describe(store)
        })?;
        Ok(tool)
    }
}

/// Instances of one tool, idle or leased.
struct Pool {
    runtime: Runtime,
    tool: String,
    component: Component,
    plan: WasiPlan,
    http: Arc<HttpPolicy>,
    memory_bytes: usize,
    time_limit: Duration,
    max: usize,
    recycle_after: u32,
    state: Mutex<PoolState>,
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("tool", &self.tool)
            .field("max", &self.max)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
struct PoolState {
    idle: Vec<Slot>,
    leased: usize,
}

/// One instantiated component and the store it lives in.
struct Slot {
    store: Store<HostState>,
    bindings: Bindings,
    calls: u32,
}

impl std::fmt::Debug for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Slot")
            .field("calls", &self.calls)
            .finish_non_exhaustive()
    }
}

impl Pool {
    fn usage(&self) -> PoolUsage {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        PoolUsage {
            leased: state.leased,
            capacity: self.max,
        }
    }

    /// Take an idle instance, or instantiate one if the cap allows.
    fn checkout(&self) -> Result<Lease<'_>, ToolError> {
        {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(slot) = state.idle.pop() {
                state.leased += 1;
                return Ok(Lease::new(self, slot));
            }
            if state.leased >= self.max {
                return Err(ToolError::Overloaded {
                    tool: self.tool.clone(),
                    limit: self.max,
                });
            }
            state.leased += 1;
        }
        match self.instantiate() {
            Ok(slot) => Ok(Lease::new(self, slot)),
            Err(error) => {
                self.state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .leased -= 1;
                Err(error)
            }
        }
    }

    fn instantiate(&self) -> Result<Slot, ToolError> {
        let wasi = sandbox::build_ctx(&self.tool, &self.plan)?;
        // Instantiation runs under the same time limit as a call, so a slow start
        // is interrupted rather than left unbounded.
        let state = HostState {
            wasi,
            http: WasiHttpCtx::new(),
            table: ResourceTable::new(),
            limits: Runtime::limits(self.memory_bytes),
            hooks: PolicyHooks::new(Arc::clone(&self.http)),
            control: Arc::new(CallControl {
                deadline: Instant::now() + self.time_limit,
                cancel: CancelToken::new(),
            }),
        };
        let mut store = self.runtime.new_store(state);
        let bindings =
            Bindings::instantiate(&mut store, &self.component, &self.runtime.shared.linker)
                .map_err(|e| ToolError::Compile {
                    tool: self.tool.clone(),
                    message: format!("{e:#}"),
                })?;
        Ok(Slot {
            store,
            bindings,
            calls: 0,
        })
    }

    /// Return a slot to the pool, or drop it if it is spent.
    fn checkin(&self, mut slot: Slot, healthy: bool) {
        slot.calls += 1;
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.leased -= 1;
        if healthy && slot.calls < self.recycle_after {
            state.idle.push(slot);
        }
    }
}

/// A checked-out instance. Returns itself to the pool on drop.
struct Lease<'a> {
    pool: &'a Pool,
    slot: Option<Slot>,
    healthy: bool,
}

impl<'a> Lease<'a> {
    fn new(pool: &'a Pool, slot: Slot) -> Self {
        Self {
            pool,
            slot: Some(slot),
            healthy: true,
        }
    }

    fn slot_mut(&mut self) -> &mut Slot {
        self.slot
            .as_mut()
            .expect("slot present until the lease ends")
    }

    /// Mark the instance as unusable. It will be dropped rather than reused.
    fn discard(&mut self) {
        self.healthy = false;
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take() {
            self.pool.checkin(slot, self.healthy);
        }
    }
}
