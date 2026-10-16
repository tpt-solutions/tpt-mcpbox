// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! The shared Wasm engine: configuration, linker, epoch ticker and per-store
//! host state.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use hyper::Request;
use wasmtime::component::Linker;
use wasmtime::{
    Config, Engine, InstanceAllocationStrategy, PoolingAllocationConfig, Store, StoreLimits,
    StoreLimitsBuilder, UpdateDeadline,
};
use wasmtime_wasi::ResourceTable;
use wasmtime_wasi::p2::IoView;
use wasmtime_wasi::p2::{WasiCtx, WasiView};
use wasmtime_wasi_http::body::HyperOutgoingBody;
use wasmtime_wasi_http::types::{
    HostFutureIncomingResponse, OutgoingRequestConfig, default_send_request,
};
use wasmtime_wasi_http::{HttpResult, WasiHttpCtx, WasiHttpView};

use crate::error::ToolError;
use crate::outbound::{HttpPolicy, declared_length};

/// Interval at which the epoch counter advances. A tool's time limit is checked
/// at this granularity, so a limit is enforced to within one tick.
pub(crate) const EPOCH_TICK: Duration = Duration::from_millis(10);

/// Instances the pooling allocator reserves address space for.
const POOL_INSTANCES: u32 = 256;

/// Largest linear memory the pooling allocator reserves per instance. A tool's
/// `memory_limit` may not exceed this.
pub(crate) const MAX_MEMORY_BYTES: usize = 256 * 1024 * 1024;

/// Cancellation handle for one invocation.
///
/// Cloning shares the flag. The router will hold one per in-flight request and
/// call [`CancelToken::cancel`] on `notifications/cancelled`.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// A token that is not cancelled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation. The running guest is interrupted at its next epoch
    /// check, within one tick.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// `true` once [`CancelToken::cancel`] has been called.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Per-invocation control, read by the epoch callback.
#[derive(Debug)]
pub(crate) struct CallControl {
    pub(crate) deadline: Instant,
    pub(crate) cancel: CancelToken,
}

/// Host state carried by every store.
pub(crate) struct HostState {
    pub(crate) wasi: WasiCtx,
    pub(crate) http: WasiHttpCtx,
    pub(crate) table: ResourceTable,
    pub(crate) limits: StoreLimits,
    pub(crate) http_policy: Arc<HttpPolicy>,
    pub(crate) control: Arc<CallControl>,
}

impl IoView for HostState {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
}

impl WasiView for HostState {
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
}

impl WasiHttpView for HostState {
    fn ctx(&mut self) -> &mut WasiHttpCtx {
        &mut self.http
    }

    /// Every outbound request is checked, cleaned and bounded here before it
    /// leaves the host. See [`HttpPolicy`].
    fn send_request(
        &mut self,
        mut request: Request<HyperOutgoingBody>,
        mut config: OutgoingRequestConfig,
    ) -> HttpResult<HostFutureIncomingResponse> {
        let policy = Arc::clone(&self.http_policy);
        if let Err(refusal) = policy.admit(request.uri(), declared_length(request.headers())) {
            return Err(policy.error_code(&refusal).into());
        }
        policy.prepare(request.headers_mut(), &mut config);
        Ok(default_send_request(request, config))
    }
}

/// Shared engine state. Every loaded tool holds one of these.
pub(crate) struct Shared {
    pub(crate) engine: Engine,
    pub(crate) linker: Linker<HostState>,
    _ticker: Ticker,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared").finish_non_exhaustive()
    }
}

/// The Wasm runtime. Cheap to clone; clones share one engine.
#[derive(Debug, Clone)]
pub struct Runtime {
    pub(crate) shared: Arc<Shared>,
}

impl Runtime {
    /// Build the engine with the component model, epoch interruption, the
    /// pooling allocator, and the sandboxed WASI and `wasi:http` linker.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Compile`] if the engine or linker cannot be built.
    /// That indicates a platform the pooling allocator does not support.
    pub fn new() -> Result<Self, ToolError> {
        let mut config = Config::new();
        config.epoch_interruption(true);
        let mut pooling = PoolingAllocationConfig::default();
        pooling
            .total_component_instances(POOL_INSTANCES)
            .total_core_instances(POOL_INSTANCES)
            .total_memories(POOL_INSTANCES)
            .total_tables(POOL_INSTANCES)
            .max_memory_size(MAX_MEMORY_BYTES);
        config.allocation_strategy(InstanceAllocationStrategy::Pooling(pooling));

        let engine = Engine::new(&config).map_err(|e| engine_error(&e))?;
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker).map_err(|e| engine_error(&e))?;
        wasmtime_wasi_http::add_only_http_to_linker_sync(&mut linker)
            .map_err(|e| engine_error(&e))?;

        let ticker = Ticker::start(engine.clone());
        Ok(Self {
            shared: Arc::new(Shared {
                engine,
                linker,
                _ticker: ticker,
            }),
        })
    }

    /// Build a store for one instance. The epoch callback interrupts the guest
    /// when the call's deadline passes or it is cancelled.
    pub(crate) fn new_store(&self, state: HostState) -> Store<HostState> {
        let mut store = Store::new(&self.shared.engine, state);
        store.limiter(
            |state: &mut HostState| -> &mut dyn wasmtime::ResourceLimiter { &mut state.limits },
        );
        store.epoch_deadline_callback(|ctx| {
            let control = &ctx.data().control;
            if control.cancel.is_cancelled() || Instant::now() >= control.deadline {
                Err(wasmtime::Error::msg("invocation interrupted"))
            } else {
                Ok(UpdateDeadline::Continue(1))
            }
        });
        // Set before any guest code runs, so the first call starts from a deadline
        // of one tick.
        store.set_epoch_deadline(1);
        store
    }

    /// Store limits for a tool with the given memory ceiling.
    pub(crate) fn limits(memory_bytes: usize) -> StoreLimits {
        StoreLimitsBuilder::new()
            .memory_size(memory_bytes)
            .instances(16)
            .tables(16)
            .memories(4)
            .build()
    }
}

/// Advances the engine's epoch every [`EPOCH_TICK`] until dropped.
#[derive(Debug)]
struct Ticker {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Ticker {
    fn start(engine: Engine) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("tpt-mcpbox-epoch".to_owned())
            .spawn(move || {
                while !flag.load(Ordering::Relaxed) {
                    std::thread::sleep(EPOCH_TICK);
                    engine.increment_epoch();
                }
            })
            .ok();
        Self { stop, thread }
    }
}

impl Drop for Ticker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn engine_error(error: &wasmtime::Error) -> ToolError {
    ToolError::Compile {
        tool: "<runtime>".to_owned(),
        message: format!("{error:#}"),
    }
}
