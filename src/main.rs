use std::sync::{Arc, Mutex};
use std::{
    convert::Infallible, ffi::c_void, mem::MaybeUninit, net::SocketAddr, ptr, time::Instant,
};

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use once_cell::sync::Lazy;
use prometheus::{Encoder, Gauge, TextEncoder};
use sysinfo::{Pid, RefreshKind};
use tokio::{
    task,
    time::{Duration, interval},
};

#[cfg(target_os = "windows")]
mod windows;

pub use windows::PdhGpu as Gpu;

fn setup_logger() -> Result<(), anyhow::Error> {
    env_logger::builder()
        .is_test(true)
        .try_init()
        .map_err(|e| anyhow::anyhow!("Failed to initialize logger: {}", e))?;
    Ok(())
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu_usage: f32,
    pub memory_used: u64,
    pub gpu_usage: f32,
}

#[derive(Debug, clap::Parser)]
struct App {
    #[clap(short, long, required = true)]
    pid: u32,
}

#[derive(Clone)]
struct AppState {
    pid: Pid,
    sys_info: Arc<Mutex<sysinfo::System>>,
    gpu: Arc<Mutex<Gpu>>,
}

// ── main ──────────────────────────────────────────────────────
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    setup_logger()?;
    let app = App::parse();

    let process_kind = sysinfo::ProcessRefreshKind::everything();

    let sys =
        sysinfo::System::new_with_specifics(RefreshKind::nothing().with_processes(process_kind));

    let pid = sysinfo::Pid::from_u32(app.pid);
    let _ = sys.process(pid).expect("process not found");

    let gpu = Gpu::new(app.pid).unwrap();

    assert!(gpu.is_active(), "GPU metrics not available");

    let app = Router::new()
        .route("/metrics", get(get_metrics))
        .with_state(AppState {
            pid,
            sys_info: Arc::new(Mutex::new(sys)),
            gpu: Arc::new(Mutex::new(gpu)),
        });

    let listener = tokio::net::TcpListener::bind("0.0.0.0:28993")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
    Ok(())
}
#[axum::debug_handler]
async fn get_metrics(state: State<AppState>) -> Json<ProcessInfo> {
    let gpu = state.gpu.lock().unwrap();
    let mut sys = state.sys_info.lock().unwrap();
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::Some(&[state.pid]),
        true,
        sysinfo::ProcessRefreshKind::everything(),
    );
    let process = sys.process(state.pid).expect("process not found");
    let gpu_usage = gpu.sample();

    Json(ProcessInfo {
        pid: state.pid.as_u32(),
        name: process.name().to_string_lossy().to_string(),
        cpu_usage: process.cpu_usage(),
        memory_used: process.memory(),
        gpu_usage: gpu_usage as f32,
    })
}
