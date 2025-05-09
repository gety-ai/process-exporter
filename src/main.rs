use std::{
    convert::Infallible, ffi::c_void, mem::MaybeUninit, net::SocketAddr, ptr, time::Instant,
};

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use once_cell::sync::Lazy;
use prometheus::{Encoder, Gauge, TextEncoder};
use tokio::{
    task,
    time::{Duration, interval},
};

mod windows;

// ── HTTP handler ──────────────────────────────────────────────
async fn metrics(_: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let mut buf = Vec::new();
    TextEncoder::new()
        .encode(&prometheus::gather(), &mut buf)
        .unwrap();
    let resp = Response::builder()
        .header("Content-Type", "text/plain; version=0.0.4")
        .body(Full::new(Bytes::from(buf)))
        .unwrap();
    Ok(resp)
}

fn setup_logger() -> Result<(), anyhow::Error> {
    env_logger::builder()
        .is_test(true)
        .try_init()
        .map_err(|e| anyhow::anyhow!("Failed to initialize logger: {}", e))?;
    Ok(())
}

// ── main ──────────────────────────────────────────────────────
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    setup_logger()?;

    Ok(())
}
