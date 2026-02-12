use super::*;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, Ordering};

mod basic;
mod caller_info;
mod fd_passing;
mod server;

// Unique socket path generator to avoid test interference
static SOCKET_COUNTER: AtomicU32 = AtomicU32::new(0);

fn unique_socket_path(prefix: &str) -> String {
    let id = SOCKET_COUNTER.fetch_add(1, Ordering::SeqCst);
    let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    format!(
        "{}/peercred-ipc-test-{}-{}-{}.sock",
        base,
        prefix,
        std::process::id(),
        id
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TestRequest {
    value: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TestResponse {
    doubled: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct LargeMessage {
    data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct StringMessage {
    text: String,
}
