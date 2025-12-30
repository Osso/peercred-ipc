//! Unix socket IPC with msgpack serialization
//!
//! Provides simple request/response communication over Unix sockets
//! using MessagePack for fast binary serialization.
//!
//! # Example
//!
//! Server:
//! ```ignore
//! use unix_ipc::{Server, CallerInfo};
//!
//! let server = Server::bind("/run/myapp.sock")?;
//! loop {
//!     let (mut conn, caller) = server.accept().await?;
//!     let request: MyRequest = conn.read().await?;
//!     conn.write(&MyResponse::Ok).await?;
//! }
//! ```
//!
//! Client:
//! ```ignore
//! use unix_ipc::Client;
//!
//! let response: MyResponse = Client::call("/run/myapp.sock", &request)?;
//! ```

use serde::{de::DeserializeOwned, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream as TokioUnixStream};

/// Maximum message size (64 KB)
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024;

#[derive(Error, Debug)]
pub enum IpcError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialize: {0}")]
    Serialize(#[from] rmp_serde::encode::Error),

    #[error("deserialize: {0}")]
    Deserialize(#[from] rmp_serde::decode::Error),

    #[error("connection closed")]
    ConnectionClosed,
}

/// Information about the connected peer, extracted from socket credentials
#[derive(Debug, Clone)]
pub struct CallerInfo {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    /// Resolved from /proc/<pid>/exe
    pub exe: PathBuf,
}

impl CallerInfo {
    /// Extract caller info from a tokio UnixStream using SO_PEERCRED
    pub fn from_stream(stream: &TokioUnixStream) -> Result<Self, IpcError> {
        let cred = stream.peer_cred()?;
        let pid = cred.pid().unwrap_or(0) as u32;
        Ok(Self {
            uid: cred.uid(),
            gid: cred.gid(),
            pid,
            exe: exe_path(pid),
        })
    }

    /// Extract caller info from a std UnixStream using SO_PEERCRED
    pub fn from_std_stream(stream: &UnixStream) -> Result<Self, IpcError> {
        // std UnixStream doesn't have peer_cred directly, use libc
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(stream);
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret != 0 {
            return Err(IpcError::Io(std::io::Error::last_os_error()));
        }
        Ok(Self {
            uid: cred.uid,
            gid: cred.gid,
            pid: cred.pid as u32,
            exe: exe_path(cred.pid as u32),
        })
    }
}

fn exe_path(pid: u32) -> PathBuf {
    fs::read_link(format!("/proc/{}/exe", pid)).unwrap_or_else(|_| PathBuf::from("unknown"))
}

/// Async server for handling IPC connections
pub struct Server {
    listener: UnixListener,
}

impl Server {
    /// Bind to a Unix socket path
    ///
    /// Removes any existing socket file and sets permissions to 0o666
    pub fn bind<P: AsRef<Path>>(path: P) -> Result<Self, IpcError> {
        let path = path.as_ref();
        let _ = fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
        Ok(Self { listener })
    }

    /// Bind with custom permissions
    pub fn bind_with_mode<P: AsRef<Path>>(path: P, mode: u32) -> Result<Self, IpcError> {
        let path = path.as_ref();
        let _ = fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        Ok(Self { listener })
    }

    /// Accept a new connection, returning the connection and caller info
    pub async fn accept(&self) -> Result<(Connection, CallerInfo), IpcError> {
        let (stream, _) = self.listener.accept().await?;
        let caller = CallerInfo::from_stream(&stream)?;
        Ok((Connection { stream }, caller))
    }
}

/// An active connection to a client
pub struct Connection {
    stream: TokioUnixStream,
}

impl Connection {
    /// Read a message from the connection
    pub async fn read<T: DeserializeOwned>(&mut self) -> Result<T, IpcError> {
        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        let n = self.stream.read(&mut buf).await?;
        if n == 0 {
            return Err(IpcError::ConnectionClosed);
        }
        Ok(rmp_serde::from_slice(&buf[..n])?)
    }

    /// Write a message to the connection
    pub async fn write<T: Serialize>(&mut self, msg: &T) -> Result<(), IpcError> {
        let data = rmp_serde::to_vec(msg)?;
        self.stream.write_all(&data).await?;
        Ok(())
    }
}

/// Synchronous client for making IPC calls
pub struct Client;

impl Client {
    /// Connect to a socket and perform a single request/response exchange
    pub fn call<P, Req, Res>(path: P, request: &Req) -> Result<Res, IpcError>
    where
        P: AsRef<Path>,
        Req: Serialize,
        Res: DeserializeOwned,
    {
        let mut stream = UnixStream::connect(path)?;
        let data = rmp_serde::to_vec(request)?;
        stream.write_all(&data)?;

        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err(IpcError::ConnectionClosed);
        }
        Ok(rmp_serde::from_slice(&buf[..n])?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    // Unique socket path generator to avoid test interference
    static SOCKET_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn unique_socket_path(prefix: &str) -> String {
        let id = SOCKET_COUNTER.fetch_add(1, Ordering::SeqCst);
        format!("/tmp/unix-ipc-test-{}-{}-{}.sock", prefix, std::process::id(), id)
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

    // ============================================================
    // Basic roundtrip tests
    // ============================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn roundtrip() {
        let socket_path = unique_socket_path("roundtrip");

        let server = Server::bind(&socket_path).unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut conn, caller) = server.accept().await.unwrap();
            assert!(caller.pid > 0);

            let req: TestRequest = conn.read().await.unwrap();
            let resp = TestResponse {
                doubled: req.value * 2,
            };
            conn.write(&resp).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let path = socket_path.clone();
        let resp: TestResponse = tokio::task::spawn_blocking(move || {
            Client::call(&path, &TestRequest { value: 21 }).unwrap()
        })
        .await
        .unwrap();
        assert_eq!(resp.doubled, 42);

        server_handle.await.unwrap();
        let _ = fs::remove_file(&socket_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn roundtrip_with_string_data() {
        let socket_path = unique_socket_path("string");

        let server = Server::bind(&socket_path).unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut conn, _) = server.accept().await.unwrap();
            let req: StringMessage = conn.read().await.unwrap();
            let resp = StringMessage {
                text: req.text.to_uppercase(),
            };
            conn.write(&resp).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let path = socket_path.clone();
        let resp: StringMessage = tokio::task::spawn_blocking(move || {
            Client::call(&path, &StringMessage { text: "hello world".to_string() }).unwrap()
        })
        .await
        .unwrap();
        assert_eq!(resp.text, "HELLO WORLD");

        server_handle.await.unwrap();
        let _ = fs::remove_file(&socket_path);
    }

    // ============================================================
    // Error handling tests
    // ============================================================

    #[tokio::test]
    async fn client_connect_to_nonexistent_socket_fails() {
        let socket_path = "/tmp/nonexistent-socket-12345.sock";
        let _ = fs::remove_file(socket_path); // Ensure it doesn't exist

        let result: Result<TestResponse, IpcError> =
            Client::call(socket_path, &TestRequest { value: 1 });

        assert!(result.is_err());
        match result.unwrap_err() {
            IpcError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
            }
            e => panic!("Expected Io error, got {:?}", e),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connection_closed_detected_on_read() {
        let socket_path = unique_socket_path("closed-read");

        let server = Server::bind(&socket_path).unwrap();

        // Server accepts but closes connection without responding
        let server_handle = tokio::spawn(async move {
            let (conn, _) = server.accept().await.unwrap();
            drop(conn); // Close immediately
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let path = socket_path.clone();
        let result = tokio::task::spawn_blocking(move || {
            Client::call::<_, TestRequest, TestResponse>(&path, &TestRequest { value: 1 })
        })
        .await
        .unwrap();

        assert!(result.is_err());
        // Connection can fail with ConnectionClosed (on read) or ConnectionReset (if write races with close)
        match result.unwrap_err() {
            IpcError::ConnectionClosed => {}
            IpcError::Io(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            IpcError::Io(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            e => panic!("Expected ConnectionClosed or ConnectionReset/BrokenPipe, got {:?}", e),
        }

        server_handle.await.unwrap();
        let _ = fs::remove_file(&socket_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connection_closed_detected_on_server_read() {
        let socket_path = unique_socket_path("server-closed-read");

        let server = Server::bind(&socket_path).unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut conn, _) = server.accept().await.unwrap();
            // Try to read but client will close without sending
            let result: Result<TestRequest, IpcError> = conn.read().await;
            assert!(matches!(result, Err(IpcError::ConnectionClosed)));
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Connect and close without sending
        let path = socket_path.clone();
        tokio::task::spawn_blocking(move || {
            let stream = UnixStream::connect(&path).unwrap();
            drop(stream); // Close immediately
        })
        .await
        .unwrap();

        server_handle.await.unwrap();
        let _ = fs::remove_file(&socket_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deserialize_error_on_malformed_data() {
        let socket_path = unique_socket_path("malformed");

        let server = Server::bind(&socket_path).unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut conn, _) = server.accept().await.unwrap();
            // Try to read as TestRequest but receive garbage
            let result: Result<TestRequest, IpcError> = conn.read().await;
            assert!(matches!(result, Err(IpcError::Deserialize(_))));
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Send raw garbage data
        let path = socket_path.clone();
        tokio::task::spawn_blocking(move || {
            let mut stream = UnixStream::connect(&path).unwrap();
            stream.write_all(b"this is not valid msgpack data!").unwrap();
        })
        .await
        .unwrap();

        server_handle.await.unwrap();
        let _ = fs::remove_file(&socket_path);
    }

    // ============================================================
    // CallerInfo tests
    // ============================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn caller_info_has_correct_pid() {
        let socket_path = unique_socket_path("callerinfo-pid");

        let server = Server::bind(&socket_path).unwrap();
        let expected_pid = std::process::id();

        let server_handle = tokio::spawn(async move {
            let (mut conn, caller) = server.accept().await.unwrap();
            assert_eq!(caller.pid, expected_pid);
            let _: TestRequest = conn.read().await.unwrap();
            conn.write(&TestResponse { doubled: 0 }).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let path = socket_path.clone();
        tokio::task::spawn_blocking(move || {
            let _: TestResponse = Client::call(&path, &TestRequest { value: 1 }).unwrap();
        })
        .await
        .unwrap();

        server_handle.await.unwrap();
        let _ = fs::remove_file(&socket_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn caller_info_has_correct_uid_gid() {
        let socket_path = unique_socket_path("callerinfo-uid");

        let server = Server::bind(&socket_path).unwrap();
        let expected_uid = unsafe { libc::getuid() };
        let expected_gid = unsafe { libc::getgid() };

        let server_handle = tokio::spawn(async move {
            let (mut conn, caller) = server.accept().await.unwrap();
            assert_eq!(caller.uid, expected_uid);
            assert_eq!(caller.gid, expected_gid);
            let _: TestRequest = conn.read().await.unwrap();
            conn.write(&TestResponse { doubled: 0 }).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let path = socket_path.clone();
        tokio::task::spawn_blocking(move || {
            let _: TestResponse = Client::call(&path, &TestRequest { value: 1 }).unwrap();
        })
        .await
        .unwrap();

        server_handle.await.unwrap();
        let _ = fs::remove_file(&socket_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn caller_info_exe_path_is_valid() {
        let socket_path = unique_socket_path("callerinfo-exe");

        let server = Server::bind(&socket_path).unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut conn, caller) = server.accept().await.unwrap();
            // Should resolve to something (not "unknown")
            assert_ne!(caller.exe, PathBuf::from("unknown"));
            // Should contain the test binary name
            let exe_str = caller.exe.to_string_lossy();
            assert!(
                exe_str.contains("unix-ipc") || exe_str.contains("unix_ipc") || exe_str.contains("deps"),
                "exe path should contain test binary reference: {}",
                exe_str
            );
            let _: TestRequest = conn.read().await.unwrap();
            conn.write(&TestResponse { doubled: 0 }).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let path = socket_path.clone();
        tokio::task::spawn_blocking(move || {
            let _: TestResponse = Client::call(&path, &TestRequest { value: 1 }).unwrap();
        })
        .await
        .unwrap();

        server_handle.await.unwrap();
        let _ = fs::remove_file(&socket_path);
    }

    #[test]
    fn caller_info_from_std_stream() {
        let socket_path = unique_socket_path("std-callerinfo");

        // Create a quick server using std
        let _ = fs::remove_file(&socket_path);
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();

        let path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            let stream = UnixStream::connect(&path).unwrap();
            let caller = CallerInfo::from_std_stream(&stream).unwrap();
            assert_eq!(caller.pid, std::process::id());
            assert_eq!(caller.uid, unsafe { libc::getuid() });
            assert_eq!(caller.gid, unsafe { libc::getgid() });
        });

        let (stream, _) = listener.accept().unwrap();
        let caller = CallerInfo::from_std_stream(&stream).unwrap();
        assert_eq!(caller.pid, std::process::id());

        client_thread.join().unwrap();
        let _ = fs::remove_file(&socket_path);
    }

    #[test]
    fn exe_path_for_current_process() {
        let path = exe_path(std::process::id());
        assert_ne!(path, PathBuf::from("unknown"));
        assert!(path.exists());
    }

    #[test]
    fn exe_path_for_nonexistent_process_returns_unknown() {
        // Use a very high PID that almost certainly doesn't exist
        let path = exe_path(u32::MAX - 1);
        assert_eq!(path, PathBuf::from("unknown"));
    }

    // ============================================================
    // Server behavior tests
    // ============================================================

    #[tokio::test]
    async fn server_removes_existing_socket_on_bind() {
        let socket_path = unique_socket_path("rebind");

        // Create a file at the socket path
        fs::write(&socket_path, "dummy").unwrap();
        assert!(Path::new(&socket_path).exists());

        // Bind should succeed and remove the existing file
        let _server = Server::bind(&socket_path).unwrap();

        // Cleanup
        let _ = fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn server_sets_default_permissions() {
        let socket_path = unique_socket_path("perms-default");

        let _server = Server::bind(&socket_path).unwrap();

        let metadata = fs::metadata(&socket_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o666, "Default permissions should be 0o666");

        let _ = fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn server_sets_custom_permissions() {
        let socket_path = unique_socket_path("perms-custom");

        let _server = Server::bind_with_mode(&socket_path, 0o600).unwrap();

        let metadata = fs::metadata(&socket_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "Custom permissions should be 0o600");

        let _ = fs::remove_file(&socket_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn server_handles_multiple_sequential_connections() {
        let socket_path = unique_socket_path("sequential");

        let server = Server::bind(&socket_path).unwrap();

        let server_handle = tokio::spawn(async move {
            for i in 0..3 {
                let (mut conn, _) = server.accept().await.unwrap();
                let req: TestRequest = conn.read().await.unwrap();
                assert_eq!(req.value, i);
                conn.write(&TestResponse { doubled: req.value * 2 }).await.unwrap();
            }
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        for i in 0..3 {
            let path = socket_path.clone();
            let resp: TestResponse = tokio::task::spawn_blocking(move || {
                Client::call(&path, &TestRequest { value: i }).unwrap()
            })
            .await
            .unwrap();
            assert_eq!(resp.doubled, i * 2);
        }

        server_handle.await.unwrap();
        let _ = fs::remove_file(&socket_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn server_handles_concurrent_connections() {
        let socket_path = unique_socket_path("concurrent");

        let server = Server::bind(&socket_path).unwrap();
        let num_clients = 5;

        let server_handle = tokio::spawn(async move {
            let mut handles = vec![];
            for _ in 0..num_clients {
                let (mut conn, _) = server.accept().await.unwrap();
                handles.push(tokio::spawn(async move {
                    let req: TestRequest = conn.read().await.unwrap();
                    // Simulate some work
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    conn.write(&TestResponse { doubled: req.value * 2 }).await.unwrap();
                }));
            }
            for h in handles {
                h.await.unwrap();
            }
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Spawn multiple clients concurrently
        let mut client_handles = vec![];
        for i in 0..num_clients {
            let path = socket_path.clone();
            client_handles.push(tokio::task::spawn_blocking(move || {
                let resp: TestResponse = Client::call(&path, &TestRequest { value: i }).unwrap();
                assert_eq!(resp.doubled, i * 2);
            }));
        }

        for h in client_handles {
            h.await.unwrap();
        }

        server_handle.await.unwrap();
        let _ = fs::remove_file(&socket_path);
    }

    // ============================================================
    // Connection lifecycle tests
    // ============================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connection_multiple_read_write_cycles() {
        let socket_path = unique_socket_path("multi-rw");

        let server = Server::bind(&socket_path).unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut conn, _) = server.accept().await.unwrap();

            for _ in 0..3 {
                let req: TestRequest = conn.read().await.unwrap();
                conn.write(&TestResponse { doubled: req.value * 2 }).await.unwrap();
            }
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let path = socket_path.clone();
        tokio::task::spawn_blocking(move || {
            // Use raw connection for multiple cycles
            let mut stream = UnixStream::connect(&path).unwrap();

            for i in 0..3 {
                let req = TestRequest { value: i * 10 };
                let data = rmp_serde::to_vec(&req).unwrap();
                stream.write_all(&data).unwrap();

                let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
                let n = stream.read(&mut buf).unwrap();
                let resp: TestResponse = rmp_serde::from_slice(&buf[..n]).unwrap();
                assert_eq!(resp.doubled, i * 20);
            }
        })
        .await
        .unwrap();

        server_handle.await.unwrap();
        let _ = fs::remove_file(&socket_path);
    }

    // ============================================================
    // Message size tests
    // ============================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn large_message_within_limit() {
        let socket_path = unique_socket_path("large-ok");

        let server = Server::bind(&socket_path).unwrap();

        // ~32KB of data (well within 64KB limit)
        let large_data = vec![0x42u8; 32 * 1024];

        let expected_data = large_data.clone();
        let server_handle = tokio::spawn(async move {
            let (mut conn, _) = server.accept().await.unwrap();
            let req: LargeMessage = conn.read().await.unwrap();
            assert_eq!(req.data.len(), expected_data.len());
            assert_eq!(req.data, expected_data);
            conn.write(&LargeMessage { data: req.data }).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let path = socket_path.clone();
        let send_data = large_data.clone();
        let resp: LargeMessage = tokio::task::spawn_blocking(move || {
            Client::call(&path, &LargeMessage { data: send_data }).unwrap()
        })
        .await
        .unwrap();

        assert_eq!(resp.data.len(), large_data.len());
        assert_eq!(resp.data, large_data);

        server_handle.await.unwrap();
        let _ = fs::remove_file(&socket_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn empty_vec_message() {
        let socket_path = unique_socket_path("empty-vec");

        let server = Server::bind(&socket_path).unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut conn, _) = server.accept().await.unwrap();
            let req: LargeMessage = conn.read().await.unwrap();
            assert!(req.data.is_empty());
            conn.write(&LargeMessage { data: vec![] }).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let path = socket_path.clone();
        let resp: LargeMessage = tokio::task::spawn_blocking(move || {
            Client::call(&path, &LargeMessage { data: vec![] }).unwrap()
        })
        .await
        .unwrap();

        assert!(resp.data.is_empty());

        server_handle.await.unwrap();
        let _ = fs::remove_file(&socket_path);
    }

    // ============================================================
    // IpcError tests
    // ============================================================

    #[test]
    fn ipc_error_display_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test");
        let err = IpcError::Io(io_err);
        assert!(err.to_string().contains("io:"));
    }

    #[test]
    fn ipc_error_display_connection_closed() {
        let err = IpcError::ConnectionClosed;
        assert_eq!(err.to_string(), "connection closed");
    }

    // ============================================================
    // Edge cases
    // ============================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rapid_connect_disconnect() {
        let socket_path = unique_socket_path("rapid");

        let server = Server::bind(&socket_path).unwrap();

        let server_handle = tokio::spawn(async move {
            // Accept connections but some may close immediately
            for _ in 0..10 {
                if let Ok((mut conn, _)) = server.accept().await {
                    let _ = conn.read::<TestRequest>().await;
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Rapid connect/disconnect
        let path = socket_path.clone();
        tokio::task::spawn_blocking(move || {
            for _ in 0..10 {
                if let Ok(stream) = UnixStream::connect(&path) {
                    drop(stream);
                }
            }
        })
        .await
        .unwrap();

        // Give server time to process
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Server should not panic
        server_handle.abort();
        let _ = fs::remove_file(&socket_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unicode_in_messages() {
        let socket_path = unique_socket_path("unicode");

        let server = Server::bind(&socket_path).unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut conn, _) = server.accept().await.unwrap();
            let req: StringMessage = conn.read().await.unwrap();
            conn.write(&req).await.unwrap(); // Echo back
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let unicode_text = "Hello 世界 🌍 Привет مرحبا".to_string();
        let expected = unicode_text.clone();

        let path = socket_path.clone();
        let resp: StringMessage = tokio::task::spawn_blocking(move || {
            Client::call(&path, &StringMessage { text: unicode_text }).unwrap()
        })
        .await
        .unwrap();

        assert_eq!(resp.text, expected);

        server_handle.await.unwrap();
        let _ = fs::remove_file(&socket_path);
    }
}
