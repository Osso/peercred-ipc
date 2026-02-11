//! Unix socket IPC with msgpack serialization and SO_PEERCRED caller info
//!
//! Provides simple request/response communication over Unix sockets
//! using MessagePack for fast binary serialization. Includes caller
//! identification via SO_PEERCRED (uid, gid, pid, exe path).
//!
//! # Example
//!
//! Server:
//! ```ignore
//! use peercred_ipc::{Server, CallerInfo};
//!
//! let server = Server::bind("/run/myapp.sock")?;
//! loop {
//!     let (mut conn, caller) = server.accept().await?;
//!     println!("Request from uid={} pid={}", caller.uid, caller.pid);
//!     let request: MyRequest = conn.read().await?;
//!     conn.write(&MyResponse::Ok).await?;
//! }
//! ```
//!
//! Client:
//! ```ignore
//! use peercred_ipc::Client;
//!
//! let response: MyResponse = Client::call("/run/myapp.sock", &request)?;
//! ```

use serde::{de::DeserializeOwned, Serialize};
use std::fs;
use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream as TokioUnixStream};

/// Maximum message size (4 MB - larger for screenshots)
pub const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

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

/// Maximum number of file descriptors that can be sent in a single message
pub const MAX_FDS: usize = 8;

/// Send data with file descriptors using SCM_RIGHTS
fn sendmsg_with_fds(fd: RawFd, data: &[u8], fds: &[RawFd]) -> Result<usize, IpcError> {
    let iov = [IoSlice::new(data)];

    if fds.is_empty() {
        // No fds, just send data
        let sent = unsafe { libc::send(fd, data.as_ptr() as *const _, data.len(), 0) };
        if sent < 0 {
            return Err(IpcError::Io(std::io::Error::last_os_error()));
        }
        return Ok(sent as usize);
    }

    // Build control message for SCM_RIGHTS
    let fds_size = std::mem::size_of_val(fds);
    let cmsg_space = unsafe { libc::CMSG_SPACE(fds_size as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = iov.as_ptr() as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
    msg.msg_controllen = cmsg_space;

    // Fill in the control message header
    let cmsg: *mut libc::cmsghdr = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(fds_size as u32) as usize;
        std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(cmsg) as *mut RawFd, fds.len());
    }

    let sent = unsafe { libc::sendmsg(fd, &msg, 0) };
    if sent < 0 {
        return Err(IpcError::Io(std::io::Error::last_os_error()));
    }
    Ok(sent as usize)
}

/// Receive data with file descriptors using SCM_RIGHTS
fn recvmsg_with_fds(fd: RawFd, buf: &mut [u8]) -> Result<(usize, Vec<OwnedFd>), IpcError> {
    let mut iov = [IoSliceMut::new(buf)];

    let fds_size = std::mem::size_of::<RawFd>() * MAX_FDS;
    let cmsg_space = unsafe { libc::CMSG_SPACE(fds_size as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = iov.as_mut_ptr() as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
    msg.msg_controllen = cmsg_space;

    let received = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if received < 0 {
        return Err(IpcError::Io(std::io::Error::last_os_error()));
    }
    if received == 0 {
        return Err(IpcError::ConnectionClosed);
    }

    // Extract file descriptors from control message
    let mut fds = Vec::new();
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        unsafe {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data_ptr = libc::CMSG_DATA(cmsg) as *const RawFd;
                let data_len = (*cmsg).cmsg_len - libc::CMSG_LEN(0) as usize;
                let num_fds = data_len / std::mem::size_of::<RawFd>();
                for i in 0..num_fds {
                    let raw_fd = *data_ptr.add(i);
                    fds.push(OwnedFd::from_raw_fd(raw_fd));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    Ok((received as usize, fds))
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
    /// Read a message from the connection (length-prefixed)
    pub async fn read<T: DeserializeOwned>(&mut self) -> Result<T, IpcError> {
        // Read 4-byte length prefix
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;

        if len > MAX_MESSAGE_SIZE {
            return Err(IpcError::Io(std::io::Error::other("message too large")));
        }

        // Read the message body
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await?;
        Ok(rmp_serde::from_slice(&buf)?)
    }

    /// Write a message to the connection (length-prefixed)
    pub async fn write<T: Serialize>(&mut self, msg: &T) -> Result<(), IpcError> {
        let data = rmp_serde::to_vec(msg)?;
        // Write 4-byte length prefix
        let len = data.len() as u32;
        self.stream.write_all(&len.to_le_bytes()).await?;
        self.stream.write_all(&data).await?;
        Ok(())
    }

    /// Read a message with file descriptors from the connection
    ///
    /// Uses SCM_RIGHTS to receive file descriptors alongside the message.
    /// The returned OwnedFd values are owned by the caller.
    pub async fn read_with_fds<T: DeserializeOwned>(
        &mut self,
    ) -> Result<(T, Vec<OwnedFd>), IpcError> {
        // Need to use blocking operation for recvmsg
        self.stream.readable().await?;
        let fd = self.stream.as_raw_fd();
        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];

        let (n, fds) = recvmsg_with_fds(fd, &mut buf)?;
        let msg = rmp_serde::from_slice(&buf[..n])?;
        Ok((msg, fds))
    }

    /// Write a message with file descriptors to the connection
    ///
    /// Uses SCM_RIGHTS to send file descriptors alongside the message.
    /// The file descriptors are borrowed and remain valid after sending.
    pub async fn write_with_fds<T: Serialize>(
        &mut self,
        msg: &T,
        fds: &[RawFd],
    ) -> Result<(), IpcError> {
        let data = rmp_serde::to_vec(msg)?;
        self.stream.writable().await?;
        let fd = self.stream.as_raw_fd();
        sendmsg_with_fds(fd, &data, fds)?;
        Ok(())
    }
}

/// Synchronous client for making IPC calls
pub struct Client;

impl Client {
    /// Connect to a socket and perform a single request/response exchange (length-prefixed)
    pub fn call<P, Req, Res>(path: P, request: &Req) -> Result<Res, IpcError>
    where
        P: AsRef<Path>,
        Req: Serialize,
        Res: DeserializeOwned,
    {
        let mut stream = UnixStream::connect(path)?;

        // Write length-prefixed request
        let data = rmp_serde::to_vec(request)?;
        let len = data.len() as u32;
        stream.write_all(&len.to_le_bytes())?;
        stream.write_all(&data)?;

        // Read length-prefixed response
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;

        if len > MAX_MESSAGE_SIZE {
            return Err(IpcError::Io(std::io::Error::other("message too large")));
        }

        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;
        Ok(rmp_serde::from_slice(&buf)?)
    }

    /// Connect and send a request, receiving a response with file descriptors
    ///
    /// Useful when the server needs to send file descriptors (e.g., device fds)
    /// back to the client.
    pub fn call_recv_fds<P, Req, Res>(
        path: P,
        request: &Req,
    ) -> Result<(Res, Vec<OwnedFd>), IpcError>
    where
        P: AsRef<Path>,
        Req: Serialize,
        Res: DeserializeOwned,
    {
        let stream = UnixStream::connect(path)?;
        let fd = stream.as_raw_fd();

        let data = rmp_serde::to_vec(request)?;
        sendmsg_with_fds(fd, &data, &[])?;

        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        let (n, fds) = recvmsg_with_fds(fd, &mut buf)?;
        let msg = rmp_serde::from_slice(&buf[..n])?;
        Ok((msg, fds))
    }

    /// Connect and send a request with file descriptors
    ///
    /// Useful when the client needs to send file descriptors to the server.
    pub fn call_send_fds<P, Req, Res>(
        path: P,
        request: &Req,
        fds: &[RawFd],
    ) -> Result<Res, IpcError>
    where
        P: AsRef<Path>,
        Req: Serialize,
        Res: DeserializeOwned,
    {
        let mut stream = UnixStream::connect(path)?;
        let fd = stream.as_raw_fd();

        let data = rmp_serde::to_vec(request)?;
        sendmsg_with_fds(fd, &data, fds)?;

        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err(IpcError::ConnectionClosed);
        }
        Ok(rmp_serde::from_slice(&buf[..n])?)
    }

    /// Connect and exchange request/response with file descriptors in both directions
    pub fn call_with_fds<P, Req, Res>(
        path: P,
        request: &Req,
        fds: &[RawFd],
    ) -> Result<(Res, Vec<OwnedFd>), IpcError>
    where
        P: AsRef<Path>,
        Req: Serialize,
        Res: DeserializeOwned,
    {
        let stream = UnixStream::connect(path)?;
        let fd = stream.as_raw_fd();

        let data = rmp_serde::to_vec(request)?;
        sendmsg_with_fds(fd, &data, fds)?;

        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        let (n, recv_fds) = recvmsg_with_fds(fd, &mut buf)?;
        let msg = rmp_serde::from_slice(&buf[..n])?;
        Ok((msg, recv_fds))
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
            Client::call(
                &path,
                &StringMessage {
                    text: "hello world".to_string(),
                },
            )
            .unwrap()
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
        let socket_path = unique_socket_path("nonexistent");
        let _ = fs::remove_file(&socket_path); // Ensure it doesn't exist

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
            e => panic!(
                "Expected ConnectionClosed or ConnectionReset/BrokenPipe, got {:?}",
                e
            ),
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
            stream
                .write_all(b"this is not valid msgpack data!")
                .unwrap();
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
                exe_str.contains("peercred-ipc")
                    || exe_str.contains("peercred_ipc")
                    || exe_str.contains("deps"),
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
                conn.write(&TestResponse {
                    doubled: req.value * 2,
                })
                .await
                .unwrap();
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
                    conn.write(&TestResponse {
                        doubled: req.value * 2,
                    })
                    .await
                    .unwrap();
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
                conn.write(&TestResponse {
                    doubled: req.value * 2,
                })
                .await
                .unwrap();
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

    // ============================================================
    // File descriptor passing tests (SCM_RIGHTS)
    // ============================================================

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct OpenDeviceRequest {
        path: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct OpenDeviceResponse {
        success: bool,
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_sends_fd_to_client() {
        let socket_path = unique_socket_path("fd-server-to-client");

        let server = Server::bind(&socket_path).unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut conn, _) = server.accept().await.unwrap();
            let req: OpenDeviceRequest = conn.read().await.unwrap();
            assert_eq!(req.path, "/dev/null");

            // Open a file and send the fd
            let file = std::fs::File::open("/dev/null").unwrap();
            let fd = file.as_raw_fd();

            conn.write_with_fds(&OpenDeviceResponse { success: true }, &[fd])
                .await
                .unwrap();

            // Keep file alive until response is sent
            drop(file);
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let path = socket_path.clone();
        tokio::task::spawn_blocking(move || {
            let (resp, fds): (OpenDeviceResponse, Vec<OwnedFd>) = Client::call_recv_fds(
                &path,
                &OpenDeviceRequest {
                    path: "/dev/null".to_string(),
                },
            )
            .unwrap();

            assert!(resp.success);
            assert_eq!(fds.len(), 1);

            // Verify the fd is valid by reading from it
            use std::io::Read;
            let mut f = unsafe { std::fs::File::from_raw_fd(fds[0].as_raw_fd()) };
            let mut buf = [0u8; 1];
            // /dev/null returns EOF immediately
            assert_eq!(f.read(&mut buf).unwrap(), 0);

            // Prevent double-close
            std::mem::forget(f);
        })
        .await
        .unwrap();

        server_handle.await.unwrap();
        let _ = fs::remove_file(&socket_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_sends_fd_to_server() {
        let socket_path = unique_socket_path("fd-client-to-server");

        let server = Server::bind(&socket_path).unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut conn, _) = server.accept().await.unwrap();
            let (req, fds): (StringMessage, Vec<OwnedFd>) = conn.read_with_fds().await.unwrap();

            assert_eq!(req.text, "here's a file");
            assert_eq!(fds.len(), 1);

            // Verify fd is valid
            use std::io::Read;
            let mut f = unsafe { std::fs::File::from_raw_fd(fds[0].as_raw_fd()) };
            let mut buf = [0u8; 1];
            assert_eq!(f.read(&mut buf).unwrap(), 0);
            std::mem::forget(f);

            conn.write(&StringMessage {
                text: "received".to_string(),
            })
            .await
            .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let path = socket_path.clone();
        tokio::task::spawn_blocking(move || {
            let file = std::fs::File::open("/dev/null").unwrap();
            let fd = file.as_raw_fd();

            let resp: StringMessage = Client::call_send_fds(
                &path,
                &StringMessage {
                    text: "here's a file".to_string(),
                },
                &[fd],
            )
            .unwrap();

            assert_eq!(resp.text, "received");
        })
        .await
        .unwrap();

        server_handle.await.unwrap();
        let _ = fs::remove_file(&socket_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multiple_fds_in_one_message() {
        let socket_path = unique_socket_path("fd-multiple");

        let server = Server::bind(&socket_path).unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut conn, _) = server.accept().await.unwrap();
            let _req: TestRequest = conn.read().await.unwrap();

            // Open multiple files
            let f1 = std::fs::File::open("/dev/null").unwrap();
            let f2 = std::fs::File::open("/dev/zero").unwrap();
            let f3 = std::fs::File::open("/dev/null").unwrap();

            conn.write_with_fds(
                &TestResponse { doubled: 3 },
                &[f1.as_raw_fd(), f2.as_raw_fd(), f3.as_raw_fd()],
            )
            .await
            .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let path = socket_path.clone();
        tokio::task::spawn_blocking(move || {
            let (resp, fds): (TestResponse, Vec<OwnedFd>) =
                Client::call_recv_fds(&path, &TestRequest { value: 1 }).unwrap();

            assert_eq!(resp.doubled, 3);
            assert_eq!(fds.len(), 3);
        })
        .await
        .unwrap();

        server_handle.await.unwrap();
        let _ = fs::remove_file(&socket_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bidirectional_fd_passing() {
        let socket_path = unique_socket_path("fd-bidirectional");

        let server = Server::bind(&socket_path).unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut conn, _) = server.accept().await.unwrap();
            let (req, client_fds): (StringMessage, Vec<OwnedFd>) =
                conn.read_with_fds().await.unwrap();

            assert_eq!(req.text, "client fd");
            assert_eq!(client_fds.len(), 1);

            // Send back a different fd
            let server_file = std::fs::File::open("/dev/zero").unwrap();
            conn.write_with_fds(
                &StringMessage {
                    text: "server fd".to_string(),
                },
                &[server_file.as_raw_fd()],
            )
            .await
            .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let path = socket_path.clone();
        tokio::task::spawn_blocking(move || {
            let client_file = std::fs::File::open("/dev/null").unwrap();

            let (resp, server_fds): (StringMessage, Vec<OwnedFd>) = Client::call_with_fds(
                &path,
                &StringMessage {
                    text: "client fd".to_string(),
                },
                &[client_file.as_raw_fd()],
            )
            .unwrap();

            assert_eq!(resp.text, "server fd");
            assert_eq!(server_fds.len(), 1);
        })
        .await
        .unwrap();

        server_handle.await.unwrap();
        let _ = fs::remove_file(&socket_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn message_without_fds_using_fd_methods() {
        let socket_path = unique_socket_path("fd-empty");

        let server = Server::bind(&socket_path).unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut conn, _) = server.accept().await.unwrap();
            let (req, fds): (TestRequest, Vec<OwnedFd>) = conn.read_with_fds().await.unwrap();

            assert_eq!(req.value, 42);
            assert!(fds.is_empty());

            conn.write_with_fds(&TestResponse { doubled: 84 }, &[])
                .await
                .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let path = socket_path.clone();
        tokio::task::spawn_blocking(move || {
            let (resp, fds): (TestResponse, Vec<OwnedFd>) =
                Client::call_with_fds(&path, &TestRequest { value: 42 }, &[]).unwrap();

            assert_eq!(resp.doubled, 84);
            assert!(fds.is_empty());
        })
        .await
        .unwrap();

        server_handle.await.unwrap();
        let _ = fs::remove_file(&socket_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn async_connection_fd_roundtrip() {
        let socket_path = unique_socket_path("fd-async-roundtrip");

        let server = Server::bind(&socket_path).unwrap();

        // Use async connection methods on both sides
        let server_handle = tokio::spawn(async move {
            let (mut conn, _) = server.accept().await.unwrap();

            // Receive with fds
            let (req, client_fds): (TestRequest, Vec<OwnedFd>) =
                conn.read_with_fds().await.unwrap();
            assert_eq!(req.value, 100);
            assert_eq!(client_fds.len(), 1);

            // Send with fds
            let f = std::fs::File::open("/dev/zero").unwrap();
            conn.write_with_fds(&TestResponse { doubled: 200 }, &[f.as_raw_fd()])
                .await
                .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Connect async client
        let mut client_stream = TokioUnixStream::connect(&socket_path).await.unwrap();
        let client_file = std::fs::File::open("/dev/null").unwrap();

        // Send with fd
        let data = rmp_serde::to_vec(&TestRequest { value: 100 }).unwrap();
        client_stream.writable().await.unwrap();
        sendmsg_with_fds(client_stream.as_raw_fd(), &data, &[client_file.as_raw_fd()]).unwrap();

        // Receive with fd
        client_stream.readable().await.unwrap();
        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        let (n, server_fds) = recvmsg_with_fds(client_stream.as_raw_fd(), &mut buf).unwrap();
        let resp: TestResponse = rmp_serde::from_slice(&buf[..n]).unwrap();

        assert_eq!(resp.doubled, 200);
        assert_eq!(server_fds.len(), 1);

        server_handle.await.unwrap();
        let _ = fs::remove_file(&socket_path);
    }
}
