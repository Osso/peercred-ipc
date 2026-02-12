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
        let mut len_buf = [0u8; 4];
        match self.stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(IpcError::ConnectionClosed);
            }
            Err(e) => return Err(IpcError::Io(e)),
        }
        let len = u32::from_le_bytes(len_buf) as usize;

        if len > MAX_MESSAGE_SIZE {
            return Err(IpcError::Io(std::io::Error::other("message too large")));
        }

        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await?;
        Ok(rmp_serde::from_slice(&buf)?)
    }

    /// Write a message to the connection (length-prefixed)
    pub async fn write<T: Serialize>(&mut self, msg: &T) -> Result<(), IpcError> {
        let data = rmp_serde::to_vec(msg)?;
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

        let data = rmp_serde::to_vec(request)?;
        let len = data.len() as u32;
        stream.write_all(&len.to_le_bytes())?;
        stream.write_all(&data)?;

        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(IpcError::ConnectionClosed);
            }
            Err(e) => return Err(IpcError::Io(e)),
        }
        let len = u32::from_le_bytes(len_buf) as usize;

        if len > MAX_MESSAGE_SIZE {
            return Err(IpcError::Io(std::io::Error::other("message too large")));
        }

        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;
        Ok(rmp_serde::from_slice(&buf)?)
    }

    /// Connect and send a request, receiving a response with file descriptors
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
mod tests;
