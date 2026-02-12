use super::*;
use std::time::Duration;

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
        let (req, _): (OpenDeviceRequest, Vec<OwnedFd>) = conn.read_with_fds().await.unwrap();
        assert_eq!(req.path, "/dev/null");

        let file = std::fs::File::open("/dev/null").unwrap();
        let fd = file.as_raw_fd();

        conn.write_with_fds(&OpenDeviceResponse { success: true }, &[fd])
            .await
            .unwrap();

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

        use std::io::Read;
        let mut f = unsafe { std::fs::File::from_raw_fd(fds[0].as_raw_fd()) };
        let mut buf = [0u8; 1];
        assert_eq!(f.read(&mut buf).unwrap(), 0);
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

        use std::io::Read;
        let mut f = unsafe { std::fs::File::from_raw_fd(fds[0].as_raw_fd()) };
        let mut buf = [0u8; 1];
        assert_eq!(f.read(&mut buf).unwrap(), 0);
        std::mem::forget(f);

        conn.write_with_fds(
            &StringMessage {
                text: "received".to_string(),
            },
            &[],
        )
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
        let (_req, _): (TestRequest, Vec<OwnedFd>) = conn.read_with_fds().await.unwrap();

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
        let (req, client_fds): (StringMessage, Vec<OwnedFd>) = conn.read_with_fds().await.unwrap();

        assert_eq!(req.text, "client fd");
        assert_eq!(client_fds.len(), 1);

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

    let server_handle = tokio::spawn(async move {
        let (mut conn, _) = server.accept().await.unwrap();

        let (req, client_fds): (TestRequest, Vec<OwnedFd>) = conn.read_with_fds().await.unwrap();
        assert_eq!(req.value, 100);
        assert_eq!(client_fds.len(), 1);

        let f = std::fs::File::open("/dev/zero").unwrap();
        conn.write_with_fds(&TestResponse { doubled: 200 }, &[f.as_raw_fd()])
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(10)).await;

    let client_stream = TokioUnixStream::connect(&socket_path).await.unwrap();
    let client_file = std::fs::File::open("/dev/null").unwrap();

    let data = rmp_serde::to_vec(&TestRequest { value: 100 }).unwrap();
    client_stream.writable().await.unwrap();
    sendmsg_with_fds(client_stream.as_raw_fd(), &data, &[client_file.as_raw_fd()]).unwrap();

    client_stream.readable().await.unwrap();
    let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
    let (n, server_fds) = recvmsg_with_fds(client_stream.as_raw_fd(), &mut buf).unwrap();
    let resp: TestResponse = rmp_serde::from_slice(&buf[..n]).unwrap();

    assert_eq!(resp.doubled, 200);
    assert_eq!(server_fds.len(), 1);

    server_handle.await.unwrap();
    let _ = fs::remove_file(&socket_path);
}
