use super::*;
use std::time::Duration;

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

#[tokio::test]
async fn client_connect_to_nonexistent_socket_fails() {
    let socket_path = unique_socket_path("nonexistent");
    let _ = fs::remove_file(&socket_path);

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

    let server_handle = tokio::spawn(async move {
        let (conn, _) = server.accept().await.unwrap();
        drop(conn);
    });

    tokio::time::sleep(Duration::from_millis(10)).await;

    let path = socket_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        Client::call::<_, TestRequest, TestResponse>(&path, &TestRequest { value: 1 })
    })
    .await
    .unwrap();

    assert!(result.is_err());
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
        let result: Result<TestRequest, IpcError> = conn.read().await;
        assert!(matches!(result, Err(IpcError::ConnectionClosed)));
    });

    tokio::time::sleep(Duration::from_millis(10)).await;

    let path = socket_path.clone();
    tokio::task::spawn_blocking(move || {
        let stream = UnixStream::connect(&path).unwrap();
        drop(stream);
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
        let result: Result<TestRequest, IpcError> = conn.read().await;
        assert!(matches!(result, Err(IpcError::Deserialize(_))));
    });

    tokio::time::sleep(Duration::from_millis(10)).await;

    // Send length-prefixed garbage data
    let path = socket_path.clone();
    tokio::task::spawn_blocking(move || {
        let mut stream = UnixStream::connect(&path).unwrap();
        let garbage = b"this is not valid msgpack data!";
        stream
            .write_all(&(garbage.len() as u32).to_le_bytes())
            .unwrap();
        stream.write_all(garbage).unwrap();
    })
    .await
    .unwrap();

    server_handle.await.unwrap();
    let _ = fs::remove_file(&socket_path);
}

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rapid_connect_disconnect() {
    let socket_path = unique_socket_path("rapid");

    let server = Server::bind(&socket_path).unwrap();

    let server_handle = tokio::spawn(async move {
        for _ in 0..10 {
            if let Ok((mut conn, _)) = server.accept().await {
                let _ = conn.read::<TestRequest>().await;
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(10)).await;

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

    tokio::time::sleep(Duration::from_millis(50)).await;

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
        conn.write(&req).await.unwrap();
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
