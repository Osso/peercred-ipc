use super::*;
use std::time::Duration;

#[tokio::test]
async fn server_removes_existing_socket_on_bind() {
    let socket_path = unique_socket_path("rebind");

    fs::write(&socket_path, "dummy").unwrap();
    assert!(Path::new(&socket_path).exists());

    let _server = Server::bind(&socket_path).unwrap();

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
        // Use raw connection with length-prefixed framing
        let mut stream = UnixStream::connect(&path).unwrap();

        for i in 0..3 {
            let req = TestRequest { value: i * 10 };
            let data = rmp_serde::to_vec(&req).unwrap();
            // Write length prefix + data
            stream
                .write_all(&(data.len() as u32).to_le_bytes())
                .unwrap();
            stream.write_all(&data).unwrap();

            // Read length prefix + data
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).unwrap();
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).unwrap();
            let resp: TestResponse = rmp_serde::from_slice(&buf).unwrap();
            assert_eq!(resp.doubled, i * 20);
        }
    })
    .await
    .unwrap();

    server_handle.await.unwrap();
    let _ = fs::remove_file(&socket_path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_message_within_limit() {
    let socket_path = unique_socket_path("large-ok");

    let server = Server::bind(&socket_path).unwrap();

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
