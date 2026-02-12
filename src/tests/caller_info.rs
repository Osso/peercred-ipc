use super::*;
use std::time::Duration;

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
        assert_ne!(caller.exe, PathBuf::from("unknown"));
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
    let path = exe_path(u32::MAX - 1);
    assert_eq!(path, PathBuf::from("unknown"));
}
