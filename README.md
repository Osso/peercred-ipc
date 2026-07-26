# peercred-ipc

[![CI](https://github.com/Osso/peercred-ipc/actions/workflows/ci.yml/badge.svg)](https://github.com/Osso/peercred-ipc/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/peercred-ipc.svg)](https://crates.io/crates/peercred-ipc)
[![docs.rs](https://docs.rs/peercred-ipc/badge.svg)](https://docs.rs/peercred-ipc)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Unix socket IPC with msgpack serialization and SO_PEERCRED caller info.

## Features

- **MessagePack serialization** - Fast binary serialization via rmp-serde
- **Caller identification** - SO_PEERCRED provides uid, gid, pid, and exe path of the connecting process
- **Async server** - Tokio-based async server for handling connections
- **Sync client** - Simple blocking client for request/response patterns
- **Disconnect-aware server connections** - Split one connection into independent reader and writer halves

## Protocol

Requests and responses use length-prefixed MessagePack frames over the Unix socket. The
legacy `Connection::read` and `Connection::write` methods use this same framed protocol.
`Client::call` performs one framed request/response exchange.

After reading a request, servers that need to observe caller lifetime can consume the
connection with `Connection::split()`:

- `ConnectionReader::read` reads framed MessagePack requests.
- `ConnectionReader::wait_for_disconnect` waits for the client to close its write side.
- `ConnectionWriter::write` sends framed MessagePack responses independently.

`wait_for_disconnect` should be called after the request is read. EOF reports a clean
disconnect; additional client data is reported as a protocol error.

## Example

Server:
```rust
use peercred_ipc::Server;

let server = Server::bind("/run/myapp.sock")?;
loop {
    let (conn, caller) = server.accept().await?;
    println!("Request from uid={} pid={}", caller.uid, caller.pid);
    let (mut reader, mut writer) = conn.split();
    let request: MyRequest = reader.read().await?;
    writer.write(&MyResponse::Ok).await?;
}
```

To monitor caller lifetime while an operation is running, keep the reader and writer
halves and select between the operation and `reader.wait_for_disconnect()`.

Client:
```rust
use peercred_ipc::Client;

let response: MyResponse = Client::call("/run/myapp.sock", &request)?;
```

## License

MIT
