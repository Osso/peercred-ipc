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
- **Disconnect-aware server** - Additive `Connection::split` API with independent reader and writer halves

## Wire protocol

The protocol remains the legacy raw MessagePack format. Requests and responses
are serialized directly to the Unix stream with no length-prefix or other
framing header. Existing `Connection::read` and `Connection::write` callers
remain compatible.

`Connection::split` consumes a connection and returns
`ConnectionReader`/`ConnectionWriter`. After reading a request, a server can
call `ConnectionReader::wait_for_disconnect()` to observe caller EOF while
retaining `ConnectionWriter` for the response. Clients that still need a
response should half-close their write side, not close the entire socket.

## Example

Server:
```rust
use peercred_ipc::{Server, CallerInfo};

let server = Server::bind("/run/myapp.sock")?;
loop {
    let (mut conn, caller) = server.accept().await?;
    println!("Request from uid={} pid={}", caller.uid, caller.pid);
    let request: MyRequest = conn.read().await?;
    conn.write(&MyResponse::Ok).await?;
}
```

Disconnect-aware server:
```rust
let (conn, _caller) = server.accept().await?;
let (mut reader, mut writer) = conn.split();
let request: MyRequest = reader.read().await?;
reader.wait_for_disconnect().await?;
writer.write(&MyResponse::Ok).await?;
```

Client:
```rust
use peercred_ipc::Client;

let response: MyResponse = Client::call("/run/myapp.sock", &request)?;
```

## License

MIT
