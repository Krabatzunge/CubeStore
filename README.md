# CubeStore

An encrypted, persistent key-value object store for Rust. CubeStore serialises any `serde`-compatible type, encrypts the data with **AES-256-GCM**, and saves it to a single `.cos` file on disk. It also exposes a reactive `Observable<T>` handle so you can watch for in-memory changes without re-querying the store.

## Features

- **AES-256-GCM encryption** – data at rest is always encrypted; the key is derived from a password you supply.
- **Type-safe API** – insert and retrieve any type that implements `serde::Serialize` / `serde::Deserialize`.
- **Reactive observables** – obtain a live `Observable<T>` handle that reflects every `insert` call without needing to query the store again.
- **Machine password helper** – generate a stable, machine-unique password using platform identifiers (Linux machine-id, macOS hardware UUID, Windows MachineGuid).
- **Cross-platform** – works on Linux, macOS, and Windows.

## Installation

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
cube-store = { git = "https://github.com/Krabatzunge/CubeStore" }
serde = { version = "1.0", features = ["derive"] }
```

## Quick Start

```rust
use cube_store::ObjectStore;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Config {
    debug_mode: bool,
    max_connections: u32,
}

fn main() -> anyhow::Result<()> {
    // Open (or create) an encrypted store at "./data/app.cos"
    let mut store = ObjectStore::new("./data", "app", "my_secret_password")?;

    let cfg = Config { debug_mode: false, max_connections: 10 };
    store.insert("config", &cfg)?;

    let loaded: Option<Config> = store.get("config")?;
    println!("{:?}", loaded); // Some(Config { debug_mode: false, max_connections: 10 })

    Ok(())
}
```

## Usage Examples

### Basic CRUD

```rust
use cube_store::ObjectStore;

let mut store = ObjectStore::new("/tmp", "mystore", "password")?;

// Insert
store.insert("greeting", &"Hello, world!".to_string())?;
store.insert("counter", &42_i32)?;

// Read
let msg: Option<String> = store.get("greeting")?;   // Some("Hello, world!")
let num: Option<i32>    = store.get("counter")?;     // Some(42)
let missing: Option<i32> = store.get("nope")?;       // None

// Update – just insert with the same key
store.insert("counter", &43_i32)?;

// Delete
store.remove("greeting")?;
```

### Persisting Custom Structs

```rust
use cube_store::ObjectStore;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct User {
    id: u32,
    name: String,
    active: bool,
}

// --- Session 1: write ---
{
    let mut store = ObjectStore::new("./data", "users", "s3cr3t")?;
    store.insert("alice", &User { id: 1, name: "Alice".into(), active: true })?;
} // store is dropped here; data is flushed to disk

// --- Session 2: read ---
{
    let store = ObjectStore::new("./data", "users", "s3cr3t")?;
    let alice: Option<User> = store.get("alice")?;
    println!("{:?}", alice); // Some(User { id: 1, name: "Alice", active: true })
}
```

### Reactive Observables

`watch` returns an `Observable<T>` handle backed by the same in-memory buffer as the store. Calling `get()` on the observable always reflects the latest value after an `insert`.

```rust
use cube_store::ObjectStore;

let mut store = ObjectStore::new("/tmp", "reactive", "password")?;
store.insert("score", &0_u32)?;

// Obtain a live handle – no clone of the data, just a shared reference
let observer = store.watch::<u32>("score").expect("key must exist first");

println!("{}", observer.get()?); // 0

store.insert("score", &42_u32)?;
println!("{}", observer.get()?); // 42  ← reflects the update automatically
```

> **Note:** If you `remove` a key, any `Observable` you obtained for it becomes detached and will still return the last value it held.

### Machine Password

Use `machine_password()` to derive a stable password tied to the current machine so the store can be reopened across application restarts without hard-coding a secret.

```rust
use cube_store::{machine_password, ObjectStore};

let password = machine_password()?;
let mut store = ObjectStore::new("./data", "secure", &password)?;

store.insert("token", &"abc123".to_string())?;
```

The same call on the same machine always returns the same hex string, making it suitable as a default encryption key when portability is not required.

## API Reference

### `ObjectStore`

| Method | Description |
|---|---|
| `ObjectStore::new(folder, name, password)` | Opens an existing store or creates a new one. The file is saved as `{folder}/{name}.cos`. |
| `store.insert(key, value)` | Serialises and encrypts `value`, then writes it to the store under `key`. Flushes to disk immediately. |
| `store.get::<T>(key)` | Retrieves and deserialises the value stored under `key`. Returns `None` if the key does not exist. |
| `store.watch::<T>(key)` | Returns `Some(Observable<T>)` if `key` exists, or `None` otherwise. |
| `store.remove(key)` | Deletes the entry for `key` and flushes to disk. |

### `Observable<T>`

| Method | Description |
|---|---|
| `observable.get()` | Deserialises and returns the current value. Reflects any subsequent `insert` on the same key. |

### `machine_password()`

Returns a `Result<String>` containing a 64-character hex string that is deterministically derived from platform-specific hardware identifiers and the current OS. Stable across restarts on the same machine.

## File Format

Each `.cos` file has the following binary layout:

```
[ 12-byte AES-GCM nonce ][ encrypted bincode payload ]
```

The payload is a `HashMap<String, Vec<u8>>` where each value is the bincode-encoded object. A fresh nonce is generated on every flush, so the ciphertext changes even when the plaintext does not.

## Security Notes

- Losing the password makes the store permanently unreadable.
- `machine_password()` is convenient but provides only as much entropy as the underlying platform identifier. For high-security use cases, supply your own strong, randomly generated password.
- The store file contains an AES-256-GCM authentication tag, so any tampering or truncation is detected on open.

## License

This project is provided as-is without a declared license. Contact the repository owner for usage rights.
