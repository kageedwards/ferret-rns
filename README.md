# Ferret

A Rust implementation of the [Reticulum Network Stack](https://reticulum.network/).

<p align="center">
  <img src="assets/ferret.jpg" alt="Ferret" width="400">
</p>

Ferret is a drop-in replacement for the Python `rnsd` daemon. It runs as a shared instance that Python RNS applications — NomadNet, MeshChat, LXMF, Sideband, and any other software built on Reticulum — can connect to without modification.

## Status

Ferret is functional and interoperable with the Python reference stack. It has been tested with:

- **NomadNet** — TUI launches, announces propagate, network peers discovered
- **Python RNS clients** — shared instance connection, RPC queries, announce forwarding
- **Live Reticulum network** — TCP transport interfaces (RMAP, RNS Faultline, etc.)

### What works

- Shared instance server (local TCP on port 37428)
- RPC server (Python `multiprocessing.connection` protocol on port 37429)
- All interface types: TCP client/server, UDP, Auto, I2P, Pipe, Serial, KISS, RNode, Weave, Backbone
- Announce validation, path table management, rate limiting
- Packet forwarding between network interfaces and local clients
- State persistence (path table, known destinations, transport identity)
- IFAC (Interface Access Code) authentication
- HDLC and KISS codec framing
- Leveled logging (Critical through Extreme)

### What's next

- CLI utilities (`rnstatus`, `rnpath`, `rnprobe`, `rnid`, `rncp`, `rnx`)
- Link establishment and channel communication
- Resource transfers

## Quick start

```sh
# Build
cargo build --release

# Run (uses ~/.reticulum/config, same as Python rnsd)
./target/release/ferret-rns

# Run with custom config directory
./target/release/ferret-rns -c /path/to/config

# Run with debug logging
./target/release/ferret-rns -l 6

# Run with extreme (per-packet) logging
./target/release/ferret-rns -l 7
```

Ferret reads the same `~/.reticulum/config` file as the Python reference. If no config exists, it creates a default one.

## Using with NomadNet

1. Stop any running Python `rnsd` instance
2. Start ferret: `./target/release/ferret-rns`
3. Start NomadNet: `nomadnet`

NomadNet will connect to ferret's shared instance automatically.

## Configuration

Ferret uses the standard Reticulum INI config format. Example:

```ini
[reticulum]
  share_instance = yes
  shared_instance_port = 37428
  instance_control_port = 37429
  enable_transport = no

[logging]
  loglevel = 4

[interfaces]
  [[Default Interface]]
    type = AutoInterface
    enabled = yes

  [[TCP Transport]]
    type = TCPClientInterface
    enabled = yes
    target_host = rmap.world
    target_port = 4242
```

## Log levels

| Level | Name | Shows |
|-------|------|-------|
| 0 | Critical | Fatal errors |
| 1 | Error | Recoverable errors |
| 2 | Warning | Interface failures, persist errors |
| 3 | Notice | Interface skipped, fallback to standalone |
| 4 | Info | Startup milestones, shutdown (default) |
| 5 | Verbose | Connections, announces validated, interfaces registered |
| 6 | Debug | Init steps, RPC commands, read loop lifecycle |
| 7 | Extreme | Per-packet routing, byte counts, frame decodes |

## Architecture

Ferret is a single-crate Rust binary. The implementation is layered:

| Layer | Module | Purpose |
|-------|--------|---------|
| 1 | `crypto` | X25519, Ed25519, AES-CBC, SHA-256/512, HMAC, HKDF, Fernet tokens |
| 2 | `identity` | Keypair management, identity store, ratchet store, announce validation |
| 3 | `destination` | Addressing, hashing, encryption, announce building |
| 3 | `packet` | Wire-format packing/unpacking, receipts, proofs |
| 3 | `transport` | Routing tables, inbound/outbound, announce processing, packet cache |
| 4 | `link` | Link establishment, handshake, keepalive, encryption, requests |
| 4 | `channel` | Reliable message delivery over links |
| 4 | `buffer` | Stream I/O over channels |
| 5 | `resource` | Large data transfer with segmentation and compression |
| 5 | `discovery` | Interface announcer, auto-connect, blackhole management |
| 6 | `interfaces` | TCP, UDP, Serial, KISS, RNode, I2P, Auto, Pipe, Backbone, Weave, Local |
| 7 | `reticulum` | Main process, config parser, RPC server, background jobs, logging |

## Building from source

Requires Rust 1.75+ (2021 edition).

```sh
# Default build (includes serial, backbone, QUIC support)
cargo build --release

# Minimal build (no serial/backbone/QUIC)
cargo build --release --no-default-features

# With specific features
cargo build --release --features "serial,backbone"
```

### Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `serial` | yes | Serial port interfaces (KISS, RNode, Weave) |
| `backbone` | yes | Backbone TCP mesh interface |
| `quic` | yes | QUIC transport (experimental) |
| `plugins` | no | Dynamic library interface plugins |

## Testing

```sh
# Run all tests
cargo test

# Run unit tests only
cargo test --lib

# Run integration tests
cargo test --test integration

# Run property-based tests
cargo test --test wiring_props

# Run with single thread (avoids port conflicts)
cargo test -- --test-threads=1
```

The test suite includes 280+ tests: unit tests, property-based tests (proptest), and end-to-end integration tests.

## License

See [LICENSE](LICENSE) for details.

## Acknowledgments

Ferret is built to be interoperable with [Reticulum](https://github.com/markqvist/Reticulum) by Mark Qvist. The protocol specification and reference implementation are the authoritative source for wire-format compatibility.
