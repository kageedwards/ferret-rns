# Ferret RNS

A Rust implementation of the [Reticulum Network Stack](https://reticulum.network/).

<p align="center">
  <img src="assets/ferret.jpg" alt="Ferret" width="100%">
</p>

Ferret is a drop-in replacement for the Python `rnsd` daemon and a native Rust library for building applications on Reticulum. It ships the same CLI utilities as the Python reference — `rnsd`, `rnstatus`, `rnpath`, `rnid`, and more — plus ferret-original tools like `rnmon`, `rnnamed`, `rnlog`, `rnlink`, and `rnbench`. Python RNS applications (NomadNet, MeshChat, LXMF, Sideband) can connect to ferret's shared instance without modification.

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
- HDLC and KISS codec framing
- Leveled logging (Critical through Extreme)
- CLI utilities: `rnsd`, `rnstatus`, `rnpath`, `rnid`, `rnprobe`, `rncp`, `rnx`, `rnlog`, `rnlink`, `rnbench`, `rnmon`, `rnnamed`, `rnodeconf`
- Name service library with PoW anti-spam, record validation, persistent store

### What's next

- Live network testing of link-based utilities (`rncp`, `rnx`, `rnlink`, `rnbench`)
- Full transport-layer integration for `rnprobe` (packet receipt callbacks)

### Should™ work

- LXStamper-compatible proof-of-work stamps (discovery announcer/handler use the same HKDF workblock expansion + leading-zero-bits algorithm as the Python LXMF LXStamper, but not yet validated against live peers exchanging discovery announces)
- IFAC (Interface Access Code) authentication
- QUIC transport interface (experimental, built with the `quic` feature flag — not yet tested against live peers)

## Quick start

```sh
# Build all binaries
cargo build --release

# Run the daemon (uses ~/.reticulum/config, same as Python rnsd)
./target/release/rnsd

# Run with custom config directory
./target/release/rnsd -c /path/to/config

# Run with verbose logging
./target/release/rnsd -vv

# Run as a service (log to file)
./target/release/rnsd -s

# Check network status
./target/release/rnstatus

# Show all interfaces including hidden ones
./target/release/rnstatus -a

# Show path table
./target/release/rnpath -t

# Generate a new identity
./target/release/rnid -g ~/.reticulum/my_identity

# Encrypt a file
./target/release/rnid -i ~/.reticulum/my_identity -e secret.txt

# Sign a file
./target/release/rnid -i ~/.reticulum/my_identity -s document.txt
```

Ferret reads the same `~/.reticulum/config` file as the Python reference. If no config exists, it creates a default one.

## Using with NomadNet

1. Stop any running Python `rnsd` instance
2. Start ferret: `./target/release/rnsd`
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

Ferret is a single-crate Rust project. The library modules are layered, and the CLI binaries live under `src/bin/`.

### CLI Binaries

| Binary | Status | Description |
|--------|--------|-------------|
| `rnsd` | ✅ | Reticulum daemon (shared instance server) |
| `rnstatus` | ✅ | Network interface status display |
| `rnpath` | ✅ | Path table management and queries |
| `rnid` | ✅ | Identity management, encrypt/decrypt, sign/verify |
| `rnprobe` | ✅ | Network probe (ping-like RTT measurement) |
| `rncp` | ✅ | File transfer over Links |
| `rnx` | ✅ | Remote command execution |
| `rnlog` | ✅ | Live announce stream logger (ferret-original) |
| `rnlink` | ✅ | Raw bidirectional Link pipe (ferret-original) |
| `rnbench` | ✅ | Network throughput benchmark (ferret-original) |
| `rnmon` | ✅ | TUI network monitor (ferret-original, requires `tui` feature) |
| `rnnamed` | ✅ | Human-readable name service (ferret-original) |
| `rnodeconf` | ✅ | RNode hardware configuration (requires `serial` feature) |

### Library Modules

| Layer | Module | Purpose |
|-------|--------|---------|
| 1 | `crypto` | X25519, Ed25519, AES-CBC, SHA-256/512, HMAC, HKDF, Fernet tokens, LXStamper PoW |
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
| 8 | `rpc_client` | RPC client for shared-instance control port queries |
| 8 | `util/format` | Output formatting (pretty hex, sizes, speeds, timestamps) |
| 8 | `names` | Human-readable name service (record, store, resolver) |

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
| `serial` | yes | Serial port interfaces (KISS, RNode, Weave) and `rnodeconf` |
| `backbone` | yes | Backbone TCP mesh interface |
| `quic` | yes | QUIC transport (experimental) |
| `tui` | yes | TUI network monitor (`rnmon`) via ratatui |
| `plugins` | no | Dynamic library interface plugins |

## Testing

```sh
# Run all tests
cargo test

# Run unit tests only
cargo test --lib

# Run CLI property tests
cargo test --test cli_props -- --test-threads=1

# Run integration tests
cargo test --test integration

# Run with single thread (avoids port conflicts for RPC tests)
cargo test -- --test-threads=1
```

The test suite includes 280+ tests: unit tests, property-based tests (proptest), and end-to-end integration tests. The CLI property tests validate 15 correctness properties covering HMAC authentication, pickle wire format, encrypt/decrypt round-trips, sign/validate round-trips, and output formatting.

## License

See [LICENSE](LICENSE) for details.

## Acknowledgments

Ferret is built to be interoperable with [Reticulum](https://github.com/markqvist/Reticulum) by Mark Qvist. The protocol specification and reference implementation are the authoritative source for wire-format compatibility.
