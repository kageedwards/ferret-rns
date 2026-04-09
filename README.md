# Ferret RNS

A Rust implementation of the [Reticulum Network Stack](https://reticulum.network/), aiming for wire-format interoperability with the Python reference implementation.

## Modules

| Module | Description |
|---|---|
| `crypto` | X25519, Ed25519, AES-CBC, SHA-256, HMAC, HKDF, Fernet tokens |
| `identity` | Keypair management, known-destination store, ratchet persistence, announce validation |
| `destination` | Destination addressing, hashing, encryption, announce building |
| `packet` | Packet construction, wire-format packing/unpacking, receipts, proofs |
| `transport` | Routing tables, inbound/outbound routing, announce processing, packet cache |
| `types` | Constants and wire-format enums |
| `util` | MessagePack helpers, hex utilities |

## Building

```sh
cargo build
```

## Testing

```sh
cargo test
```

Tests use [proptest](https://crates.io/crates/proptest) for property-based correctness checks.

## License

See [LICENSE](LICENSE) for details.
