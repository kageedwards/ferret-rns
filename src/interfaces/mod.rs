//! Interface subsystem — codecs, IFAC processor, base interface, and concrete implementations.

// Codecs and processors (always available)
pub mod hdlc_codec;
pub mod kiss_codec;
pub mod ifac_processor;
pub mod base;

// Always-on concrete interfaces
pub mod tcp_client;
pub mod tcp_server;
pub mod udp;
pub mod pipe;
pub mod local;
pub mod auto;
pub mod i2p;

// Feature-gated interfaces
#[cfg(feature = "quic")]
pub mod quic;

#[cfg(feature = "serial")]
pub mod serial;

#[cfg(feature = "serial")]
pub mod kiss;

#[cfg(feature = "serial")]
pub mod rnode;

#[cfg(feature = "serial")]
pub mod weave;

#[cfg(feature = "backbone")]
pub mod backbone;

#[cfg(feature = "plugins")]
pub mod plugin;

// Re-exports for key types
pub use base::Interface;
pub use hdlc_codec::HdlcDecoder;
pub use kiss_codec::KissDecoder;
pub use ifac_processor::IfacState;
