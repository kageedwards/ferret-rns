/// Convenience alias used throughout the crate
pub type Result<T> = std::result::Result<T, FerretError>;

#[derive(Debug, thiserror::Error)]
pub enum FerretError {
    // Crypto errors
    #[error("invalid key length: expected {expected}, got {got}")]
    KeyLength { expected: usize, got: usize },

    #[error("invalid padding: {0}")]
    Padding(String),

    #[error("HMAC verification failed")]
    HmacVerification,

    #[error("invalid signature")]
    SignatureVerification,

    #[error("invalid public key bytes")]
    InvalidPublicKey,

    #[error("HKDF error: {0}")]
    Hkdf(String),

    #[error("token error: {0}")]
    Token(String),

    // Common errors
    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("deserialization error: {0}")]
    Deserialization(String),

    #[error("invalid enum value {value} for {enum_name}")]
    InvalidEnumValue { enum_name: &'static str, value: u8 },

    // Identity errors
    #[error("operation requires a public key, but none is available")]
    MissingPublicKey,

    #[error("operation requires a private key, but none is available")]
    MissingPrivateKey,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    // Destination errors
    #[error("invalid destination configuration: {0}")]
    InvalidDestination(String),

    // Packet errors
    #[error("packet exceeds MTU: {size} > {mtu}")]
    PacketTooLarge { size: usize, mtu: usize },

    #[error("malformed packet: {0}")]
    MalformedPacket(String),

    #[error("packet requires transport_id for Header2")]
    MissingTransportId,

    // Transport errors
    #[error("duplicate destination registration: {0}")]
    DuplicateDestination(String),

    #[error("ratchet file error: {0}")]
    RatchetFile(String),
}
