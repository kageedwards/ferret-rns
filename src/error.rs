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
}
