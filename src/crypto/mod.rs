pub mod x25519;
pub mod ed25519;
pub mod hashes;
pub mod hmac;
pub mod hkdf;
pub mod aes_cbc;
pub mod pkcs7;
pub mod token;

// Re-exports for convenient access
pub use x25519::{X25519PrivateKey, X25519PublicKey};
pub use ed25519::{Ed25519SigningKey, Ed25519VerifyingKey};
pub use hashes::{sha256, sha512};
pub use hmac::hmac_sha256;
pub use hkdf::hkdf;
pub use aes_cbc::{
    aes128_cbc_encrypt, aes128_cbc_decrypt,
    aes256_cbc_encrypt, aes256_cbc_decrypt,
};
pub use pkcs7::{pad, unpad, DEFAULT_BLOCK_SIZE};
pub use token::{Token, TokenMode};

// Crypto-level constants (from Identity.py in the reference implementation)
/// Total key size in bits (256-bit X25519 + 256-bit Ed25519)
pub const KEYSIZE: usize = 512;
/// Ratchet key size in bits
pub const RATCHETSIZE: usize = 256;
/// AES-128 block size in bytes
pub const AES128_BLOCKSIZE: usize = 16;
/// Hash output length in bits (SHA-256)
pub const HASHLENGTH: usize = 256;
/// Signature length in bits (Ed25519, equal to KEYSIZE)
pub const SIGLENGTH: usize = 512;
/// Name hash length in bits
pub const NAME_HASH_LENGTH: usize = 80;
/// Token overhead in bytes (16-byte IV + 32-byte HMAC)
pub const TOKEN_OVERHEAD: usize = 48;
