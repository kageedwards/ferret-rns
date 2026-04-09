use sha2::Digest;

/// Compute the SHA-256 hash of `data`, returning a 32-byte digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute the SHA-512 hash of `data`, returning a 64-byte digest.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = sha2::Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}
