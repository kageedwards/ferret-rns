use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 over `data` using the given `key`.
///
/// This function is infallible. Keys longer than 64 bytes are
/// automatically hashed per RFC 2104 by the underlying `hmac` crate.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // `new_from_slice` returns Result but HMAC accepts any key length per RFC 2104.
    // The hmac crate never returns Err here — this expect is provably unreachable.
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}
