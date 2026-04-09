use hkdf::Hkdf;
use sha2::Sha256;

/// HKDF key derivation using HMAC-SHA256.
///
/// - `length`: desired output length in bytes (must be ≥ 1)
/// - `derive_from`: input key material (must be non-empty)
/// - `salt`: optional salt; defaults to 32 zero bytes when `None` or empty
/// - `context`: optional info/context; defaults to empty bytes when `None`
pub fn hkdf(
    length: usize,
    derive_from: &[u8],
    salt: Option<&[u8]>,
    context: Option<&[u8]>,
) -> crate::Result<Vec<u8>> {
    if length < 1 {
        return Err(crate::FerretError::Hkdf(
            "output length must be at least 1".into(),
        ));
    }
    if derive_from.is_empty() {
        return Err(crate::FerretError::Hkdf(
            "input key material must not be empty".into(),
        ));
    }

    let default_salt = [0u8; 32];
    let effective_salt = match salt {
        Some(s) if !s.is_empty() => s,
        _ => &default_salt,
    };
    let effective_context = context.unwrap_or(b"");

    let hk = Hkdf::<Sha256>::new(Some(effective_salt), derive_from);
    let mut okm = vec![0u8; length];
    hk.expand(effective_context, &mut okm).map_err(|e| {
        crate::FerretError::Hkdf(e.to_string())
    })?;

    Ok(okm)
}
