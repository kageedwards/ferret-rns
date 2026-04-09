/// Default block size (AES block size).
pub const DEFAULT_BLOCK_SIZE: usize = 16;

/// Appends PKCS7 padding to `data` for the given `block_size`.
///
/// Adds `n` bytes of value `n` where `n = block_size - (data.len() % block_size)`.
/// When the data is already aligned to `block_size`, a full block of padding is added.
pub fn pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let n = block_size - (data.len() % block_size);
    let mut out = Vec::with_capacity(data.len() + n);
    out.extend_from_slice(data);
    out.resize(data.len() + n, n as u8);
    out
}

/// Removes PKCS7 padding from `data` for the given `block_size`.
///
/// Reads the last byte as the padding length, validates it is > 0 and ≤ `block_size`,
/// then verifies all padding bytes match. Returns `FerretError::Padding` on any error.
pub fn unpad(data: &[u8], block_size: usize) -> crate::Result<Vec<u8>> {
    if data.is_empty() {
        return Err(crate::FerretError::Padding("input is empty".into()));
    }

    let pad_len = *data.last().unwrap() as usize;

    if pad_len == 0 || pad_len > block_size {
        return Err(crate::FerretError::Padding(format!(
            "invalid padding byte {pad_len} for block size {block_size}"
        )));
    }

    if pad_len > data.len() {
        return Err(crate::FerretError::Padding(format!(
            "padding length {pad_len} exceeds data length {}",
            data.len()
        )));
    }

    // Verify all padding bytes are consistent
    let start = data.len() - pad_len;
    for &b in &data[start..] {
        if b as usize != pad_len {
            return Err(crate::FerretError::Padding(format!(
                "expected padding byte {pad_len}, found {b}"
            )));
        }
    }

    Ok(data[..start].to_vec())
}
