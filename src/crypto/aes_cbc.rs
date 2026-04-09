use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};

type Aes128CbcEnc = Encryptor<aes::Aes128>;
type Aes128CbcDec = Decryptor<aes::Aes128>;
type Aes256CbcEnc = Encryptor<aes::Aes256>;
type Aes256CbcDec = Decryptor<aes::Aes256>;

/// AES-128-CBC encrypt already-padded plaintext.
/// Plaintext length must be a multiple of 16.
pub fn aes128_cbc_encrypt(plaintext: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    let enc = Aes128CbcEnc::new(key.into(), iv.into());
    enc.encrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(plaintext)
}

/// AES-128-CBC decrypt ciphertext. Returns the raw decrypted bytes (caller handles unpadding).
pub fn aes128_cbc_decrypt(
    ciphertext: &[u8],
    key: &[u8; 16],
    iv: &[u8; 16],
) -> crate::Result<Vec<u8>> {
    let dec = Aes128CbcDec::new(key.into(), iv.into());
    dec.decrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(ciphertext)
        .map_err(|e| crate::FerretError::Token(format!("decryption failed: {}", e)))
}

/// AES-256-CBC encrypt already-padded plaintext.
/// Plaintext length must be a multiple of 16.
pub fn aes256_cbc_encrypt(plaintext: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    let enc = Aes256CbcEnc::new(key.into(), iv.into());
    enc.encrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(plaintext)
}

/// AES-256-CBC decrypt ciphertext. Returns the raw decrypted bytes (caller handles unpadding).
pub fn aes256_cbc_decrypt(
    ciphertext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 16],
) -> crate::Result<Vec<u8>> {
    let dec = Aes256CbcDec::new(key.into(), iv.into());
    dec.decrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(ciphertext)
        .map_err(|e| crate::FerretError::Token(format!("decryption failed: {}", e)))
}
