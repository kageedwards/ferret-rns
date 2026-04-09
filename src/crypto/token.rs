use rand::RngCore;

/// Token encryption mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenMode {
    Aes128Cbc,
    Aes256Cbc,
}

/// Modified Fernet token for authenticated encryption.
///
/// Wire format: `[IV: 16 bytes] [AES-CBC ciphertext] [HMAC-SHA256: 32 bytes]`
///
/// - AES-128 mode: 32-byte key (16 signing + 16 encryption)
/// - AES-256 mode: 64-byte key (32 signing + 32 encryption)
pub struct Token {
    signing_key: Vec<u8>,
    encryption_key: Vec<u8>,
    mode: TokenMode,
}

impl Token {
    /// Create a new Token from a combined key.
    ///
    /// - 32 bytes → AES-128-CBC (first 16 = signing, last 16 = encryption)
    /// - 64 bytes → AES-256-CBC (first 32 = signing, last 32 = encryption)
    pub fn new(key: &[u8]) -> crate::Result<Self> {
        match key.len() {
            32 => Ok(Token {
                signing_key: key[..16].to_vec(),
                encryption_key: key[16..].to_vec(),
                mode: TokenMode::Aes128Cbc,
            }),
            64 => Ok(Token {
                signing_key: key[..32].to_vec(),
                encryption_key: key[32..].to_vec(),
                mode: TokenMode::Aes256Cbc,
            }),
            got => Err(crate::FerretError::KeyLength {
                expected: 32, // or 64
                got,
            }),
        }
    }

    /// Generate a random key of appropriate size for the given mode.
    pub fn generate_key(mode: TokenMode) -> Vec<u8> {
        let len = match mode {
            TokenMode::Aes128Cbc => 32,
            TokenMode::Aes256Cbc => 64,
        };
        let mut key = vec![0u8; len];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    /// Encrypt plaintext into a token.
    ///
    /// Flow: random 16-byte IV → PKCS7 pad → AES-CBC encrypt →
    ///       concat IV + ciphertext → HMAC-SHA256 over (IV + ciphertext) → append HMAC
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        // Generate random IV
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);

        // PKCS7 pad the plaintext
        let padded = super::pkcs7::pad(plaintext, 16);

        // AES-CBC encrypt (key sizes guaranteed by constructor)
        let ciphertext = match self.mode {
            TokenMode::Aes128Cbc => {
                let mut key = [0u8; 16];
                key.copy_from_slice(&self.encryption_key);
                super::aes_cbc::aes128_cbc_encrypt(&padded, &key, &iv)
            }
            TokenMode::Aes256Cbc => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&self.encryption_key);
                super::aes_cbc::aes256_cbc_encrypt(&padded, &key, &iv)
            }
        };

        // Concatenate IV + ciphertext
        let mut iv_and_ciphertext = Vec::with_capacity(16 + ciphertext.len());
        iv_and_ciphertext.extend_from_slice(&iv);
        iv_and_ciphertext.extend_from_slice(&ciphertext);

        // HMAC-SHA256 over IV + ciphertext
        let hmac = super::hmac::hmac_sha256(&self.signing_key, &iv_and_ciphertext);

        // Append HMAC
        let mut token = iv_and_ciphertext;
        token.extend_from_slice(&hmac);
        token
    }

    /// Decrypt a token back to plaintext.
    ///
    /// Flow: verify length > 32 → extract HMAC (last 32) → verify HMAC →
    ///       extract IV (first 16) → AES-CBC decrypt → PKCS7 unpad
    pub fn decrypt(&self, token: &[u8]) -> crate::Result<Vec<u8>> {
        // Token must be longer than 32 bytes (at minimum: 16 IV + 16 ciphertext + 32 HMAC = 64)
        if token.len() <= 32 {
            return Err(crate::FerretError::Token(
                "token too short".into(),
            ));
        }

        let hmac_start = token.len() - 32;
        let received_hmac = &token[hmac_start..];
        let iv_and_ciphertext = &token[..hmac_start];

        // Compute expected HMAC
        let expected_hmac = super::hmac::hmac_sha256(&self.signing_key, iv_and_ciphertext);

        // Constant-time comparison: compare all bytes without short-circuiting
        let mut diff: u8 = 0;
        for i in 0..32 {
            diff |= received_hmac[i] ^ expected_hmac[i];
        }
        if diff != 0 {
            return Err(crate::FerretError::HmacVerification);
        }

        // Extract IV and ciphertext
        let iv: [u8; 16] = iv_and_ciphertext[..16].try_into()
            .map_err(|_| crate::FerretError::Token("invalid IV length".into()))?;
        let ciphertext = &iv_and_ciphertext[16..];

        // AES-CBC decrypt
        let decrypted = match self.mode {
            TokenMode::Aes128Cbc => {
                let key: [u8; 16] = self.encryption_key[..16].try_into()
                    .map_err(|_| crate::FerretError::Token("invalid key length".into()))?;
                super::aes_cbc::aes128_cbc_decrypt(ciphertext, &key, &iv)?
            }
            TokenMode::Aes256Cbc => {
                let key: [u8; 32] = self.encryption_key[..32].try_into()
                    .map_err(|_| crate::FerretError::Token("invalid key length".into()))?;
                super::aes_cbc::aes256_cbc_decrypt(ciphertext, &key, &iv)?
            }
        };

        // PKCS7 unpad
        super::pkcs7::unpad(&decrypted, 16)
    }
}
