use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

/// Ed25519 signing key wrapping `ed25519_dalek::SigningKey`.
pub struct Ed25519SigningKey {
    inner: SigningKey,
}

/// Ed25519 verifying key wrapping `ed25519_dalek::VerifyingKey`.
pub struct Ed25519VerifyingKey {
    inner: VerifyingKey,
}

impl Ed25519SigningKey {
    /// Generate a random Ed25519 signing key from a cryptographically secure source.
    pub fn generate() -> Self {
        let inner = SigningKey::generate(&mut rand::thread_rng());
        Self { inner }
    }

    /// Construct from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            inner: SigningKey::from_bytes(seed),
        }
    }

    /// Return the 32-byte seed.
    pub fn to_seed(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Derive the corresponding verifying (public) key.
    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        Ed25519VerifyingKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// Sign a message, returning a 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.inner.sign(message).to_bytes()
    }
}

impl Ed25519VerifyingKey {
    /// Construct from 32 bytes. Returns error for invalid public key bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> crate::Result<Self> {
        let inner =
            VerifyingKey::from_bytes(bytes).map_err(|_| crate::FerretError::InvalidPublicKey)?;
        Ok(Self { inner })
    }

    /// Serialize the verifying key to a 32-byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Verify a 64-byte signature against a message.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> crate::Result<()> {
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        self.inner
            .verify_strict(message, &sig)
            .map_err(|_| crate::FerretError::SignatureVerification)
    }
}
