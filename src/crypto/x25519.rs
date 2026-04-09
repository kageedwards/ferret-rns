use x25519_dalek::{PublicKey, StaticSecret};

/// X25519 private key wrapping `x25519_dalek::StaticSecret`.
pub struct X25519PrivateKey {
    secret: StaticSecret,
}

/// X25519 public key wrapping `x25519_dalek::PublicKey`.
pub struct X25519PublicKey {
    key: PublicKey,
}

impl X25519PrivateKey {
    /// Generate a random X25519 private key from a cryptographically secure source.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        Self { secret }
    }

    /// Construct from a 32-byte array (compile-time length check).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(*bytes),
        }
    }

    /// Serialize the private key to a 32-byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey {
            key: PublicKey::from(&self.secret),
        }
    }

    /// Perform X25519 Diffie-Hellman key exchange, returning the 32-byte shared secret.
    pub fn exchange(&self, peer: &X25519PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(&peer.key).to_bytes()
    }

    /// Construct from a runtime-length-checked slice.
    pub fn try_from_slice(slice: &[u8]) -> crate::Result<Self> {
        let bytes: [u8; 32] = slice.try_into().map_err(|_| crate::FerretError::KeyLength {
            expected: 32,
            got: slice.len(),
        })?;
        Ok(Self::from_bytes(&bytes))
    }
}

impl X25519PublicKey {
    /// Construct from a 32-byte array (compile-time length check).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            key: PublicKey::from(*bytes),
        }
    }

    /// Serialize the public key to a 32-byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    /// Construct from a runtime-length-checked slice.
    pub fn try_from_slice(slice: &[u8]) -> crate::Result<Self> {
        let bytes: [u8; 32] = slice.try_into().map_err(|_| crate::FerretError::KeyLength {
            expected: 32,
            got: slice.len(),
        })?;
        Ok(Self::from_bytes(&bytes))
    }
}
