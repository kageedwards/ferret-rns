// Identity struct: keypair management, encrypt/decrypt, sign/verify

use crate::crypto::ed25519::{Ed25519SigningKey, Ed25519VerifyingKey};
use crate::crypto::hashes::sha256;
use crate::crypto::x25519::{X25519PrivateKey, X25519PublicKey};
use crate::types::constants::TRUNCATED_HASHLENGTH;
use crate::{FerretError, Result};
use std::path::Path;

pub struct Identity {
    prv: Option<X25519PrivateKey>,
    sig_prv: Option<Ed25519SigningKey>,
    pub_key: Option<X25519PublicKey>,
    sig_pub: Option<Ed25519VerifyingKey>,
    hash: Option<[u8; 16]>,
    hexhash: Option<String>,
}

impl Identity {
    /// Create a new identity with freshly generated random keys.
    pub fn new() -> Self {
        let prv = X25519PrivateKey::generate();
        let sig_prv = Ed25519SigningKey::generate();
        let pub_key = prv.public_key();
        let sig_pub = sig_prv.verifying_key();

        let (hash, hexhash) = Self::compute_hash(&pub_key, &sig_pub);

        Self {
            prv: Some(prv),
            sig_prv: Some(sig_prv),
            pub_key: Some(pub_key),
            sig_pub: Some(sig_pub),
            hash: Some(hash),
            hexhash: Some(hexhash),
        }
    }

    /// Create an empty identity with no keys.
    pub fn new_empty() -> Self {
        Self {
            prv: None,
            sig_prv: None,
            pub_key: None,
            sig_pub: None,
            hash: None,
            hexhash: None,
        }
    }

    /// Construct from 64 bytes of private key data.
    /// First 32 = X25519 private, last 32 = Ed25519 seed.
    pub fn from_private_key(prv_bytes: &[u8]) -> Result<Self> {
        if prv_bytes.len() != 64 {
            return Err(FerretError::KeyLength {
                expected: 64,
                got: prv_bytes.len(),
            });
        }

        let x_bytes: [u8; 32] = prv_bytes[..32]
            .try_into()
            .map_err(|_| FerretError::KeyLength { expected: 64, got: prv_bytes.len() })?;
        let ed_bytes: [u8; 32] = prv_bytes[32..]
            .try_into()
            .map_err(|_| FerretError::KeyLength { expected: 64, got: prv_bytes.len() })?;

        let prv = X25519PrivateKey::from_bytes(&x_bytes);
        let sig_prv = Ed25519SigningKey::from_seed(&ed_bytes);
        let pub_key = prv.public_key();
        let sig_pub = sig_prv.verifying_key();

        let (hash, hexhash) = Self::compute_hash(&pub_key, &sig_pub);

        Ok(Self {
            prv: Some(prv),
            sig_prv: Some(sig_prv),
            pub_key: Some(pub_key),
            sig_pub: Some(sig_pub),
            hash: Some(hash),
            hexhash: Some(hexhash),
        })
    }

    /// Load only public keys from 64 bytes.
    /// First 32 = X25519 public, last 32 = Ed25519 verifying.
    pub fn from_public_key(pub_bytes: &[u8]) -> Result<Self> {
        if pub_bytes.len() != 64 {
            return Err(FerretError::KeyLength {
                expected: 64,
                got: pub_bytes.len(),
            });
        }

        let x_bytes: [u8; 32] = pub_bytes[..32]
            .try_into()
            .map_err(|_| FerretError::KeyLength { expected: 64, got: pub_bytes.len() })?;
        let ed_bytes: [u8; 32] = pub_bytes[32..]
            .try_into()
            .map_err(|_| FerretError::KeyLength { expected: 64, got: pub_bytes.len() })?;

        let pub_key = X25519PublicKey::from_bytes(&x_bytes);
        let sig_pub = Ed25519VerifyingKey::from_bytes(&ed_bytes)?;

        let (hash, hexhash) = Self::compute_hash(&pub_key, &sig_pub);

        Ok(Self {
            prv: None,
            sig_prv: None,
            pub_key: Some(pub_key),
            sig_pub: Some(sig_pub),
            hash: Some(hash),
            hexhash: Some(hexhash),
        })
    }

    /// Compute the identity hash from public keys.
    /// Hash = sha256(x25519_pub ++ ed25519_verifying)[..16]
    fn compute_hash(
        pub_key: &X25519PublicKey,
        sig_pub: &Ed25519VerifyingKey,
    ) -> ([u8; 16], String) {
        let mut pub_bytes = [0u8; 64];
        pub_bytes[..32].copy_from_slice(&pub_key.to_bytes());
        pub_bytes[32..].copy_from_slice(&sig_pub.to_bytes());

        let full = sha256(&pub_bytes);
        let truncated_len = TRUNCATED_HASHLENGTH / 8; // 16
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&full[..truncated_len]);

        let hexhash = hash.iter().map(|b| format!("{:02x}", b)).collect();

        (hash, hexhash)
    }

    /// Returns the 64-byte private key (X25519 prv ++ Ed25519 seed).
    pub fn get_private_key(&self) -> Result<[u8; 64]> {
        let prv = self.prv.as_ref().ok_or(FerretError::MissingPrivateKey)?;
        let sig_prv = self.sig_prv.as_ref().ok_or(FerretError::MissingPrivateKey)?;

        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&prv.to_bytes());
        key[32..].copy_from_slice(&sig_prv.to_seed());
        Ok(key)
    }

    /// Returns the 64-byte public key (X25519 pub ++ Ed25519 verifying).
    pub fn get_public_key(&self) -> Result<[u8; 64]> {
        let pub_key = self.pub_key.as_ref().ok_or(FerretError::MissingPublicKey)?;
        let sig_pub = self.sig_pub.as_ref().ok_or(FerretError::MissingPublicKey)?;

        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&pub_key.to_bytes());
        key[32..].copy_from_slice(&sig_pub.to_bytes());
        Ok(key)
    }

    /// Returns the 16-byte identity hash.
    pub fn hash(&self) -> Result<&[u8; 16]> {
        self.hash.as_ref().ok_or(FerretError::MissingPublicKey)
    }

    /// Returns the hex string of the identity hash.
    pub fn hexhash(&self) -> Result<&str> {
        self.hexhash
            .as_deref()
            .ok_or(FerretError::MissingPublicKey)
    }

    /// Write the 64-byte private key to a file.
    pub fn to_file(&self, path: &Path) -> Result<()> {
        let key = self.get_private_key()?;
        std::fs::write(path, key)?;
        Ok(())
    }

    /// Read a file containing a 64-byte private key and construct an Identity.
    pub fn from_file(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        if data.len() != 64 {
            return Err(FerretError::KeyLength {
                expected: 64,
                got: data.len(),
            });
        }
        Self::from_private_key(&data)
    }
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.hexhash {
            Some(h) => write!(f, "<{}>", h),
            None => write!(f, "<unknown>"),
        }
    }
}
