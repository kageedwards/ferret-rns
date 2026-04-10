// Identity struct: keypair management, encrypt/decrypt, sign/verify

use crate::crypto::ed25519::{Ed25519SigningKey, Ed25519VerifyingKey};
use crate::crypto::hashes::sha256;
use crate::crypto::x25519::{X25519PrivateKey, X25519PublicKey};
use crate::packet::packet::Packet;
use crate::packet::Encryptable;
use crate::transport::TransportState;
use crate::types::constants::TRUNCATED_HASHLENGTH;
use crate::types::packet::{ContextFlag, HeaderType, PacketContext, PacketType};
use crate::types::transport::TransportType;
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

    /// Encrypt plaintext for this identity, optionally using a ratchet public key.
    /// Returns: ephemeral_pub_bytes (32) ++ token_ciphertext
    pub fn encrypt(&self, plaintext: &[u8], ratchet: Option<&[u8; 32]>) -> Result<Vec<u8>> {
        let pub_key = self.pub_key.as_ref().ok_or(FerretError::MissingPublicKey)?;

        let ephemeral = X25519PrivateKey::generate();
        let ephemeral_pub_bytes = ephemeral.public_key().to_bytes();

        let target_pub = match ratchet {
            Some(r) => X25519PublicKey::from_bytes(r),
            None => X25519PublicKey::from_bytes(&pub_key.to_bytes()),
        };

        let shared_key = ephemeral.exchange(&target_pub);

        let hash = self.hash.as_ref().ok_or(FerretError::MissingPublicKey)?;
        let derived_key = crate::crypto::hkdf::hkdf(
            super::DERIVED_KEY_LENGTH,
            &shared_key,
            Some(hash.as_slice()),
            None,
        )?;

        let token = crate::crypto::token::Token::new(&derived_key)?;
        let ciphertext = token.encrypt(plaintext);

        let mut result = Vec::with_capacity(32 + ciphertext.len());
        result.extend_from_slice(&ephemeral_pub_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt a ciphertext token addressed to this identity.
    /// Tries ratchet keys first, then falls back to identity key (unless enforce_ratchets).
    /// Returns Ok(Some(plaintext)) on success, Ok(None) if ratchet-enforced and no ratchet works.
    pub fn decrypt(
        &self,
        ciphertext_token: &[u8],
        ratchets: Option<&[Vec<u8>]>,
        enforce_ratchets: bool,
    ) -> Result<Option<Vec<u8>>> {
        let prv = self.prv.as_ref().ok_or(FerretError::MissingPrivateKey)?;

        if ciphertext_token.len() <= 32 {
            return Err(FerretError::Token("ciphertext token too short".into()));
        }

        let peer_pub_bytes: [u8; 32] = ciphertext_token[..32]
            .try_into()
            .map_err(|_| FerretError::Token("invalid ephemeral key".into()))?;
        let peer_pub = X25519PublicKey::from_bytes(&peer_pub_bytes);
        let ciphertext = &ciphertext_token[32..];

        let hash = self.hash.as_ref().ok_or(FerretError::MissingPublicKey)?;

        // Try ratchet keys first
        let mut plaintext: Option<Vec<u8>> = None;
        if let Some(ratchet_keys) = ratchets {
            for ratchet_bytes in ratchet_keys {
                if ratchet_bytes.len() != 32 {
                    continue;
                }
                let ratchet_prv_bytes: [u8; 32] = ratchet_bytes[..32]
                    .try_into()
                    .map_err(|_| FerretError::KeyLength {
                        expected: 32,
                        got: ratchet_bytes.len(),
                    })?;
                let ratchet_prv = X25519PrivateKey::from_bytes(&ratchet_prv_bytes);
                // Re-derive peer_pub for each attempt since exchange consumes nothing
                let ratchet_peer_pub = X25519PublicKey::from_bytes(&peer_pub_bytes);
                let shared_key = ratchet_prv.exchange(&ratchet_peer_pub);
                match self.try_decrypt(&shared_key, hash, ciphertext) {
                    Ok(pt) => {
                        plaintext = Some(pt);
                        break;
                    }
                    Err(_) => continue,
                }
            }
        }

        if enforce_ratchets && plaintext.is_none() {
            return Ok(None);
        }

        if plaintext.is_none() {
            // Fallback to identity key
            let shared_key = prv.exchange(&peer_pub);
            plaintext = Some(self.try_decrypt(&shared_key, hash, ciphertext)?);
        }

        Ok(plaintext)
    }

    /// Attempt decryption with a given shared key and identity hash.
    fn try_decrypt(
        &self,
        shared_key: &[u8; 32],
        hash: &[u8; 16],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let derived_key = crate::crypto::hkdf::hkdf(
            super::DERIVED_KEY_LENGTH,
            shared_key,
            Some(hash.as_slice()),
            None,
        )?;
        let token = crate::crypto::token::Token::new(&derived_key)?;
        token.decrypt(ciphertext)
    }

    /// Sign a message with the Ed25519 signing key. Returns 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        let sig_prv = self.sig_prv.as_ref().ok_or(FerretError::MissingPrivateKey)?;
        Ok(sig_prv.sign(message))
    }

    /// Verify a signature against a message using the Ed25519 verifying key.
    /// Returns true if valid, false if invalid signature.
    pub fn validate(&self, signature: &[u8; 64], message: &[u8]) -> Result<bool> {
        let sig_pub = self.sig_pub.as_ref().ok_or(FerretError::MissingPublicKey)?;
        match sig_pub.verify(message, signature) {
            Ok(()) => Ok(true),
            Err(FerretError::SignatureVerification) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// SHA-256 hash of data (32 bytes). Equivalent to RNS.Identity.full_hash().
    pub fn full_hash(data: &[u8]) -> [u8; 32] {
        sha256(data)
    }

    /// Truncated SHA-256 hash (first 16 bytes = TRUNCATED_HASHLENGTH / 8).
    /// Equivalent to RNS.Identity.truncated_hash().
    pub fn truncated_hash(data: &[u8]) -> [u8; 16] {
        let full = sha256(data);
        let mut truncated = [0u8; 16];
        truncated.copy_from_slice(&full[..TRUNCATED_HASHLENGTH / 8]);
        truncated
    }

    /// Random truncated hash: truncated_hash(random_16_bytes).
    /// Equivalent to RNS.Identity.get_random_hash().
    pub fn get_random_hash() -> [u8; 16] {
        let mut random_bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random_bytes);
        Self::truncated_hash(&random_bytes)
    }

    /// Prove delivery of a received packet by signing its hash and sending a PROOF packet.
    ///
    /// If `destination` is None, a ProofDestination is generated from the packet.
    /// Uses explicit proofs: packet_hash(32) + signature(64) = 96 bytes.
    pub fn prove(
        &self,
        packet: &Packet,
        destination: Option<&dyn Encryptable>,
        transport: &TransportState,
    ) -> Result<()> {
        let packet_hash = packet.get_hash();
        let signature = self.sign(&packet_hash)?;

        // Explicit proof: hash(32) + signature(64) = 96 bytes
        let mut proof_data = Vec::with_capacity(96);
        proof_data.extend_from_slice(&packet_hash);
        proof_data.extend_from_slice(&signature);

        // Use provided destination or generate proof destination
        let proof_dest;
        let dest: &dyn Encryptable = match destination {
            Some(d) => d,
            None => {
                proof_dest = packet.generate_proof_destination();
                &proof_dest
            }
        };

        // Create and send PROOF packet
        let mut proof_packet = Packet::new(
            dest,
            proof_data,
            PacketType::Proof,
            PacketContext::None,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        proof_packet.pack(dest)?;
        transport.outbound(&mut proof_packet)?;

        Ok(())
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
