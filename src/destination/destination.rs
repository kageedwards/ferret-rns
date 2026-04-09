// Destination struct: construction, hashing, encrypt/decrypt, group key management

use crate::crypto::hashes::sha256;
use crate::crypto::token::Token;
use crate::crypto::NAME_HASH_LENGTH;
use crate::identity::{Identity, RatchetStore};
use crate::packet::Encryptable;
use crate::types::constants::TRUNCATED_HASHLENGTH;
use crate::types::destination::{DestinationDirection, DestinationType, ProofStrategy};
use crate::{FerretError, Result};
use std::path::PathBuf;

pub struct Destination {
    pub identity: Option<Identity>,
    pub direction: DestinationDirection,
    pub dest_type: DestinationType,
    pub hash: [u8; 16],
    pub name_hash: [u8; 10],
    pub name: String,
    pub hexhash: String,
    // Proof strategy
    pub proof_strategy: ProofStrategy,
    pub accept_link_requests: bool,
    // Group key (GROUP destinations only)
    group_key: Option<Vec<u8>>,
    group_token: Option<Token>,
    // Ratchet state (managed by ratchets.rs, but fields here)
    pub ratchets: Option<Vec<Vec<u8>>>,
    pub ratchets_path: Option<PathBuf>,
    pub ratchet_interval: u64,
    pub retained_ratchets: usize,
    pub latest_ratchet_time: Option<f64>,
    pub latest_ratchet_id: Option<[u8; 10]>,
    pub enforce_ratchets_flag: bool,
    // Default app data
    pub default_app_data: Option<Vec<u8>>,
    // MTU
    pub mtu: usize,
}

impl Destination {
    /// Construct a new Destination with all validation.
    pub fn new(
        identity: Option<Identity>,
        direction: DestinationDirection,
        dest_type: DestinationType,
        app_name: &str,
        aspects: &[&str],
    ) -> Result<Self> {
        // Validate no dots in app_name or aspects
        if app_name.contains('.') {
            return Err(FerretError::InvalidDestination(
                "dots not allowed in app_name".into(),
            ));
        }
        for a in aspects {
            if a.contains('.') {
                return Err(FerretError::InvalidDestination(
                    "dots not allowed in aspects".into(),
                ));
            }
        }

        let mut identity = identity;
        let mut owned_aspects: Vec<String> = aspects.iter().map(|s| s.to_string()).collect();

        // IN non-PLAIN without identity: generate a new one
        if identity.is_none()
            && direction == DestinationDirection::In
            && dest_type != DestinationType::Plain
        {
            let new_id = Identity::new();
            owned_aspects.push(new_id.hexhash()?.to_string());
            identity = Some(new_id);
        }

        // OUT non-PLAIN without identity: error
        if identity.is_none()
            && direction == DestinationDirection::Out
            && dest_type != DestinationType::Plain
        {
            return Err(FerretError::InvalidDestination(
                "OUT non-PLAIN destination requires identity".into(),
            ));
        }

        // PLAIN with identity: error
        if identity.is_some() && dest_type == DestinationType::Plain {
            return Err(FerretError::InvalidDestination(
                "PLAIN destination cannot hold identity".into(),
            ));
        }

        // Build the full name (with identity hexhash appended if present)
        let name = Self::build_name(identity.as_ref(), app_name, &owned_aspects)?;

        // Compute name_hash (without identity hexhash)
        let name_without_hexhash = Self::build_name_without_hexhash(app_name, aspects);
        let name_hash_full = sha256(name_without_hexhash.as_bytes());
        let mut name_hash = [0u8; 10];
        name_hash.copy_from_slice(&name_hash_full[..NAME_HASH_LENGTH / 8]);

        // Compute destination hash
        let hash = Self::compute_hash(identity.as_ref(), &name_hash)?;
        let hexhash: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

        Ok(Self {
            identity,
            direction,
            dest_type,
            hash,
            name_hash,
            name,
            hexhash,
            proof_strategy: ProofStrategy::ProveNone,
            accept_link_requests: true,
            group_key: None,
            group_token: None,
            ratchets: None,
            ratchets_path: None,
            ratchet_interval: super::RATCHET_INTERVAL,
            retained_ratchets: super::RATCHET_COUNT,
            latest_ratchet_time: None,
            latest_ratchet_id: None,
            enforce_ratchets_flag: false,
            default_app_data: None,
            mtu: 0,
        })
    }

    /// Build the name string without the identity hexhash.
    fn build_name_without_hexhash(app_name: &str, aspects: &[&str]) -> String {
        let mut name = app_name.to_string();
        for a in aspects {
            name.push('.');
            name.push_str(a);
        }
        name
    }

    /// Build the full name string including identity hexhash (if present).
    fn build_name(
        identity: Option<&Identity>,
        app_name: &str,
        aspects: &[String],
    ) -> Result<String> {
        let mut name = app_name.to_string();
        for a in aspects {
            name.push('.');
            name.push_str(a);
        }
        if let Some(id) = identity {
            name.push('.');
            name.push_str(id.hexhash()?);
        }
        Ok(name)
    }

    /// Compute the destination hash from identity and name_hash.
    fn compute_hash(
        identity: Option<&Identity>,
        name_hash: &[u8; 10],
    ) -> Result<[u8; 16]> {
        let mut material = Vec::new();
        material.extend_from_slice(name_hash);
        if let Some(id) = identity {
            material.extend_from_slice(id.hash()?);
        }
        let full = sha256(&material);
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&full[..TRUNCATED_HASHLENGTH / 8]);
        Ok(hash)
    }

    /// Expand a destination name from components without constructing a full Destination.
    pub fn expand_name(
        identity: Option<&Identity>,
        app_name: &str,
        aspects: &[&str],
    ) -> Result<String> {
        let mut name = app_name.to_string();
        for a in aspects {
            name.push('.');
            name.push_str(a);
        }
        if let Some(id) = identity {
            name.push('.');
            name.push_str(id.hexhash()?);
        }
        Ok(name)
    }

    /// Compute a destination hash without constructing a full Destination.
    pub fn hash_for(
        identity: Option<&Identity>,
        app_name: &str,
        aspects: &[&str],
    ) -> Result<[u8; 16]> {
        let name_without_hexhash = Self::build_name_without_hexhash(app_name, aspects);
        let name_hash_full = sha256(name_without_hexhash.as_bytes());
        let mut name_hash = [0u8; 10];
        name_hash.copy_from_slice(&name_hash_full[..NAME_HASH_LENGTH / 8]);
        Self::compute_hash(identity, &name_hash)
    }

    /// Encrypt data according to destination type.
    /// Use `encrypt_data` to pass an optional ratchet store.
    pub fn encrypt_data(
        &self,
        plaintext: &[u8],
        ratchet_store: Option<&RatchetStore>,
    ) -> Result<Vec<u8>> {
        match self.dest_type {
            DestinationType::Plain => Ok(plaintext.to_vec()),
            DestinationType::Single => {
                let identity = self
                    .identity
                    .as_ref()
                    .ok_or(FerretError::MissingPublicKey)?;
                let ratchet = ratchet_store
                    .and_then(|rs| rs.get_ratchet(&self.hash))
                    .and_then(|r| <[u8; 32]>::try_from(r.as_slice()).ok());
                identity.encrypt(plaintext, ratchet.as_ref())
            }
            DestinationType::Group => {
                let token = self.group_token.as_ref().ok_or(
                    FerretError::InvalidDestination("no group key loaded".into()),
                )?;
                Ok(token.encrypt(plaintext))
            }
            DestinationType::Link => {
                // Link encryption handled by Link module in Layer 4
                Ok(plaintext.to_vec())
            }
        }
    }

    /// Decrypt data according to destination type.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.dest_type {
            DestinationType::Plain => Ok(Some(ciphertext.to_vec())),
            DestinationType::Single => {
                let identity = self
                    .identity
                    .as_ref()
                    .ok_or(FerretError::MissingPrivateKey)?;
                let ratchets = self.ratchets.as_deref();
                identity.decrypt(ciphertext, ratchets, self.enforce_ratchets_flag)
            }
            DestinationType::Group => {
                let token = self.group_token.as_ref().ok_or(
                    FerretError::InvalidDestination("no group key loaded".into()),
                )?;
                Ok(Some(token.decrypt(ciphertext)?))
            }
            DestinationType::Link => Ok(Some(ciphertext.to_vec())),
        }
    }

    /// Generate and store a symmetric key for GROUP destinations.
    pub fn create_keys(&mut self) -> Result<()> {
        match self.dest_type {
            DestinationType::Plain => Err(FerretError::InvalidDestination(
                "PLAIN cannot hold keys".into(),
            )),
            DestinationType::Single => Err(FerretError::InvalidDestination(
                "SINGLE holds keys via Identity".into(),
            )),
            DestinationType::Group => {
                let key =
                    Token::generate_key(crate::crypto::token::TokenMode::Aes256Cbc);
                self.group_token = Some(Token::new(&key)?);
                self.group_key = Some(key);
                Ok(())
            }
            DestinationType::Link => Err(FerretError::InvalidDestination(
                "LINK cannot create keys".into(),
            )),
        }
    }

    /// Get the raw symmetric key bytes (GROUP only).
    pub fn get_private_key(&self) -> Result<&[u8]> {
        match self.dest_type {
            DestinationType::Group => self
                .group_key
                .as_deref()
                .ok_or(FerretError::InvalidDestination("no group key".into())),
            _ => Err(FerretError::InvalidDestination(
                "only GROUP has private key".into(),
            )),
        }
    }

    /// Load a symmetric key from bytes (GROUP only).
    pub fn load_private_key(&mut self, key: &[u8]) -> Result<()> {
        match self.dest_type {
            DestinationType::Group => {
                self.group_token = Some(Token::new(key)?);
                self.group_key = Some(key.to_vec());
                Ok(())
            }
            _ => Err(FerretError::InvalidDestination(
                "only GROUP can load key".into(),
            )),
        }
    }
}

impl Encryptable for Destination {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_data(plaintext, None)
    }

    fn dest_hash(&self) -> &[u8; 16] {
        &self.hash
    }

    fn dest_type(&self) -> DestinationType {
        self.dest_type
    }
}
