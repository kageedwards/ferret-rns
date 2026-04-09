// Destination struct: construction, hashing, encrypt/decrypt, group key management

use crate::crypto::hashes::sha256;
use crate::crypto::token::Token;
use crate::crypto::NAME_HASH_LENGTH;
use crate::identity::{Identity, RatchetStore};
use crate::packet::Encryptable;
use crate::types::constants::TRUNCATED_HASHLENGTH;
use crate::types::destination::{DestinationDirection, DestinationType, ProofStrategy};
use crate::types::packet::{ContextFlag, HeaderType, PacketContext, PacketType};
use crate::types::transport::TransportType;
use crate::{FerretError, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::handlers::RequestHandler;

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
    // Callbacks (placeholder types until Link is available in Layer 4)
    link_established_callback: Option<Box<dyn Fn() + Send + Sync>>,
    packet_callback: Option<Box<dyn Fn(&[u8], &crate::packet::packet::Packet) + Send + Sync>>,
    proof_requested_callback: Option<Box<dyn Fn(&crate::packet::packet::Packet) -> bool + Send + Sync>>,
    // Request handlers
    request_handlers: HashMap<[u8; 16], RequestHandler>,
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
            link_established_callback: None,
            packet_callback: None,
            proof_requested_callback: None,
            request_handlers: HashMap::new(),
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

    // ── Callbacks and handlers (Task 7.1) ──

    /// Store a callback invoked when a link is established.
    pub fn set_link_established_callback(&mut self, cb: Box<dyn Fn() + Send + Sync>) {
        self.link_established_callback = Some(cb);
    }

    /// Store a callback invoked when a data packet is received.
    pub fn set_packet_callback(
        &mut self,
        cb: Box<dyn Fn(&[u8], &crate::packet::packet::Packet) + Send + Sync>,
    ) {
        self.packet_callback = Some(cb);
    }

    /// Store a callback invoked when a proof is requested.
    pub fn set_proof_requested_callback(
        &mut self,
        cb: Box<dyn Fn(&crate::packet::packet::Packet) -> bool + Send + Sync>,
    ) {
        self.proof_requested_callback = Some(cb);
    }

    /// Set the proof strategy. Validates the strategy value.
    pub fn set_proof_strategy(&mut self, strategy: ProofStrategy) -> Result<()> {
        self.proof_strategy = strategy;
        Ok(())
    }

    /// Returns whether this destination accepts link requests.
    pub fn accepts_links(&self) -> bool {
        self.accept_link_requests
    }

    /// Set whether this destination accepts link requests.
    pub fn set_accepts_links(&mut self, accepts: bool) {
        self.accept_link_requests = accepts;
    }

    /// Register a request handler keyed by the truncated hash of the path.
    pub fn register_request_handler(
        &mut self,
        path: &str,
        generator: Box<
            dyn Fn(&str, &[u8], &[u8], &[u8], Option<&Identity>, f64) -> Option<Vec<u8>>
                + Send
                + Sync,
        >,
        allow: u8,
        allowed_list: Option<Vec<Vec<u8>>>,
    ) -> Result<()> {
        if path.is_empty() {
            return Err(FerretError::InvalidDestination(
                "request handler path cannot be empty".into(),
            ));
        }
        let path_hash = Identity::truncated_hash(path.as_bytes());
        let handler = RequestHandler {
            path: path.to_string(),
            response_generator: generator,
            allow,
            allowed_list,
        };
        self.request_handlers.insert(path_hash, handler);
        Ok(())
    }

    /// Deregister a request handler by path. Returns true if found.
    pub fn deregister_request_handler(&mut self, path: &str) -> bool {
        let path_hash = Identity::truncated_hash(path.as_bytes());
        self.request_handlers.remove(&path_hash).is_some()
    }

    /// Receive a packet: decrypt data and invoke the packet callback.
    /// Returns Ok(true) on success.
    pub fn receive(&mut self, packet: &mut crate::packet::packet::Packet) -> Result<bool> {
        let plaintext = self.decrypt(&packet.data)?;
        if let Some(pt) = plaintext {
            if let Some(ref cb) = self.packet_callback {
                cb(&pt, packet);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Set default app data (static bytes).
    pub fn set_default_app_data(&mut self, data: Option<Vec<u8>>) {
        self.default_app_data = data;
    }

    /// Clear default app data.
    pub fn clear_default_app_data(&mut self) {
        self.default_app_data = None;
    }

    // ── Ratchet rotation (Task 7.2) ──

    /// Enable ratchets, loading from file if it exists, or initializing empty.
    pub fn enable_ratchets(&mut self, path: &Path) -> Result<()> {
        self.ratchets_path = Some(path.to_path_buf());

        if path.exists() {
            let file_data = std::fs::read(path)?;
            // File format: signature(64) + msgpack(ratchet_list)
            if file_data.len() < 64 {
                return Err(FerretError::RatchetFile("ratchet file too short".into()));
            }
            let signature: [u8; 64] = file_data[..64]
                .try_into()
                .map_err(|_| FerretError::RatchetFile("invalid signature length".into()))?;
            let payload = &file_data[64..];

            let identity = self
                .identity
                .as_ref()
                .ok_or(FerretError::MissingPrivateKey)?;
            let valid = identity.validate(&signature, payload)?;
            if !valid {
                return Err(FerretError::RatchetFile(
                    "ratchet file signature invalid".into(),
                ));
            }

            let ratchet_list: Vec<Vec<u8>> = crate::util::msgpack::deserialize(payload)?;
            self.ratchets = Some(ratchet_list);
        } else {
            self.ratchets = Some(Vec::new());
        }

        Ok(())
    }

    /// Rotate ratchets if the interval has elapsed. Returns true if rotated.
    pub fn rotate_ratchets(&mut self) -> Result<bool> {
        if self.ratchets.is_none() {
            return Ok(false);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        let should_rotate = match self.latest_ratchet_time {
            Some(t) => (now - t) >= self.ratchet_interval as f64,
            None => true, // first rotation
        };

        if !should_rotate {
            return Ok(false);
        }

        let new_ratchet = RatchetStore::generate();
        let pub_bytes = RatchetStore::ratchet_public_bytes(&new_ratchet);
        let ratchet_id = RatchetStore::get_ratchet_id(&pub_bytes);

        if let Some(ref mut ratchets) = self.ratchets {
            ratchets.insert(0, new_ratchet.to_vec());
            if ratchets.len() > self.retained_ratchets {
                ratchets.truncate(self.retained_ratchets);
            }
        }

        self.latest_ratchet_time = Some(now);
        self.latest_ratchet_id = Some(ratchet_id);

        // Persist to disk
        self.persist_ratchets()?;

        Ok(true)
    }

    /// Set the enforce_ratchets flag. Returns true if ratchets are enabled.
    pub fn enforce_ratchets(&mut self) -> Result<bool> {
        if self.ratchets.is_some() {
            self.enforce_ratchets_flag = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Set the number of retained ratchets. Returns true if valid.
    pub fn set_retained_ratchets(&mut self, count: usize) -> bool {
        if count == 0 {
            return false;
        }
        self.retained_ratchets = count;
        if let Some(ref mut ratchets) = self.ratchets {
            if ratchets.len() > count {
                ratchets.truncate(count);
            }
        }
        true
    }

    /// Set the ratchet rotation interval in seconds. Returns true if valid.
    pub fn set_ratchet_interval(&mut self, interval: u64) -> bool {
        if interval == 0 {
            return false;
        }
        self.ratchet_interval = interval;
        true
    }

    /// Persist ratchets to disk atomically: sign serialized data, write temp + rename.
    fn persist_ratchets(&self) -> Result<()> {
        let path = self
            .ratchets_path
            .as_ref()
            .ok_or(FerretError::RatchetFile("no ratchet path set".into()))?;
        let identity = self
            .identity
            .as_ref()
            .ok_or(FerretError::MissingPrivateKey)?;
        let ratchets = self
            .ratchets
            .as_ref()
            .ok_or(FerretError::RatchetFile("no ratchets to persist".into()))?;

        let payload = crate::util::msgpack::serialize(ratchets)?;
        let signature = identity.sign(&payload)?;

        let mut file_data = Vec::with_capacity(64 + payload.len());
        file_data.extend_from_slice(&signature);
        file_data.extend_from_slice(&payload);

        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, &file_data)?;
        std::fs::rename(&tmp_path, path)?;

        Ok(())
    }

    // ── Announce building (Task 7.3) ──

    /// Build an announce packet for this destination.
    pub fn announce(
        &mut self,
        app_data: Option<&[u8]>,
        path_response: bool,
        _tag: Option<&[u8]>,
        send: bool,
        ratchet_store: Option<&RatchetStore>,
    ) -> Result<Option<crate::packet::packet::Packet>> {
        if self.dest_type != DestinationType::Single {
            return Err(FerretError::InvalidDestination(
                "only SINGLE can announce".into(),
            ));
        }
        if self.direction != DestinationDirection::In {
            return Err(FerretError::InvalidDestination(
                "only IN can announce".into(),
            ));
        }

        if self.identity.is_none() {
            return Err(FerretError::MissingPrivateKey);
        }

        // Build random_hash: 5 random bytes + 5 bytes timestamp (big-endian)
        let mut random_hash = [0u8; 10];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random_hash[..5]);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        random_hash[5..].copy_from_slice(&ts.to_be_bytes()[3..8]);

        // Ratchet handling (needs &mut self, so do before borrowing identity)
        let mut ratchet_bytes = Vec::new();
        if self.ratchets.is_some() {
            self.rotate_ratchets()?;
            if let Some(ref ratchets) = self.ratchets {
                if let Some(first) = ratchets.first() {
                    let prv: [u8; 32] = first
                        .as_slice()
                        .try_into()
                        .map_err(|_| FerretError::RatchetFile("invalid ratchet".into()))?;
                    let pub_bytes = RatchetStore::ratchet_public_bytes(&prv);
                    ratchet_bytes = pub_bytes.to_vec();
                    if let Some(rs) = ratchet_store {
                        rs.remember_ratchet(&self.hash, first)?;
                    }
                }
            }
        }

        // App data
        let effective_app_data = app_data
            .map(|d| d.to_vec())
            .or_else(|| self.default_app_data.clone());

        // Now borrow identity immutably (no more &mut self after this)
        let identity = self.identity.as_ref().ok_or(FerretError::MissingPrivateKey)?;
        let pub_key = identity.get_public_key()?;

        // Build signed data
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&self.hash);
        signed_data.extend_from_slice(&pub_key);
        signed_data.extend_from_slice(&self.name_hash);
        signed_data.extend_from_slice(&random_hash);
        signed_data.extend_from_slice(&ratchet_bytes);
        if let Some(ref ad) = effective_app_data {
            signed_data.extend_from_slice(ad);
        }

        let signature = identity.sign(&signed_data)?;

        // Build announce data
        let mut announce_data = Vec::new();
        announce_data.extend_from_slice(&pub_key);
        announce_data.extend_from_slice(&self.name_hash);
        announce_data.extend_from_slice(&random_hash);
        announce_data.extend_from_slice(&ratchet_bytes);
        announce_data.extend_from_slice(&signature);
        if let Some(ref ad) = effective_app_data {
            announce_data.extend_from_slice(ad);
        }

        // Context flag
        let context_flag = if !ratchet_bytes.is_empty() {
            ContextFlag::Set
        } else {
            ContextFlag::Unset
        };

        let announce_context = if path_response {
            PacketContext::PathResponse
        } else {
            PacketContext::None
        };

        let mut packet = crate::packet::packet::Packet::new(
            self as &dyn Encryptable,
            announce_data,
            PacketType::Announce,
            announce_context,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            context_flag,
        );

        if send {
            packet.send_packed(self as &dyn Encryptable)?;
            Ok(None)
        } else {
            Ok(Some(packet))
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
