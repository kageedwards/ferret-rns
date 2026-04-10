// Link struct: construction, encryption, accessors, callbacks

use std::sync::{Arc, RwLock};

use crate::crypto::ed25519::{Ed25519SigningKey, Ed25519VerifyingKey};
use crate::crypto::token::Token;
use crate::crypto::x25519::{X25519PrivateKey, X25519PublicKey};
use crate::crypto::{AES128_BLOCKSIZE, TOKEN_OVERHEAD};
use crate::destination::destination::Destination;
use crate::identity::Identity;
use crate::link::{
    LinkMode, LinkStatus, TeardownReason, ECPUBSIZE, ESTABLISHMENT_TIMEOUT_PER_HOP,
    KEEPALIVE_MAX, LINK_MTU_SIZE, MODE_DEFAULT, STALE_FACTOR,
};
use crate::packet::packet::Packet;
use crate::packet::Encryptable;
use crate::transport::transport::{PendingLink, TransportState};
use crate::types::constants::{HEADER_MINSIZE, IFAC_MIN_SIZE, MTU};
use crate::types::destination::DestinationType;
use crate::types::packet::{ContextFlag, HeaderType, PacketContext, PacketType};
use crate::types::transport::TransportType;
use crate::{FerretError, Result};

// ── LinkCallbacks ──

pub(crate) struct LinkCallbacks {
    pub(crate) link_established: Option<Box<dyn Fn(&Link) + Send + Sync>>,
    pub(crate) link_closed: Option<Box<dyn Fn(&Link) + Send + Sync>>,
    pub(crate) packet: Option<Box<dyn Fn(&[u8], &Packet) + Send + Sync>>,
    pub(crate) remote_identified: Option<Box<dyn Fn(&Link, &Identity) + Send + Sync>>,
}

impl LinkCallbacks {
    fn new() -> Self {
        Self {
            link_established: None,
            link_closed: None,
            packet: None,
            remote_identified: None,
        }
    }
}

// ── LinkInner ──

pub(crate) struct LinkInner {
    // Identity
    pub(crate) link_id: [u8; 16],
    pub(crate) initiator: bool,

    // Ephemeral keys
    pub(crate) prv: Option<X25519PrivateKey>,
    pub(crate) pub_key: Option<X25519PublicKey>,
    pub(crate) pub_bytes: Option<[u8; 32]>,
    pub(crate) sig_prv: Option<Ed25519SigningKey>,
    pub(crate) sig_pub: Option<Ed25519VerifyingKey>,
    pub(crate) sig_pub_bytes: Option<[u8; 32]>,

    // Peer keys
    pub(crate) peer_pub: Option<X25519PublicKey>,
    pub(crate) peer_pub_bytes: Option<[u8; 32]>,
    pub(crate) peer_sig_pub: Option<Ed25519VerifyingKey>,
    pub(crate) peer_sig_pub_bytes: Option<[u8; 32]>,

    // Derived secrets
    pub(crate) shared_key: Option<[u8; 32]>,
    pub(crate) derived_key: Option<Vec<u8>>,
    pub(crate) token: Option<Token>,

    // Status
    pub(crate) status: LinkStatus,
    pub(crate) teardown_reason: Option<TeardownReason>,
    pub(crate) mode: LinkMode,
    pub(crate) activated_at: Option<f64>,

    // MTU / MDU
    pub(crate) mtu: usize,
    pub(crate) mdu: usize,

    // RTT and timing
    pub(crate) rtt: Option<f64>,
    pub(crate) request_time: Option<f64>,
    pub(crate) establishment_timeout: f64,
    pub(crate) establishment_cost: usize,

    // Traffic tracking
    pub(crate) last_inbound: f64,
    pub(crate) last_outbound: f64,
    pub(crate) last_data: f64,
    pub(crate) last_proof: f64,
    pub(crate) last_keepalive: f64,
    pub(crate) tx: u64,
    pub(crate) rx: u64,
    pub(crate) txbytes: u64,
    pub(crate) rxbytes: u64,

    // Keepalive
    pub(crate) keepalive: f64,
    pub(crate) stale_time: f64,

    // References
    pub(crate) destination: Option<Arc<RwLock<Destination>>>,
    pub(crate) owner: Option<Arc<RwLock<Destination>>>,
    pub(crate) attached_interface: Option<usize>,
    pub(crate) remote_identity: Option<Identity>,

    // Channel (lazily created)
    pub(crate) channel: Option<crate::channel::Channel>,

    // Pending requests
    pub(crate) pending_requests: Vec<super::request::RequestReceipt>,

    // Resource tracking
    pub(crate) incoming_resources: Vec<[u8; 32]>,
    pub(crate) outgoing_resources: Vec<[u8; 32]>,
    pub(crate) last_resource_window: Option<usize>,
    pub(crate) last_resource_eifr: Option<f64>,

    // Callbacks
    pub(crate) callbacks: LinkCallbacks,
}

impl LinkInner {
    /// Lazily create or return the existing Token from derived_key.
    pub(crate) fn get_or_create_token(&mut self) -> Result<&Token> {
        if self.token.is_none() {
            let dk = self
                .derived_key
                .as_ref()
                .ok_or(FerretError::Token("no derived key available".into()))?;
            self.token = Some(Token::new(dk)?);
        }
        Ok(self.token.as_ref().expect("just set"))
    }
}

// ── Link (public handle) ──

/// Thread-safe Link handle. Cloneable, wraps `Arc<RwLock<LinkInner>>`.
#[derive(Clone)]
pub struct Link {
    pub(crate) inner: Arc<RwLock<LinkInner>>,
    /// Cached link_id outside the lock for `Encryptable::dest_hash()`.
    pub(crate) link_id_cache: [u8; 16],
}

impl Link {
    // -- lock helpers --

    pub(crate) fn read(&self) -> Result<std::sync::RwLockReadGuard<'_, LinkInner>> {
        self.inner
            .read()
            .map_err(|_| FerretError::Token("lock poisoned".into()))
    }

    pub(crate) fn write(&self) -> Result<std::sync::RwLockWriteGuard<'_, LinkInner>> {
        self.inner
            .write()
            .map_err(|_| FerretError::Token("lock poisoned".into()))
    }

    /// Construct a new Link as initiator to a remote Destination.
    pub fn new(
        destination: Arc<RwLock<Destination>>,
        transport: &TransportState,
        established_callback: Option<Box<dyn Fn(&Link) + Send + Sync>>,
        closed_callback: Option<Box<dyn Fn(&Link) + Send + Sync>>,
    ) -> Result<Self> {
        // Validate destination is SINGLE
        let (dest_hash, dest_type) = {
            let d = destination
                .read()
                .map_err(|_| FerretError::Token("lock poisoned".into()))?;
            (d.hash, d.dest_type)
        };
        if dest_type != DestinationType::Single {
            return Err(FerretError::InvalidDestination(
                "links can only be established to SINGLE destinations".into(),
            ));
        }

        // Generate ephemeral keys
        let prv = X25519PrivateKey::generate();
        let sig_prv = Ed25519SigningKey::generate();
        let pub_key = prv.public_key();
        let sig_pub = sig_prv.verifying_key();
        let pub_bytes = pub_key.to_bytes();
        let sig_pub_bytes = sig_pub.to_bytes();

        // Build signalling bytes (default MTU + default mode)
        let signalling = super::handshake::signalling_bytes(MTU as u32, MODE_DEFAULT)?;

        // Build LinkRequest data: x25519_pub(32) + ed25519_pub(32) + signalling(3)
        let mut request_data = Vec::with_capacity(ECPUBSIZE + LINK_MTU_SIZE);
        request_data.extend_from_slice(&pub_bytes);
        request_data.extend_from_slice(&sig_pub_bytes);
        request_data.extend_from_slice(&signalling);

        // Compute hops to destination for timeout
        let hops = transport.hops_to(&dest_hash).unwrap_or(1);

        // Build a temporary Encryptable for the LinkRequest packet
        let temp_dest = crate::packet::ProofDestination::new(dest_hash);
        let mut packet = Packet::new(
            &temp_dest,
            request_data.clone(),
            PacketType::LinkRequest,
            PacketContext::None,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        packet.pack(&temp_dest)?;

        // Compute link_id from hashable part (excluding signalling bytes)
        let link_id = link_id_from_packet(&packet, request_data.len());

        let establishment_timeout =
            ESTABLISHMENT_TIMEOUT_PER_HOP * (hops.max(1) as f64) + KEEPALIVE_MAX;

        let mut callbacks = LinkCallbacks::new();
        callbacks.link_established = established_callback;
        callbacks.link_closed = closed_callback;

        let mtu = MTU;
        let mdu = compute_mdu(mtu);

        let inner = LinkInner {
            link_id,
            initiator: true,
            prv: Some(prv),
            pub_key: Some(pub_key),
            pub_bytes: Some(pub_bytes),
            sig_prv: Some(sig_prv),
            sig_pub: Some(sig_pub),
            sig_pub_bytes: Some(sig_pub_bytes),
            peer_pub: None,
            peer_pub_bytes: None,
            peer_sig_pub: None,
            peer_sig_pub_bytes: None,
            shared_key: None,
            derived_key: None,
            token: None,
            status: LinkStatus::Pending,
            teardown_reason: None,
            mode: MODE_DEFAULT,
            activated_at: None,
            mtu,
            mdu,
            rtt: None,
            request_time: Some(now()),
            establishment_timeout,
            establishment_cost: packet.raw.len(),
            last_inbound: 0.0,
            last_outbound: 0.0,
            last_data: 0.0,
            last_proof: 0.0,
            last_keepalive: 0.0,
            tx: 0,
            rx: 0,
            txbytes: 0,
            rxbytes: 0,
            keepalive: KEEPALIVE_MAX,
            stale_time: KEEPALIVE_MAX * STALE_FACTOR as f64,
            destination: Some(destination),
            owner: None,
            attached_interface: None,
            remote_identity: None,
            channel: None,
            pending_requests: Vec::new(),
            incoming_resources: Vec::new(),
            outgoing_resources: Vec::new(),
            last_resource_window: None,
            last_resource_eifr: None,
            callbacks,
        };

        let link = Link {
            inner: Arc::new(RwLock::new(inner)),
            link_id_cache: link_id,
        };

        // Register as pending link in TransportState
        transport.register_link(PendingLink {
            link_id,
            destination_hash: dest_hash,
            timestamp: now(),
        })?;

        // Send the LinkRequest packet
        transport.outbound(&mut packet)?;

        Ok(link)
    }

    /// Construct a new Link as responder (called from validate_request).
    pub(crate) fn new_responder(
        owner: Arc<RwLock<Destination>>,
        peer_pub_bytes: &[u8; 32],
        peer_sig_pub_bytes: &[u8; 32],
    ) -> Result<Self> {
        // Use owner Destination's Identity signing key
        let (sig_prv_seed, sig_pub_bytes_arr) = {
            let o = owner
                .read()
                .map_err(|_| FerretError::Token("lock poisoned".into()))?;
            let id = o
                .identity
                .as_ref()
                .ok_or(FerretError::MissingPrivateKey)?;
            let prv_key = id.get_private_key()?;
            // Ed25519 seed is the last 32 bytes of the 64-byte private key
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&prv_key[32..]);
            let pub_key = id.get_public_key()?;
            let mut sig_pub = [0u8; 32];
            sig_pub.copy_from_slice(&pub_key[32..]);
            (seed, sig_pub)
        };

        let sig_prv = Ed25519SigningKey::from_seed(&sig_prv_seed);
        let sig_pub = sig_prv.verifying_key();

        // Generate ephemeral X25519 key pair
        let prv = X25519PrivateKey::generate();
        let pub_key = prv.public_key();
        let pub_bytes_arr = pub_key.to_bytes();

        // Load peer keys
        let peer_pub = X25519PublicKey::from_bytes(peer_pub_bytes);
        let peer_sig_pub = Ed25519VerifyingKey::from_bytes(peer_sig_pub_bytes)?;

        let mtu = MTU;
        let mdu = compute_mdu(mtu);

        let inner = LinkInner {
            link_id: [0u8; 16], // set later by set_link_id
            initiator: false,
            prv: Some(prv),
            pub_key: Some(pub_key),
            pub_bytes: Some(pub_bytes_arr),
            sig_prv: Some(sig_prv),
            sig_pub: Some(sig_pub),
            sig_pub_bytes: Some(sig_pub_bytes_arr),
            peer_pub: Some(peer_pub),
            peer_pub_bytes: Some(*peer_pub_bytes),
            peer_sig_pub: Some(peer_sig_pub),
            peer_sig_pub_bytes: Some(*peer_sig_pub_bytes),
            shared_key: None,
            derived_key: None,
            token: None,
            status: LinkStatus::Pending,
            teardown_reason: None,
            mode: MODE_DEFAULT,
            activated_at: None,
            mtu,
            mdu,
            rtt: None,
            request_time: None,
            establishment_timeout: ESTABLISHMENT_TIMEOUT_PER_HOP + KEEPALIVE_MAX,
            establishment_cost: 0,
            last_inbound: 0.0,
            last_outbound: 0.0,
            last_data: 0.0,
            last_proof: 0.0,
            last_keepalive: 0.0,
            tx: 0,
            rx: 0,
            txbytes: 0,
            rxbytes: 0,
            keepalive: KEEPALIVE_MAX,
            stale_time: KEEPALIVE_MAX * STALE_FACTOR as f64,
            destination: None,
            owner: Some(owner),
            attached_interface: None,
            remote_identity: None,
            channel: None,
            pending_requests: Vec::new(),
            incoming_resources: Vec::new(),
            outgoing_resources: Vec::new(),
            last_resource_window: None,
            last_resource_eifr: None,
            callbacks: LinkCallbacks::new(),
        };

        Ok(Link {
            inner: Arc::new(RwLock::new(inner)),
            link_id_cache: [0u8; 16], // updated by set_link_id
        })
    }

    // ── Encryption ──

    /// Encrypt plaintext using the link's Token (lazily instantiated).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut inner = self.write()?;
        let token = inner.get_or_create_token()?;
        Ok(token.encrypt(plaintext))
    }

    /// Decrypt ciphertext using the link's Token. Returns Ok(None) on failure.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut inner = self.write()?;
        let token = inner.get_or_create_token()?;
        match token.decrypt(ciphertext) {
            Ok(pt) => Ok(Some(pt)),
            Err(_) => Ok(None),
        }
    }

    /// Sign a message with the link's Ed25519 signing key.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        let inner = self.read()?;
        let sig_prv = inner
            .sig_prv
            .as_ref()
            .ok_or(FerretError::MissingPrivateKey)?;
        Ok(sig_prv.sign(message))
    }

    // ── Accessors ──

    pub fn status(&self) -> Result<LinkStatus> {
        Ok(self.read()?.status)
    }

    pub fn link_id(&self) -> Result<[u8; 16]> {
        Ok(self.read()?.link_id)
    }

    pub fn rtt(&self) -> Result<Option<f64>> {
        Ok(self.read()?.rtt)
    }

    pub fn mdu(&self) -> Result<usize> {
        Ok(self.read()?.mdu)
    }

    pub fn mtu(&self) -> Result<usize> {
        Ok(self.read()?.mtu)
    }

    // ── Channel ──

    /// Lazily create a Channel backed by LinkChannelOutlet, return mutable ref.
    pub fn get_channel(&self) -> Result<()> {
        let mut inner = self.write()?;
        if inner.channel.is_none() {
            let outlet = crate::channel::outlet::LinkChannelOutlet::new(self.clone());
            inner.channel = Some(crate::channel::Channel::new(Box::new(outlet)));
        }
        Ok(())
    }

    /// Access the channel (must call get_channel first to ensure it exists).
    pub fn with_channel<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut crate::channel::Channel) -> R,
    {
        let mut inner = self.write()?;
        if inner.channel.is_none() {
            let outlet = crate::channel::outlet::LinkChannelOutlet::new(self.clone());
            inner.channel = Some(crate::channel::Channel::new(Box::new(outlet)));
        }
        let channel = inner.channel.as_mut().expect("just ensured");
        Ok(f(channel))
    }

    // ── Callback setters ──

    pub fn set_link_established_callback(
        &self,
        cb: Box<dyn Fn(&Link) + Send + Sync>,
    ) -> Result<()> {
        self.write()?.callbacks.link_established = Some(cb);
        Ok(())
    }

    pub fn set_link_closed_callback(
        &self,
        cb: Box<dyn Fn(&Link) + Send + Sync>,
    ) -> Result<()> {
        self.write()?.callbacks.link_closed = Some(cb);
        Ok(())
    }

    pub fn set_packet_callback(
        &self,
        cb: Box<dyn Fn(&[u8], &Packet) + Send + Sync>,
    ) -> Result<()> {
        self.write()?.callbacks.packet = Some(cb);
        Ok(())
    }

    pub fn set_remote_identified_callback(
        &self,
        cb: Box<dyn Fn(&Link, &Identity) + Send + Sync>,
    ) -> Result<()> {
        self.write()?.callbacks.remote_identified = Some(cb);
        Ok(())
    }

    /// Update the cached link_id (called after set_link_id on responder).
    pub(crate) fn update_link_id_cache(&mut self) -> Result<()> {
        let id = self.read()?.link_id;
        self.link_id_cache = id;
        Ok(())
    }

    // ── Teardown ──

    /// Initiate teardown: encrypt link_id, send as LinkClose, transition to Closed.
    pub fn teardown(&self, transport: &TransportState) -> Result<()> {
        let status = self.read()?.status;
        if status == LinkStatus::Pending || status == LinkStatus::Closed {
            return Ok(());
        }

        let link_id = self.read()?.link_id;
        let encrypted = self.encrypt(&link_id)?;

        let mut packet = Packet::new(
            self as &dyn Encryptable,
            encrypted,
            PacketType::Data,
            PacketContext::LinkClose,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        packet.pack(self as &dyn Encryptable)?;
        transport.outbound(&mut packet)?;

        let reason = if self.read()?.initiator {
            TeardownReason::InitiatorClosed
        } else {
            TeardownReason::DestinationClosed
        };

        self.link_closed(reason)?;
        Ok(())
    }

    /// Handle a received LinkClose packet: decrypt, verify data == link_id, close.
    pub(crate) fn teardown_packet(&self, packet: &Packet) -> Result<()> {
        let plaintext = self.decrypt(&packet.data)?;
        let plaintext = match plaintext {
            Some(pt) => pt,
            None => return Ok(()), // Decryption failed, ignore
        };

        let link_id = self.read()?.link_id;
        if plaintext.len() != 16 || plaintext[..] != link_id[..] {
            return Ok(()); // Data doesn't match link_id, ignore
        }

        let reason = if self.read()?.initiator {
            TeardownReason::DestinationClosed
        } else {
            TeardownReason::InitiatorClosed
        };

        self.link_closed(reason)?;
        Ok(())
    }

    /// Transition to Closed: zero out keys, set status, invoke callback.
    pub(crate) fn link_closed(&self, reason: TeardownReason) -> Result<()> {
        {
            let mut inner = self.write()?;
            inner.status = LinkStatus::Closed;
            inner.teardown_reason = Some(reason);

            // Zero out key material
            inner.prv = None;
            inner.pub_key = None;
            inner.pub_bytes = None;
            inner.sig_prv = None;
            inner.sig_pub = None;
            inner.sig_pub_bytes = None;
            inner.peer_pub = None;
            inner.peer_pub_bytes = None;
            inner.peer_sig_pub = None;
            inner.peer_sig_pub_bytes = None;
            inner.shared_key = None;
            inner.derived_key = None;
            inner.token = None;

            // Clear all active resources
            inner.incoming_resources.clear();
            inner.outgoing_resources.clear();

            // Shut down channel if exists
            if let Some(ref mut channel) = inner.channel {
                channel.shutdown();
            }
        }

        // Invoke link_closed callback
        let inner = self.read()?;
        if let Some(ref cb) = inner.callbacks.link_closed {
            cb(self);
        }

        Ok(())
    }
}

// ── Encryptable impl ──

impl Encryptable for Link {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        Link::encrypt(self, plaintext)
    }

    fn dest_hash(&self) -> &[u8; 16] {
        &self.link_id_cache
    }

    fn dest_type(&self) -> DestinationType {
        DestinationType::Link
    }
}

// ── Helper functions ──

/// Compute link_id from a packed LinkRequest packet.
/// Excludes signalling bytes from the hash input.
pub fn link_id_from_packet(packet: &Packet, data_len: usize) -> [u8; 16] {
    let mut hashable = packet.get_hashable_part();
    if data_len > ECPUBSIZE {
        let diff = data_len - ECPUBSIZE;
        let new_len = hashable.len().saturating_sub(diff);
        hashable.truncate(new_len);
    }
    Identity::truncated_hash(&hashable)
}

/// Compute MDU from MTU using the standard formula.
pub fn compute_mdu(mtu: usize) -> usize {
    let usable = mtu
        .saturating_sub(IFAC_MIN_SIZE)
        .saturating_sub(HEADER_MINSIZE)
        .saturating_sub(TOKEN_OVERHEAD);
    let blocks = usable / AES128_BLOCKSIZE;
    if blocks == 0 {
        return 0;
    }
    blocks * AES128_BLOCKSIZE - 1
}

/// Current time as f64 seconds since UNIX epoch.
pub(crate) fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

// ── Test helpers ──

impl Link {
    /// Create a minimal Link in Active state with key material for testing.
    /// Only available for tests.
    #[doc(hidden)]
    pub fn new_test_active(derived_key: &[u8]) -> Self {
        let prv = X25519PrivateKey::generate();
        let sig_prv = Ed25519SigningKey::generate();
        let pub_key = prv.public_key();
        let sig_pub = sig_prv.verifying_key();
        let pub_bytes = pub_key.to_bytes();
        let sig_pub_bytes = sig_pub.to_bytes();

        let mtu = MTU;
        let mdu = compute_mdu(mtu);

        let inner = LinkInner {
            link_id: [0xAA; 16],
            initiator: true,
            prv: Some(prv),
            pub_key: Some(pub_key),
            pub_bytes: Some(pub_bytes),
            sig_prv: Some(sig_prv),
            sig_pub: Some(sig_pub),
            sig_pub_bytes: Some(sig_pub_bytes),
            peer_pub: None,
            peer_pub_bytes: None,
            peer_sig_pub: None,
            peer_sig_pub_bytes: None,
            shared_key: Some([0xBB; 32]),
            derived_key: Some(derived_key.to_vec()),
            token: None,
            status: LinkStatus::Active,
            teardown_reason: None,
            mode: MODE_DEFAULT,
            activated_at: Some(now()),
            mtu,
            mdu,
            rtt: Some(0.5),
            request_time: None,
            establishment_timeout: KEEPALIVE_MAX,
            establishment_cost: 0,
            last_inbound: now(),
            last_outbound: now(),
            last_data: now(),
            last_proof: 0.0,
            last_keepalive: 0.0,
            tx: 0,
            rx: 0,
            txbytes: 0,
            rxbytes: 0,
            keepalive: KEEPALIVE_MAX,
            stale_time: KEEPALIVE_MAX * STALE_FACTOR as f64,
            destination: None,
            owner: None,
            attached_interface: None,
            remote_identity: None,
            channel: None,
            pending_requests: Vec::new(),
            incoming_resources: Vec::new(),
            outgoing_resources: Vec::new(),
            last_resource_window: None,
            last_resource_eifr: None,
            callbacks: LinkCallbacks::new(),
        };

        Link {
            inner: Arc::new(RwLock::new(inner)),
            link_id_cache: [0xAA; 16],
        }
    }

    /// Close the link with a given reason. Public test helper.
    #[doc(hidden)]
    pub fn test_close(&self, reason: TeardownReason) -> Result<()> {
        self.link_closed(reason)
    }

    /// Check whether key material is present. Public test helper.
    #[doc(hidden)]
    pub fn has_key_material(&self) -> Result<bool> {
        let inner = self.read()?;
        Ok(inner.prv.is_some()
            || inner.pub_key.is_some()
            || inner.shared_key.is_some()
            || inner.derived_key.is_some()
            || inner.token.is_some()
            || inner.sig_prv.is_some()
            || inner.sig_pub.is_some())
    }
}
