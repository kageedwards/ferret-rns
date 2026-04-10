// Base Interface struct — common state shared by all concrete interfaces.
//
// Ported from the Python reference: lxcf/_ref_rns/Interfaces/Interface.py

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Mutex;

use crate::crypto::sha256;
use crate::interfaces::ifac_processor::IfacState;
use crate::transport::InterfaceHandle;
use crate::types::InterfaceMode;
use crate::Result;

// ---------------------------------------------------------------------------
// Constants (matching Python reference)
// ---------------------------------------------------------------------------

/// Incoming announce frequency sample window size.
pub const IA_FREQ_SAMPLES: usize = 6;
/// Outgoing announce frequency sample window size.
pub const OA_FREQ_SAMPLES: usize = 6;
/// Maximum held announces during ingress limiting.
pub const MAX_HELD_ANNOUNCES: usize = 256;
/// How long a spawned interface is considered "new" (2 hours).
pub const IC_NEW_TIME: f64 = 7200.0;
/// Burst frequency threshold for new interfaces.
pub const IC_BURST_FREQ_NEW: f64 = 3.5;
/// Burst frequency threshold for established interfaces.
pub const IC_BURST_FREQ: f64 = 12.0;
/// Duration to hold burst mode active (1 minute).
pub const IC_BURST_HOLD: f64 = 60.0;
/// Penalty delay after burst mode deactivates (5 minutes).
pub const IC_BURST_PENALTY: f64 = 300.0;
/// Interval between releasing held announces.
pub const IC_HELD_RELEASE_INTERVAL: f64 = 30.0;
/// Queued announce lifetime (24 hours).
pub const QUEUED_ANNOUNCE_LIFE: f64 = 86400.0;

// ---------------------------------------------------------------------------
// Supporting structs
// ---------------------------------------------------------------------------

/// An entry in the announce queue.
pub struct AnnounceQueueEntry {
    pub raw: Vec<u8>,
    pub hops: u8,
    pub time: f64,
}

/// Ingress control state for burst detection and held announces.
pub struct IngressControl {
    pub is_new: bool,
    pub created: f64,
    pub in_burst: bool,
    pub burst_started: f64,
    pub held_announces: Vec<(Vec<u8>, f64)>,
    pub last_held_release: f64,
}

impl IngressControl {
    fn new(created: f64) -> Self {
        Self {
            is_new: true,
            created,
            in_burst: false,
            burst_started: 0.0,
            held_announces: Vec::new(),
            last_held_release: 0.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Interface struct
// ---------------------------------------------------------------------------

/// Common interface state shared by all concrete interfaces.
pub struct Interface {
    // Identity
    pub name: String,
    pub mode: InterfaceMode,
    pub online: AtomicBool,
    pub detached: AtomicBool,

    // Direction flags
    pub dir_in: bool,
    pub dir_out: bool,

    // Transport
    pub bitrate: u64,
    pub hw_mtu: Option<usize>,
    pub autoconfigure_mtu: bool,

    // Statistics
    pub rxb: AtomicU64,
    pub txb: AtomicU64,
    pub created: f64,

    // IFAC
    pub ifac_state: Option<IfacState>,

    // Announce rate management
    pub announce_cap: f64,
    pub announce_queue: Mutex<Vec<AnnounceQueueEntry>>,

    // Announce frequency tracking (sliding window)
    pub ia_freq_deque: Mutex<VecDeque<f64>>,
    pub oa_freq_deque: Mutex<VecDeque<f64>>,

    // Ingress control
    pub ingress_control: Mutex<IngressControl>,

    // Parent interface (index/handle)
    pub parent_interface: Option<usize>,

    // Transmit callback — set by concrete interface
    transmit_fn: Option<Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync>>,

    // Cached interface hash
    interface_hash: Option<Vec<u8>>,

    // Announce timing
    announce_allowed_at: Mutex<f64>,
}

// ---------------------------------------------------------------------------
// Constructor and core methods
// ---------------------------------------------------------------------------

impl Interface {
    /// Create a new Interface with the given name and optional transmit callback.
    pub fn new(
        name: String,
        transmit_fn: Option<Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync>>,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        Self {
            name,
            mode: InterfaceMode::Full,
            online: AtomicBool::new(false),
            detached: AtomicBool::new(false),
            dir_in: false,
            dir_out: false,
            bitrate: 62500,
            hw_mtu: None,
            autoconfigure_mtu: false,
            rxb: AtomicU64::new(0),
            txb: AtomicU64::new(0),
            created: now,
            ifac_state: None,
            announce_cap: 0.0,
            announce_queue: Mutex::new(Vec::new()),
            ia_freq_deque: Mutex::new(VecDeque::with_capacity(IA_FREQ_SAMPLES)),
            oa_freq_deque: Mutex::new(VecDeque::with_capacity(OA_FREQ_SAMPLES)),
            ingress_control: Mutex::new(IngressControl::new(now)),
            parent_interface: None,
            transmit_fn,
            interface_hash: None,
            announce_allowed_at: Mutex::new(0.0),
        }
    }

    /// Compute interface hash = SHA-256 of the display string's UTF-8 bytes.
    pub fn compute_hash(display_string: &str) -> Vec<u8> {
        sha256(display_string.as_bytes()).to_vec()
    }

    /// Auto-configure HW_MTU based on bitrate tiers (matching Python reference).
    pub fn optimise_mtu(&mut self) {
        if self.autoconfigure_mtu {
            if self.bitrate >= 1_000_000_000 {
                self.hw_mtu = Some(524288);
            } else if self.bitrate > 750_000_000 {
                self.hw_mtu = Some(262144);
            } else if self.bitrate > 400_000_000 {
                self.hw_mtu = Some(131072);
            } else if self.bitrate > 200_000_000 {
                self.hw_mtu = Some(65536);
            } else if self.bitrate > 100_000_000 {
                self.hw_mtu = Some(32768);
            } else if self.bitrate > 10_000_000 {
                self.hw_mtu = Some(16384);
            } else if self.bitrate > 5_000_000 {
                self.hw_mtu = Some(8192);
            } else if self.bitrate > 2_000_000 {
                self.hw_mtu = Some(4096);
            } else if self.bitrate > 1_000_000 {
                self.hw_mtu = Some(2048);
            } else if self.bitrate > 62_500 {
                self.hw_mtu = Some(1024);
            } else {
                self.hw_mtu = None;
            }
        }
    }

    /// Age of this interface in seconds since creation.
    pub fn age(&self) -> f64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        now - self.created
    }
}

// ---------------------------------------------------------------------------
// InterfaceHandle trait implementation
// ---------------------------------------------------------------------------

impl InterfaceHandle for Interface {
    fn transmit(&self, raw: &[u8]) -> Result<()> {
        if let Some(ref f) = self.transmit_fn {
            f(raw)
        } else {
            Err(crate::FerretError::InterfaceError(
                "no transmit function configured".into(),
            ))
        }
    }

    fn is_outbound(&self) -> bool {
        self.dir_out
    }

    fn bitrate(&self) -> Option<u64> {
        Some(self.bitrate)
    }

    fn announce_cap(&self) -> f64 {
        self.announce_cap
    }

    fn announce_allowed_at(&self) -> f64 {
        *self.announce_allowed_at.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set_announce_allowed_at(&self, t: f64) {
        let mut guard = self.announce_allowed_at.lock().unwrap_or_else(|e| e.into_inner());
        *guard = t;
    }

    fn mode(&self) -> InterfaceMode {
        self.mode
    }

    fn interface_hash(&self) -> &[u8] {
        match &self.interface_hash {
            Some(h) => h,
            None => &[],
        }
    }
}
