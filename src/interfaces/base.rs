// Base Interface struct — common state shared by all concrete interfaces.
//
// Ported from the Python reference: lxcf/_ref_rns/Interfaces/Interface.py

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use crate::crypto::sha256;
use crate::interfaces::ifac_processor::{ifac_check, ifac_mask, ifac_unmask, IfacState};
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
        let t = now();

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
            created: t,
            ifac_state: None,
            announce_cap: 0.0,
            announce_queue: Mutex::new(Vec::new()),
            ia_freq_deque: Mutex::new(VecDeque::with_capacity(IA_FREQ_SAMPLES)),
            oa_freq_deque: Mutex::new(VecDeque::with_capacity(OA_FREQ_SAMPLES)),
            ingress_control: Mutex::new(IngressControl::new(t)),
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
        now() - self.created
    }

    // -----------------------------------------------------------------------
    // Announce rate management (task 8.2)
    // -----------------------------------------------------------------------

    /// Record an incoming announce timestamp in the sliding window.
    pub fn received_announce(&self) {
        let mut deque = self.ia_freq_deque.lock().unwrap_or_else(|e| e.into_inner());
        deque.push_back(now());
        while deque.len() > IA_FREQ_SAMPLES {
            deque.pop_front();
        }
    }

    /// Record an outgoing announce timestamp in the sliding window.
    pub fn sent_announce(&self) {
        let mut deque = self.oa_freq_deque.lock().unwrap_or_else(|e| e.into_inner());
        deque.push_back(now());
        while deque.len() > OA_FREQ_SAMPLES {
            deque.pop_front();
        }
    }

    /// Compute incoming announce frequency from the sliding window.
    ///
    /// Matches the Python reference: sum of inter-sample deltas plus the
    /// delta from the newest sample to now, divided into the sample count.
    pub fn incoming_announce_frequency(&self) -> f64 {
        let deque = self.ia_freq_deque.lock().unwrap_or_else(|e| e.into_inner());
        announce_frequency_from_deque(&deque)
    }

    /// Compute outgoing announce frequency from the sliding window.
    pub fn outgoing_announce_frequency(&self) -> f64 {
        let deque = self.oa_freq_deque.lock().unwrap_or_else(|e| e.into_inner());
        announce_frequency_from_deque(&deque)
    }

    /// Check whether ingress limiting should be active.
    ///
    /// Mirrors the Python `should_ingress_limit` logic:
    /// - If already in burst and frequency has dropped below threshold for
    ///   longer than IC_BURST_HOLD, deactivate burst and schedule penalty.
    /// - If not in burst and frequency exceeds threshold, activate burst.
    pub fn should_ingress_limit(&self) -> bool {
        let mut ic = self.ingress_control.lock().unwrap_or_else(|e| e.into_inner());
        let freq_threshold = if self.age() < IC_NEW_TIME {
            IC_BURST_FREQ_NEW
        } else {
            IC_BURST_FREQ
        };
        let ia_freq = {
            let deque = self.ia_freq_deque.lock().unwrap_or_else(|e| e.into_inner());
            announce_frequency_from_deque(&deque)
        };

        if ic.in_burst {
            if ia_freq < freq_threshold && now() > ic.burst_started + IC_BURST_HOLD {
                ic.in_burst = false;
                ic.last_held_release = now() + IC_BURST_PENALTY;
            }
            true
        } else if ia_freq > freq_threshold {
            ic.in_burst = true;
            ic.burst_started = now();
            true
        } else {
            false
        }
    }

    /// Hold an announce packet for later release during burst mode.
    pub fn hold_announce(&self, raw: Vec<u8>) {
        let mut ic = self.ingress_control.lock().unwrap_or_else(|e| e.into_inner());
        if ic.held_announces.len() < MAX_HELD_ANNOUNCES {
            ic.held_announces.push((raw, now()));
            ic.in_burst = true;
            if ic.burst_started == 0.0 {
                ic.burst_started = now();
            }
        }
    }

    /// Process held announces: release one if burst has subsided and the
    /// penalty period has elapsed.
    ///
    /// Returns the raw packets that should be re-injected into transport.
    pub fn process_held_announces(&self) -> Vec<Vec<u8>> {
        let mut released = Vec::new();

        // Check if we should still be limiting
        if self.should_ingress_limit() {
            return released;
        }

        let mut ic = self.ingress_control.lock().unwrap_or_else(|e| e.into_inner());
        if ic.held_announces.is_empty() {
            return released;
        }

        let current = now();
        if current <= ic.last_held_release {
            return released;
        }

        let freq_threshold = if self.age() < IC_NEW_TIME {
            IC_BURST_FREQ_NEW
        } else {
            IC_BURST_FREQ
        };
        let ia_freq = {
            let deque = self.ia_freq_deque.lock().unwrap_or_else(|e| e.into_inner());
            announce_frequency_from_deque(&deque)
        };

        if ia_freq < freq_threshold {
            // Select the held announce with minimum hops (we don't have hop
            // info in held announces, so release oldest first — matching the
            // Python reference which iterates the dict in insertion order and
            // picks min hops; since we store raw bytes without parsed hops,
            // we release the first entry).
            if !ic.held_announces.is_empty() {
                let (raw, _time) = ic.held_announces.remove(0);
                ic.last_held_release = current + IC_HELD_RELEASE_INTERVAL;
                released.push(raw);
            }
        }

        released
    }

    /// Process the announce queue: transmit the lowest-hop announce, compute
    /// wait time, remove stale entries.
    ///
    /// Returns `Some(wait_time)` if an announce was transmitted, `None` if
    /// the queue is empty.
    pub fn process_announce_queue(&self) -> Option<f64> {
        let mut queue = self.announce_queue.lock().unwrap_or_else(|e| e.into_inner());

        // Remove stale announces (older than QUEUED_ANNOUNCE_LIFE)
        let current = now();
        queue.retain(|entry| current - entry.time <= QUEUED_ANNOUNCE_LIFE);

        if queue.is_empty() {
            return None;
        }

        // Find entry with minimum hops (oldest first among ties)
        let mut best_idx = 0;
        let mut best_hops = queue[0].hops;
        let mut best_time = queue[0].time;
        for (i, entry) in queue.iter().enumerate().skip(1) {
            if entry.hops < best_hops || (entry.hops == best_hops && entry.time < best_time) {
                best_idx = i;
                best_hops = entry.hops;
                best_time = entry.time;
            }
        }

        let selected = queue.remove(best_idx);

        // Compute wait time: (packet_size_bits / bitrate) / announce_cap
        let packet_size_bits = (selected.raw.len() as f64) * 8.0;
        let bitrate = self.bitrate as f64;
        let cap = if self.announce_cap > 0.0 {
            self.announce_cap
        } else {
            1.0 // avoid division by zero
        };
        let tx_time = packet_size_bits / bitrate;
        let wait_time = tx_time / cap;

        // Update announce_allowed_at
        {
            let mut allowed = self.announce_allowed_at.lock().unwrap_or_else(|e| e.into_inner());
            *allowed = current + wait_time;
        }

        // Transmit via transmit_fn
        if let Some(ref f) = self.transmit_fn {
            let _ = f(&selected.raw);
        }

        // Record outgoing announce
        {
            let mut deque = self.oa_freq_deque.lock().unwrap_or_else(|e| e.into_inner());
            deque.push_back(current);
            while deque.len() > OA_FREQ_SAMPLES {
                deque.pop_front();
            }
        }

        Some(wait_time)
    }

    // -----------------------------------------------------------------------
    // Packet processing (task 8.3)
    // -----------------------------------------------------------------------

    /// Process an inbound packet: IFAC check → unmask if needed → update rxb.
    ///
    /// Concrete interfaces call this from their read loops after decoding
    /// frames from the transport codec (HDLC/KISS/raw).
    pub fn process_incoming(&self, data: &[u8]) {
        // Step 1-2: Check IFAC flag/config consistency
        let (_flag_set, consistent) = ifac_check(data, self.ifac_state.is_some());
        if !consistent {
            // Flag doesn't match config — silently drop
            return;
        }

        // Step 3-4: Unmask if IFAC is configured, otherwise use data as-is
        let packet = if let Some(ref state) = self.ifac_state {
            match ifac_unmask(data, state) {
                Ok(Some(raw)) => raw,
                Ok(None) => return, // Bad IFAC tag — drop
                Err(_) => return,   // Internal error — drop
            }
        } else {
            data.to_vec()
        };

        // Step 5: Update rxb counter
        self.rxb.fetch_add(packet.len() as u64, Ordering::Relaxed);

        // Step 6: Deliver to transport for inbound processing.
        // TODO: Wire up transport delivery — concrete interfaces will call
        // TransportState::inbound(packet, interface_arc) once they have an
        // Arc<dyn InterfaceHandle> reference to pass along.
        let _ = &packet;
    }

    /// Process an outbound packet: IFAC mask if configured → transmit → update txb.
    pub fn process_outgoing(&self, data: &[u8]) -> Result<()> {
        // Step 1: IFAC mask if configured
        let to_send = if let Some(ref state) = self.ifac_state {
            ifac_mask(data, state)?
        } else {
            data.to_vec()
        };

        // Step 2: Transmit via transmit_fn callback
        if let Some(ref f) = self.transmit_fn {
            f(&to_send)?;
        } else {
            return Err(crate::FerretError::InterfaceError(
                "no transmit function configured".into(),
            ));
        }

        // Step 3: Update txb counter
        self.txb.fetch_add(data.len() as u64, Ordering::Relaxed);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Get current UNIX timestamp as f64 seconds.
fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Compute announce frequency from a deque of timestamps.
///
/// Matches the Python reference algorithm:
/// ```python
/// delta_sum = sum(deque[i] - deque[i-1] for i in range(1, len))
/// delta_sum += time.time() - deque[-1]
/// avg = 1 / (delta_sum / len) if delta_sum != 0 else 0
/// ```
fn announce_frequency_from_deque(deque: &VecDeque<f64>) -> f64 {
    if deque.len() < 2 {
        return 0.0;
    }
    let dq_len = deque.len();
    let mut delta_sum = 0.0;
    for i in 1..dq_len {
        delta_sum += deque[i] - deque[i - 1];
    }
    delta_sum += now() - deque[dq_len - 1];

    if delta_sum == 0.0 {
        0.0
    } else {
        1.0 / (delta_sum / dq_len as f64)
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
