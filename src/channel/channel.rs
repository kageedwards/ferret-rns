// Channel struct: send/receive, window adaptation, TX/RX ring management

use std::collections::{HashMap, VecDeque};

use crate::channel::envelope::Envelope;
use crate::channel::message::{ChannelError, MessageBase, MessageFactory};
use crate::channel::outlet::ChannelOutlet;
use crate::channel::{
    FAST_RATE_THRESHOLD, MAX_TRIES, RTT_FAST, RTT_MEDIUM, RTT_SLOW,
    WINDOW, WINDOW_FLEXIBILITY, WINDOW_MAX_FAST, WINDOW_MAX_MEDIUM,
    WINDOW_MAX_SLOW, WINDOW_MIN, WINDOW_MIN_LIMIT_FAST, WINDOW_MIN_LIMIT_MEDIUM,
};
use crate::transport::transport::TransportState;
use crate::{FerretError, Result};

/// Reliable, sequenced message delivery over a ChannelOutlet.
pub struct Channel {
    outlet: Box<dyn ChannelOutlet>,
    tx_ring: VecDeque<Envelope>,
    rx_ring: VecDeque<Envelope>,
    message_callbacks: Vec<Box<dyn Fn(&dyn MessageBase) -> bool + Send + Sync>>,
    next_sequence: u16,
    next_rx_sequence: u16,
    message_factories: HashMap<u16, MessageFactory>,
    max_tries: u8,

    // Window adaptation
    window: u16,
    window_max: u16,
    window_min: u16,
    window_flexibility: u16,
    fast_rate_rounds: u16,
    medium_rate_rounds: u16,
}

impl Channel {
    /// Create a new Channel with the given outlet and default window parameters.
    pub fn new(outlet: Box<dyn ChannelOutlet>) -> Self {
        Self {
            outlet,
            tx_ring: VecDeque::new(),
            rx_ring: VecDeque::new(),
            message_callbacks: Vec::new(),
            next_sequence: 0,
            next_rx_sequence: 0,
            message_factories: HashMap::new(),
            max_tries: MAX_TRIES,
            window: WINDOW,
            window_max: WINDOW_MAX_SLOW,
            window_min: WINDOW_MIN,
            window_flexibility: WINDOW_FLEXIBILITY,
            fast_rate_rounds: 0,
            medium_rate_rounds: 0,
        }
    }

    /// Register a user message type. MSGTYPE must be non-zero and < 0xF000.
    pub fn register_message_type(
        &mut self,
        msgtype: u16,
        factory: MessageFactory,
    ) -> Result<()> {
        if msgtype == 0 {
            return Err(FerretError::ChannelError(ChannelError::NoMsgType));
        }
        if msgtype >= 0xF000 {
            return Err(FerretError::ChannelError(ChannelError::InvalidMsgType));
        }
        self.message_factories.insert(msgtype, factory);
        Ok(())
    }

    /// Register a system message type (MSGTYPE >= 0xF000 allowed).
    pub(crate) fn register_system_message_type(
        &mut self,
        msgtype: u16,
        factory: MessageFactory,
    ) -> Result<()> {
        if msgtype == 0 {
            return Err(FerretError::ChannelError(ChannelError::NoMsgType));
        }
        self.message_factories.insert(msgtype, factory);
        Ok(())
    }

    /// Add a message handler callback. Returns the index.
    pub fn add_message_handler(
        &mut self,
        cb: Box<dyn Fn(&dyn MessageBase) -> bool + Send + Sync>,
    ) {
        self.message_callbacks.push(cb);
    }

    /// Remove a message handler by index.
    pub fn remove_message_handler(&mut self, index: usize) {
        if index < self.message_callbacks.len() {
            let _ = self.message_callbacks.remove(index);
        }
    }

    /// Channel MDU = outlet MDU minus 6-byte envelope header.
    pub fn mdu(&self) -> usize {
        let outlet_mdu = self.outlet.mdu();
        outlet_mdu.saturating_sub(6)
    }

    /// Whether the channel is ready to send (outstanding < window).
    pub fn is_ready_to_send(&self) -> bool {
        (self.tx_ring.len() as u16) < self.window
    }

    /// Send a message over the channel.
    pub fn send(
        &mut self,
        message: Box<dyn MessageBase>,
        transport: &TransportState,
    ) -> Result<()> {
        if !self.is_ready_to_send() {
            return Err(FerretError::ChannelError(ChannelError::LinkNotReady));
        }

        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);

        let mut envelope = Envelope::new(message, sequence);
        let raw = envelope.pack()?;

        if raw.len() > self.outlet.mdu() {
            return Err(FerretError::ChannelError(ChannelError::TooBig));
        }

        let packet = self.outlet.send(&raw, transport)?;
        envelope.packet = Some(packet);
        envelope.tries = 1;
        envelope.tracked = true;
        envelope.ts = now();

        self.tx_ring.push_back(envelope);
        Ok(())
    }

    /// Receive raw bytes from the outlet, unpack and deliver in order.
    pub fn receive(&mut self, raw: &[u8]) -> Result<()> {
        if raw.len() < 6 {
            return Err(FerretError::MalformedPacket(
                "channel data too short".into(),
            ));
        }

        let sequence = u16::from_be_bytes([raw[2], raw[3]]);

        // Discard if behind next_rx_sequence and outside valid window
        if self.sequence_is_old(sequence) {
            return Ok(());
        }

        // Discard duplicates already in RX ring
        if self.rx_ring.iter().any(|e| e.sequence == sequence) {
            return Ok(());
        }

        let mut envelope = Envelope::new_empty(sequence);
        envelope.unpack(raw, &self.message_factories)?;

        // Insert sorted by sequence (ascending)
        let pos = self
            .rx_ring
            .iter()
            .position(|e| self.sequence_after(e.sequence, sequence));
        match pos {
            Some(idx) => self.rx_ring.insert(idx, envelope),
            None => self.rx_ring.push_back(envelope),
        }

        // Deliver contiguous messages starting from next_rx_sequence
        self.deliver_pending();
        Ok(())
    }

    /// Check if a sequence number is old (behind next_rx_sequence and outside window).
    fn sequence_is_old(&self, sequence: u16) -> bool {
        if sequence == self.next_rx_sequence {
            return false;
        }
        // Compute distance with wrapping
        let dist = self.next_rx_sequence.wrapping_sub(sequence);
        // If dist is small (within half the sequence space), it's behind us
        dist > 0 && dist < 0x8000
    }

    /// Returns true if `a` should come before `b` in sequence order.
    fn sequence_after(&self, a: u16, b: u16) -> bool {
        let diff = a.wrapping_sub(b);
        diff > 0 && diff < 0x8000
    }

    /// Deliver contiguous messages from the RX ring to callbacks.
    fn deliver_pending(&mut self) {
        while let Some(front) = self.rx_ring.front() {
            if front.sequence != self.next_rx_sequence {
                break;
            }
            let envelope = self.rx_ring.pop_front().expect("just checked front");
            self.next_rx_sequence = self.next_rx_sequence.wrapping_add(1);

            if let Some(ref msg) = envelope.message {
                for cb in &self.message_callbacks {
                    if cb(msg.as_ref()) {
                        break;
                    }
                }
            }
        }
    }

    /// Handle delivery confirmation: remove from TX ring, grow window.
    pub(crate) fn on_delivery(&mut self, sequence: u16) {
        if let Some(pos) = self.tx_ring.iter().position(|e| e.sequence == sequence) {
            self.tx_ring.remove(pos);
        }
        // Grow window by 1 up to window_max
        if self.window < self.window_max {
            self.window += 1;
        }
        // Update RTT-based tier
        self.update_window_tier();
    }

    /// Handle timeout: shrink window, retry or teardown.
    pub(crate) fn on_timeout(
        &mut self,
        sequence: u16,
        transport: &TransportState,
    ) {
        // Shrink window
        if self.window > self.window_min {
            self.window -= 1;
        }
        // Shrink window_max down to (window_min + window_flexibility)
        let floor = self.window_min + self.window_flexibility;
        if self.window_max > floor {
            self.window_max -= 1;
            if self.window_max < floor {
                self.window_max = floor;
            }
        }

        // Find envelope and retry or teardown
        if let Some(pos) = self.tx_ring.iter().position(|e| e.sequence == sequence) {
            let tries = self.tx_ring[pos].tries;
            if tries >= self.max_tries {
                // Max retries exceeded: shutdown + teardown
                self.shutdown();
                self.outlet.timed_out(transport);
                return;
            }

            // Retry with exponential backoff
            self.tx_ring[pos].tries += 1;
            let new_tries = self.tx_ring[pos].tries;

            if let Some(ref mut packet) = self.tx_ring[pos].packet {
                let _ = self.outlet.resend(packet, transport);
            }

            // Set new timeout with exponential backoff
            let rtt = self.outlet.rtt();
            let base_timeout = rtt.max(0.025) * 2.5;
            let backoff = 1.5_f64.powi((new_tries - 1) as i32);
            let ring_factor = self.tx_ring.len() as f64 + 1.5;
            let timeout = backoff * base_timeout * ring_factor;

            if let Some(ref mut packet) = self.tx_ring[pos].packet {
                // We can't easily set callbacks here without self-referential borrows,
                // so we just set the timeout value
                self.outlet.set_packet_timeout_callback(packet, None, Some(timeout));
            }
        }

        self.update_window_tier();
    }

    /// RTT-based window tier selection.
    fn update_window_tier(&mut self) {
        let rtt = self.outlet.rtt();

        if rtt > RTT_SLOW {
            // Very slow: constrain everything to 1
            self.window = 1;
            self.window_max = 1;
            self.window_min = 1;
            self.window_flexibility = 1;
            self.fast_rate_rounds = 0;
            self.medium_rate_rounds = 0;
        } else if rtt <= RTT_FAST {
            // Fast link
            self.medium_rate_rounds = 0;
            self.fast_rate_rounds += 1;
            if self.fast_rate_rounds >= FAST_RATE_THRESHOLD {
                self.window_max = self.window_max.max(WINDOW_MAX_FAST);
                self.window_min = self.window_min.max(WINDOW_MIN_LIMIT_FAST);
            }
        } else if rtt <= RTT_MEDIUM {
            // Medium link
            self.fast_rate_rounds = 0;
            self.medium_rate_rounds += 1;
            if self.medium_rate_rounds >= FAST_RATE_THRESHOLD {
                self.window_max = self.window_max.max(WINDOW_MAX_MEDIUM);
                self.window_min = self.window_min.max(WINDOW_MIN_LIMIT_MEDIUM);
            }
        } else {
            // Between MEDIUM and SLOW: use slow defaults, reset counters
            self.fast_rate_rounds = 0;
            self.medium_rate_rounds = 0;
        }
    }

    /// Shut down the channel: clear rings and callbacks.
    pub(crate) fn shutdown(&mut self) {
        self.tx_ring.clear();
        self.rx_ring.clear();
        self.message_callbacks.clear();
    }

    // ── Test helpers ──

    /// Expose window for testing.
    #[doc(hidden)]
    pub fn window(&self) -> u16 {
        self.window
    }

    /// Expose window_max for testing.
    #[doc(hidden)]
    pub fn window_max(&self) -> u16 {
        self.window_max
    }

    /// Expose window_min for testing.
    #[doc(hidden)]
    pub fn window_min(&self) -> u16 {
        self.window_min
    }

    /// Expose window_flexibility for testing.
    #[doc(hidden)]
    pub fn window_flexibility(&self) -> u16 {
        self.window_flexibility
    }

    /// Set window for testing.
    #[doc(hidden)]
    pub fn set_window(&mut self, w: u16) {
        self.window = w;
    }

    /// Set window_max for testing.
    #[doc(hidden)]
    pub fn set_window_max(&mut self, w: u16) {
        self.window_max = w;
    }

    /// Set window_min for testing.
    #[doc(hidden)]
    pub fn set_window_min(&mut self, w: u16) {
        self.window_min = w;
    }

    /// Set window_flexibility for testing.
    #[doc(hidden)]
    pub fn set_window_flexibility(&mut self, w: u16) {
        self.window_flexibility = w;
    }

    /// Expose fast_rate_rounds for testing.
    #[doc(hidden)]
    pub fn fast_rate_rounds(&self) -> u16 {
        self.fast_rate_rounds
    }

    /// Expose medium_rate_rounds for testing.
    #[doc(hidden)]
    pub fn medium_rate_rounds(&self) -> u16 {
        self.medium_rate_rounds
    }

    /// Set fast_rate_rounds for testing.
    #[doc(hidden)]
    pub fn set_fast_rate_rounds(&mut self, r: u16) {
        self.fast_rate_rounds = r;
    }

    /// Set medium_rate_rounds for testing.
    #[doc(hidden)]
    pub fn set_medium_rate_rounds(&mut self, r: u16) {
        self.medium_rate_rounds = r;
    }

    /// Trigger delivery callback for testing.
    #[doc(hidden)]
    pub fn test_on_delivery(&mut self, sequence: u16) {
        self.on_delivery(sequence);
    }

    /// Trigger timeout callback for testing.
    #[doc(hidden)]
    pub fn test_on_timeout(&mut self, sequence: u16, transport: &TransportState) {
        self.on_timeout(sequence, transport);
    }

    /// Trigger window tier update for testing.
    #[doc(hidden)]
    pub fn test_update_window_tier(&mut self) {
        self.update_window_tier();
    }

    /// Get next_rx_sequence for testing.
    #[doc(hidden)]
    pub fn next_rx_sequence(&self) -> u16 {
        self.next_rx_sequence
    }
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
