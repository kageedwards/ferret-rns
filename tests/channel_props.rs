// Property-based tests for Channel module
// Feature: ferret-link-channel

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use proptest::prelude::*;

use ferret_rns::channel::message::{MessageBase, MessageFactory, MessageState};
use ferret_rns::channel::outlet::ChannelOutlet;
use ferret_rns::channel::Channel;
use ferret_rns::packet::packet::Packet;
use ferret_rns::transport::transport::TransportState;
use ferret_rns::Result;

// ── Test message type for property tests ──

/// A simple test message that stores raw bytes.
struct TestMessage {
    msg_type: u16,
    data: Vec<u8>,
}

impl TestMessage {
    fn new(msg_type: u16) -> Self {
        Self {
            msg_type,
            data: Vec::new(),
        }
    }
}

impl MessageBase for TestMessage {
    fn msgtype(&self) -> u16 {
        self.msg_type
    }

    fn pack(&self) -> Result<Vec<u8>> {
        Ok(self.data.clone())
    }

    fn unpack(&mut self, raw: &[u8]) -> Result<()> {
        self.data = raw.to_vec();
        Ok(())
    }
}

// ── Mock ChannelOutlet for property tests ──

struct MockOutlet {
    mdu_val: usize,
    rtt_val: f64,
    usable: bool,
    sent_data: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl MockOutlet {
    fn new(mdu: usize, rtt: f64) -> Self {
        Self {
            mdu_val: mdu,
            rtt_val: rtt,
            usable: true,
            sent_data: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl ChannelOutlet for MockOutlet {
    fn send(&self, raw: &[u8], _transport: &TransportState) -> Result<Packet> {
        self.sent_data.lock().unwrap().push(raw.to_vec());
        // Return a minimal packet
        Ok(Packet::from_raw(raw.to_vec()))
    }

    fn resend(&self, _packet: &mut Packet, _transport: &TransportState) -> Result<()> {
        Ok(())
    }

    fn mdu(&self) -> usize {
        self.mdu_val
    }

    fn rtt(&self) -> f64 {
        self.rtt_val
    }

    fn is_usable(&self) -> bool {
        self.usable
    }

    fn timed_out(&self, _transport: &TransportState) {}

    fn get_packet_state(&self, _packet: &Packet) -> MessageState {
        MessageState::Sent
    }

    fn set_packet_timeout_callback(
        &self,
        _packet: &mut Packet,
        _callback: Option<Box<dyn Fn(&Packet) + Send + Sync>>,
        _timeout: Option<f64>,
    ) {
    }

    fn set_packet_delivered_callback(
        &self,
        _packet: &mut Packet,
        _callback: Option<Box<dyn Fn(&Packet) + Send + Sync>>,
    ) {
    }

    fn get_packet_id(&self, _packet: &Packet) -> Option<[u8; 32]> {
        None
    }
}

// ── Property 2: Envelope pack/unpack round trip ──
// For any valid MSGTYPE (1..0xF000), sequence (u16), and payload bytes (0..400),
// pack then unpack produces equivalent message.
// **Validates: Requirements 16.1, 16.2, 16.3**

proptest! {
    #[test]
    fn envelope_pack_unpack_round_trip(
        msgtype in 1u16..0xF000u16,
        sequence in any::<u16>(),
        payload in prop::collection::vec(any::<u8>(), 0..400),
    ) {
        use ferret_rns::channel::envelope::Envelope;

        let mut msg = TestMessage::new(msgtype);
        msg.data = payload.clone();

        let mut envelope = Envelope::new(Box::new(msg), sequence);
        let raw = envelope.pack().unwrap();

        // Verify header structure: 6 bytes header + payload
        prop_assert_eq!(raw.len(), 6 + payload.len());

        // Verify header fields
        let hdr_msgtype = u16::from_be_bytes([raw[0], raw[1]]);
        let hdr_sequence = u16::from_be_bytes([raw[2], raw[3]]);
        let hdr_length = u16::from_be_bytes([raw[4], raw[5]]);
        prop_assert_eq!(hdr_msgtype, msgtype);
        prop_assert_eq!(hdr_sequence, sequence);
        prop_assert_eq!(hdr_length, payload.len() as u16);

        // Build factory map and unpack
        let mt = msgtype;
        let mut factories: HashMap<u16, MessageFactory> = HashMap::new();
        factories.insert(mt, Box::new(move || {
            Box::new(TestMessage::new(mt)) as Box<dyn MessageBase>
        }));

        let mut envelope2 = Envelope::new_empty(0);
        envelope2.unpack(&raw, &factories).unwrap();

        // Verify round-trip
        prop_assert_eq!(envelope2.sequence, sequence);
        let msg2 = envelope2.message.as_ref().unwrap();
        prop_assert_eq!(msg2.msgtype(), msgtype);
        let repacked = msg2.pack().unwrap();
        prop_assert_eq!(repacked, payload);
    }
}

// ── Property 6: Channel delivers messages in contiguous sequence order ──
// For any permutation of N messages (N in 1..20), Channel delivers in strictly
// ascending sequence order.
// **Validates: Requirements 13.4**

proptest! {
    #[test]
    fn channel_delivers_in_order(
        n in 1usize..20usize,
        seed in any::<u64>(),
    ) {
        use std::sync::{Arc, Mutex};

        // Generate a permutation of 0..n using a simple Fisher-Yates with seed
        let mut indices: Vec<u16> = (0..n as u16).collect();
        let mut rng_state = seed;
        for i in (1..indices.len()).rev() {
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let j = (rng_state as usize) % (i + 1);
            indices.swap(i, j);
        }

        let delivered: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(Vec::new()));
        let delivered_clone = delivered.clone();

        let outlet = MockOutlet::new(500, 0.5);
        let mut channel = Channel::new(Box::new(outlet));

        // Register test message type
        let mt: u16 = 1;
        channel.register_message_type(mt, Box::new(move || {
            Box::new(TestMessage::new(mt)) as Box<dyn MessageBase>
        })).unwrap();

        // Add handler that records delivered sequence numbers
        channel.add_message_handler(Box::new(move |msg: &dyn MessageBase| {
            // The sequence is encoded in the message data
            let data = msg.pack().unwrap();
            if data.len() >= 2 {
                let seq = u16::from_be_bytes([data[0], data[1]]);
                delivered_clone.lock().unwrap().push(seq);
            }
            true
        }));

        // Feed messages in permuted order
        for &seq in &indices {
            let mut msg = TestMessage::new(mt);
            msg.data = seq.to_be_bytes().to_vec();

            // Build raw envelope bytes manually
            let payload = msg.pack().unwrap();
            let length = payload.len() as u16;
            let mut raw = Vec::with_capacity(6 + payload.len());
            raw.extend_from_slice(&mt.to_be_bytes());
            raw.extend_from_slice(&seq.to_be_bytes());
            raw.extend_from_slice(&length.to_be_bytes());
            raw.extend_from_slice(&payload);

            channel.receive(&raw).unwrap();
        }

        // Verify delivery order is strictly ascending 0, 1, 2, ..., n-1
        let delivered_seqs = delivered.lock().unwrap();
        prop_assert_eq!(delivered_seqs.len(), n, "expected {} deliveries, got {}", n, delivered_seqs.len());
        for (i, &seq) in delivered_seqs.iter().enumerate() {
            prop_assert_eq!(seq, i as u16, "delivery {} was seq {} expected {}", i, seq, i);
        }
    }
}

// ── Property 9: Channel window growth on delivery ──
// For any Channel with window < window_max, delivery increases window by exactly 1;
// at window_max, no increase.
// **Validates: Requirements 12.4**

proptest! {
    #[test]
    fn window_growth_on_delivery(
        window in 1u16..47u16,
        window_max in 2u16..48u16,
    ) {
        // Ensure window_max > window for the growth case
        let effective_max = window.max(2) + 1 + (window_max % 20);

        let outlet = MockOutlet::new(500, 0.5);
        let mut channel = Channel::new(Box::new(outlet));
        channel.set_window(window);
        channel.set_window_max(effective_max);

        let before = channel.window();
        channel.test_on_delivery(0);
        let after = channel.window();

        if before < effective_max {
            prop_assert_eq!(after, before + 1, "window should grow by 1: {} -> {}", before, after);
        } else {
            prop_assert_eq!(after, before, "window should not grow at max: {} -> {}", before, after);
        }
    }

    #[test]
    fn window_no_growth_at_max(
        window_max in 2u16..48u16,
    ) {
        let outlet = MockOutlet::new(500, 0.5);
        let mut channel = Channel::new(Box::new(outlet));
        channel.set_window(window_max);
        channel.set_window_max(window_max);

        channel.test_on_delivery(0);

        prop_assert_eq!(channel.window(), window_max,
            "window should not exceed window_max");
    }
}

// ── Property 10: Channel window shrink on timeout ──
// For any Channel with window > window_min, timeout decreases window by 1;
// window_max decreases by 1 down to (window_min + window_flexibility).
// **Validates: Requirements 12.7**

proptest! {
    #[test]
    fn window_shrink_on_timeout(
        window in 3u16..48u16,
        window_min in 1u16..3u16,
        window_max in 5u16..48u16,
        flexibility in 1u16..5u16,
    ) {
        // Ensure valid relationships
        let effective_min = window_min.min(window - 1);
        let effective_max = window_max.max(window + 1);
        let floor = effective_min + flexibility;

        let outlet = MockOutlet::new(500, 0.5);
        let mut channel = Channel::new(Box::new(outlet));
        channel.set_window(window);
        channel.set_window_min(effective_min);
        channel.set_window_max(effective_max);
        channel.set_window_flexibility(flexibility);

        let transport = TransportState::new();
        let before_window = channel.window();
        let before_max = channel.window_max();

        channel.test_on_timeout(999, &transport); // sequence not in tx_ring, so only window shrink happens

        // Window should decrease by 1 (since window > window_min)
        if before_window > effective_min {
            prop_assert_eq!(channel.window(), before_window - 1,
                "window should shrink by 1");
        }

        // window_max should decrease by 1 down to floor
        if before_max > floor {
            let expected_max = (before_max - 1).max(floor);
            prop_assert_eq!(channel.window_max(), expected_max,
                "window_max should shrink toward floor");
        } else {
            prop_assert_eq!(channel.window_max(), before_max,
                "window_max should not go below floor");
        }
    }
}

// ── Property 11: RTT-based window tier selection ──
// For any RTT, correct tier is selected per thresholds and round counts.
// **Validates: Requirements 14.1, 14.2, 14.3, 14.4**

proptest! {
    #[test]
    fn rtt_based_window_tier_selection(
        rtt in 0.01f64..5.0f64,
        rounds in 0u16..20u16,
    ) {
        use ferret_rns::channel::{
            RTT_FAST, RTT_MEDIUM, RTT_SLOW,
            FAST_RATE_THRESHOLD,
            WINDOW_MAX_FAST, WINDOW_MAX_MEDIUM,
            WINDOW_MIN_LIMIT_FAST, WINDOW_MIN_LIMIT_MEDIUM,
        };

        let outlet = MockOutlet::new(500, rtt);
        let mut channel = Channel::new(Box::new(outlet));

        // Pre-set round counters
        if rtt <= RTT_FAST {
            channel.set_fast_rate_rounds(rounds);
        } else if rtt <= RTT_MEDIUM {
            channel.set_medium_rate_rounds(rounds);
        }

        channel.test_update_window_tier();

        if rtt > RTT_SLOW {
            // Very slow tier
            prop_assert_eq!(channel.window(), 1, "slow: window should be 1");
            prop_assert_eq!(channel.window_max(), 1, "slow: window_max should be 1");
            prop_assert_eq!(channel.window_min(), 1, "slow: window_min should be 1");
            prop_assert_eq!(channel.window_flexibility(), 1, "slow: flexibility should be 1");
        } else if rtt <= RTT_FAST {
            // Fast tier
            if rounds + 1 >= FAST_RATE_THRESHOLD {
                // +1 because update_window_tier increments before checking
                prop_assert!(channel.window_max() >= WINDOW_MAX_FAST,
                    "fast after threshold: window_max {} should be >= {}", channel.window_max(), WINDOW_MAX_FAST);
                prop_assert!(channel.window_min() >= WINDOW_MIN_LIMIT_FAST,
                    "fast after threshold: window_min {} should be >= {}", channel.window_min(), WINDOW_MIN_LIMIT_FAST);
            }
        } else if rtt <= RTT_MEDIUM {
            // Medium tier
            if rounds + 1 >= FAST_RATE_THRESHOLD {
                prop_assert!(channel.window_max() >= WINDOW_MAX_MEDIUM,
                    "medium after threshold: window_max {} should be >= {}", channel.window_max(), WINDOW_MAX_MEDIUM);
                prop_assert!(channel.window_min() >= WINDOW_MIN_LIMIT_MEDIUM,
                    "medium after threshold: window_min {} should be >= {}", channel.window_min(), WINDOW_MIN_LIMIT_MEDIUM);
            }
        }
        // Between MEDIUM and SLOW: counters reset, no special assertions needed
    }
}
