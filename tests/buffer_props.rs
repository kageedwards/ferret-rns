// Property-based tests for Buffer module
// Feature: ferret-test-coverage

use std::sync::{Arc, Mutex};

use proptest::prelude::*;

use ferret_rns::buffer::stream_data::StreamDataMessage;
use ferret_rns::buffer::STREAM_ID_MAX;
use ferret_rns::channel::message::{MessageBase, MessageState};
use ferret_rns::channel::outlet::ChannelOutlet;
use ferret_rns::channel::Channel;
use ferret_rns::packet::packet::Packet;
use ferret_rns::transport::transport::TransportState;
use ferret_rns::Result;

// ── Mock ChannelOutlet (same pattern as channel_props.rs) ──

struct MockOutlet {
    mdu_val: usize,
    rtt_val: f64,
    sent_data: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl MockOutlet {
    fn new(mdu: usize, rtt: f64) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let outlet = Self {
            mdu_val: mdu,
            rtt_val: rtt,
            sent_data: sent.clone(),
        };
        (outlet, sent)
    }
}

impl ChannelOutlet for MockOutlet {
    fn send(&self, raw: &[u8], _transport: &TransportState) -> Result<Packet> {
        self.sent_data.lock().unwrap().push(raw.to_vec());
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
        true
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

/// Helper: create a Channel with MockOutlet, returning (channel, sent_data_handle).
fn make_channel(mdu: usize) -> (Channel, Arc<Mutex<Vec<Vec<u8>>>>) {
    let (outlet, sent) = MockOutlet::new(mdu, 0.1);
    let channel = Channel::new(Box::new(outlet));
    (channel, sent)
}

/// Helper: build a StreamDataMessage and return its packed representation
/// (as would be delivered by Channel to a message handler).
fn make_sdm(stream_id: u16, eof: bool, data: &[u8]) -> StreamDataMessage {
    StreamDataMessage::new(stream_id, eof, false, data.to_vec()).unwrap()
}

// ══════════════════════════════════════════════════════════════════════════════
// Feature: ferret-test-coverage, Property 1: Buffer Reader accumulation, EOF, and partial read
// **Validates: Requirements 1.1, 1.3, 1.5**
// ══════════════════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    #[test]
    fn reader_accumulation_eof_partial_read(
        stream_id in 0u16..=STREAM_ID_MAX,
        // 1-5 payloads, each 0-200 bytes
        payloads in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..200), 1..6),
        send_eof in any::<bool>(),
        read_frac in 1u8..100u8,  // fraction of buffer to read (1-99%)
    ) {
        use ferret_rns::buffer::reader::RawChannelReader;

        let (mut channel, _sent) = make_channel(500);
        let mut reader = RawChannelReader::new(stream_id, &mut channel);

        // Feed payloads
        let mut expected = Vec::new();
        for payload in &payloads {
            let msg = make_sdm(stream_id, false, payload);
            let accepted = reader.handle_message(&msg);
            prop_assert!(accepted, "handle_message should accept matching stream_id");
            expected.extend_from_slice(payload);
        }

        // EOF not yet received
        prop_assert!(!reader.is_eof(), "should not be EOF before EOF message");

        // Optionally send EOF
        if send_eof {
            let eof_msg = make_sdm(stream_id, true, &[]);
            reader.handle_message(&eof_msg);
            prop_assert!(reader.is_eof(), "should be EOF after EOF message");
        }

        // Buffer should contain all accumulated bytes
        prop_assert_eq!(reader.available(), expected.len());

        // Partial read: read a fraction of the buffer
        if !expected.is_empty() {
            let n = ((expected.len() as u64 * read_frac as u64) / 100).max(1) as usize;
            let n = n.min(expected.len());
            let data = reader.read(n).unwrap();
            prop_assert_eq!(data.len(), n);
            prop_assert_eq!(&data[..], &expected[..n]);
            // Remainder should still be in buffer
            prop_assert_eq!(reader.available(), expected.len() - n);
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Feature: ferret-test-coverage, Property 2: Buffer Reader stream_id filtering
// **Validates: Requirements 1.2**
// ══════════════════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    #[test]
    fn reader_stream_id_filtering(
        reader_id in 0u16..=STREAM_ID_MAX,
        msg_id in 0u16..=STREAM_ID_MAX,
        payload in prop::collection::vec(any::<u8>(), 1..100),
    ) {
        // Only test when IDs differ
        prop_assume!(reader_id != msg_id);

        use ferret_rns::buffer::reader::RawChannelReader;

        let (mut channel, _sent) = make_channel(500);
        let mut reader = RawChannelReader::new(reader_id, &mut channel);

        let msg = make_sdm(msg_id, false, &payload);
        let accepted = reader.handle_message(&msg);

        prop_assert!(!accepted, "handle_message should reject mismatched stream_id");
        prop_assert_eq!(reader.available(), 0, "buffer should remain empty");
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Feature: ferret-test-coverage, Property 3: Buffer Reader ready callback
// **Validates: Requirements 1.4**
// ══════════════════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    #[test]
    fn reader_ready_callback(
        stream_id in 0u16..=STREAM_ID_MAX,
        payloads in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..100), 1..8),
    ) {
        use ferret_rns::buffer::reader::RawChannelReader;

        let (mut channel, _sent) = make_channel(500);
        let mut reader = RawChannelReader::new(stream_id, &mut channel);

        // Register a callback that records the buffer length each time it's called
        let recorded_lengths: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded_clone = recorded_lengths.clone();
        reader.add_ready_callback(Box::new(move |len| {
            recorded_clone.lock().unwrap().push(len);
        }));

        // Feed payloads and track expected cumulative lengths
        let mut cumulative = 0usize;
        let mut expected_lengths = Vec::new();
        for payload in &payloads {
            cumulative += payload.len();
            expected_lengths.push(cumulative);
            let msg = make_sdm(stream_id, false, payload);
            reader.handle_message(&msg);
        }

        let recorded = recorded_lengths.lock().unwrap();
        prop_assert_eq!(recorded.len(), payloads.len(),
            "callback should be invoked once per accepted message");
        prop_assert_eq!(&*recorded, &expected_lengths,
            "callback should receive cumulative buffer length");
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Feature: ferret-test-coverage, Property 4: Buffer Writer chunking and total bytes preservation
// **Validates: Requirements 2.1, 2.3, 2.4**
// ══════════════════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    #[test]
    fn writer_chunking_and_total_bytes(
        stream_id in 0u16..=STREAM_ID_MAX,
        data in prop::collection::vec(any::<u8>(), 1..500),
    ) {
        use ferret_rns::buffer::writer::RawChannelWriter;

        // Use a large window so the channel stays ready to send.
        // MDU 500 → channel.mdu() = 494 → max_chunk = 492
        let (mut channel, sent) = make_channel(500);
        channel.set_window(1000);
        channel.set_window_max(1000);

        let transport = TransportState::new();
        let mut writer = RawChannelWriter::new(stream_id, &channel);

        let written = writer.write(&data, &mut channel, &transport).unwrap();
        prop_assert_eq!(written, data.len(), "all bytes should be written");

        // Inspect sent envelopes: each is a 6-byte envelope header + 2-byte SDM header + payload
        let sent_envelopes = sent.lock().unwrap();
        prop_assert!(!sent_envelopes.is_empty(), "should have sent at least one chunk");

        let max_chunk = 492usize; // (500 - 6) - 2
        let mut total_payload = 0usize;

        for envelope_raw in sent_envelopes.iter() {
            // Envelope: 6 header + SDM packed data
            prop_assert!(envelope_raw.len() >= 8,
                "envelope should be at least 8 bytes (6 hdr + 2 SDM hdr)");

            // The SDM packed data starts at offset 6
            let sdm_packed = &envelope_raw[6..];
            let mut sdm = StreamDataMessage::empty();
            sdm.unpack(sdm_packed).unwrap();

            prop_assert_eq!(sdm.stream_id, stream_id);
            prop_assert!(!sdm.eof, "data chunks should not have eof");

            // The original (uncompressed) payload size must be ≤ max_chunk.
            // If compressed, the original data was ≤ max_chunk before compression.
            // We verify the SDM data length (which is the decompressed payload).
            prop_assert!(sdm.data.len() <= max_chunk,
                "chunk payload {} exceeds max_chunk {}", sdm.data.len(), max_chunk);

            total_payload += sdm.data.len();
        }

        prop_assert_eq!(total_payload, data.len(),
            "total payload across chunks should equal original data length");

        // Drop the lock before calling close (which sends another envelope)
        drop(sent_envelopes);

        // write after close should return 0
        writer.close(&mut channel, &transport).unwrap();
        let after_close = writer.write(&data, &mut channel, &transport).unwrap();
        prop_assert_eq!(after_close, 0, "write after close should return 0");
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Feature: ferret-test-coverage, Property 5 (unit): Buffer Writer close sends EOF
// and write-after-close returns 0
// **Validates: Requirements 2.2, 2.3**
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn writer_close_sends_eof_and_write_after_close_returns_zero() {
    use ferret_rns::buffer::writer::RawChannelWriter;

    let (mut channel, sent) = make_channel(500);
    channel.set_window(1000);
    channel.set_window_max(1000);

    let transport = TransportState::new();
    let mut writer = RawChannelWriter::new(0, &channel);

    // Write some data first
    let data = vec![1u8, 2, 3, 4, 5];
    writer.write(&data, &mut channel, &transport).unwrap();

    let before_close_count = sent.lock().unwrap().len();

    // Close the writer
    writer.close(&mut channel, &transport).unwrap();
    assert!(writer.is_eof(), "writer should be EOF after close");

    // The close should have sent one more envelope (the EOF message)
    let envelopes = sent.lock().unwrap();
    assert_eq!(envelopes.len(), before_close_count + 1,
        "close should send exactly one additional envelope");

    // Verify the last sent envelope contains an EOF StreamDataMessage
    let last_envelope = envelopes.last().unwrap();
    let sdm_packed = &last_envelope[6..]; // skip 6-byte envelope header
    let mut sdm = StreamDataMessage::empty();
    sdm.unpack(sdm_packed).unwrap();
    assert!(sdm.eof, "close message should have eof=true");
    assert!(sdm.data.is_empty(), "close message should have empty data");

    // Write after close returns 0
    drop(envelopes);
    let written = writer.write(&[10, 20, 30], &mut channel, &transport).unwrap();
    assert_eq!(written, 0, "write after close should return 0");
}
