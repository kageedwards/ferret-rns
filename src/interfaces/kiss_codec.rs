// KISS framing codec — KISS TNC protocol byte-stuffing.
//
// Used by KISSInterface, RNodeInterface, and optionally TCP/I2P interfaces
// to packetize Reticulum data on radio and byte-stream transports.

// ── KISS framing constants ──

/// KISS frame delimiter.
pub const FEND: u8 = 0xC0;
/// KISS escape byte.
pub const FESC: u8 = 0xDB;
/// Transposed FEND (used after FESC to represent a literal FEND).
pub const TFEND: u8 = 0xDC;
/// Transposed FESC (used after FESC to represent a literal FESC).
pub const TFESC: u8 = 0xDD;

// ── Standard KISS command bytes ──
// These use the low nibble of the command byte; the high nibble is the port number.

/// Data frame (port 0).
pub const CMD_DATA: u8 = 0x00;
/// Set TX delay (in 10 ms units).
pub const CMD_TXDELAY: u8 = 0x01;
/// Set persistence parameter P.
pub const CMD_P: u8 = 0x02;
/// Set slot time (in 10 ms units).
pub const CMD_SLOTTIME: u8 = 0x03;
/// Set TX tail (in 10 ms units).
pub const CMD_TXTAIL: u8 = 0x04;
/// Set hardware-specific parameter.
pub const CMD_SET_HARDWARE: u8 = 0x06;
/// TNC ready signal (flow control).
pub const CMD_READY: u8 = 0x0F;
/// Return from KISS mode.
pub const CMD_RETURN: u8 = 0xFF;

// ── RNode extended KISS commands ──
// These share byte values with standard KISS commands but are used in a
// different context: they are sent as KISS command frames to configure
// RNode LoRa radio hardware.

/// Set radio frequency (4-byte big-endian Hz).
pub const CMD_FREQUENCY: u8 = 0x01;
/// Set radio bandwidth (4-byte big-endian Hz).
pub const CMD_BANDWIDTH: u8 = 0x02;
/// Set TX power (1 byte, dBm).
pub const CMD_TXPOWER: u8 = 0x03;
/// Set spreading factor (1 byte).
pub const CMD_SF: u8 = 0x04;
/// Set coding rate (1 byte).
pub const CMD_CR: u8 = 0x05;
/// Set radio state (on/off).
pub const CMD_RADIO_STATE: u8 = 0x06;
/// Set radio lock.
pub const CMD_RADIO_LOCK: u8 = 0x07;
/// Detect RNode hardware.
pub const CMD_DETECT: u8 = 0x08;
/// RX statistics.
pub const CMD_STAT_RX: u8 = 0x21;
/// TX statistics.
pub const CMD_STAT_TX: u8 = 0x22;
/// Last RSSI value.
pub const CMD_STAT_RSSI: u8 = 0x23;
/// Last SNR value.
pub const CMD_STAT_SNR: u8 = 0x24;
/// Channel time statistics.
pub const CMD_STAT_TNCI: u8 = 0x25;
/// Battery status.
pub const CMD_STAT_BAT: u8 = 0x26;
/// Blink LED.
pub const CMD_BLINK: u8 = 0x30;
/// Request random bytes.
pub const CMD_RANDOM: u8 = 0x40;
/// Firmware version query.
pub const CMD_FW_VERSION: u8 = 0x50;
/// ROM read.
pub const CMD_ROM_READ: u8 = 0x51;
/// Reset device.
pub const CMD_RESET: u8 = 0x55;

// ── KISS escaping helpers ──

/// Escape KISS special bytes in `data`, replacing FEND with [FESC, TFEND]
/// and FESC with [FESC, TFESC].
fn escape(data: &[u8], out: &mut Vec<u8>) {
    for &b in data {
        match b {
            FEND => {
                out.push(FESC);
                out.push(TFEND);
            }
            FESC => {
                out.push(FESC);
                out.push(TFESC);
            }
            _ => out.push(b),
        }
    }
}

/// Encode a data payload into a KISS CMD_DATA frame: `[FEND, CMD_DATA, escaped_data, FEND]`.
pub fn encode_data(data: &[u8]) -> Vec<u8> {
    encode_command(CMD_DATA, data)
}

/// Encode an arbitrary command frame: `[FEND, cmd, escaped_data, FEND]`.
pub fn encode_command(cmd: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 2 + 3);
    out.push(FEND);
    out.push(cmd);
    escape(data, &mut out);
    out.push(FEND);
    out
}

/// A decoded KISS frame with its command byte and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KissFrame {
    /// Command byte (low nibble only, port nibble stripped).
    pub command: u8,
    /// Decoded (unescaped) payload data.
    pub data: Vec<u8>,
}

/// Streaming KISS decoder that accumulates bytes and yields complete frames.
///
/// Feed arbitrary chunks of bytes via [`feed`](KissDecoder::feed). When a
/// complete frame (delimited by FEND bytes) is received, the command byte is
/// extracted (low nibble), the payload is unescaped, and a [`KissFrame`] is
/// returned. Frames whose decoded payload exceeds `hw_mtu` are silently discarded.
pub struct KissDecoder {
    buffer: Vec<u8>,
    in_frame: bool,
    escape: bool,
    has_command: bool,
    command: u8,
    overflow: bool,
    hw_mtu: usize,
}

impl KissDecoder {
    /// Create a new streaming decoder. `hw_mtu` is the maximum decoded payload
    /// size; frames exceeding this are discarded.
    pub fn new(hw_mtu: usize) -> Self {
        Self {
            buffer: Vec::new(),
            in_frame: false,
            escape: false,
            has_command: false,
            command: 0,
            overflow: false,
            hw_mtu,
        }
    }

    /// Feed a chunk of bytes into the decoder.
    ///
    /// Returns a `Vec` of complete decoded [`KissFrame`]s extracted from the
    /// stream. Frames exceeding `hw_mtu` are silently discarded. The port
    /// nibble (high 4 bits) is stripped from the command byte.
    pub fn feed(&mut self, data: &[u8]) -> Vec<KissFrame> {
        let mut frames = Vec::new();

        for &byte in data {
            if byte == FEND {
                if self.in_frame && self.has_command && !self.overflow {
                    // End of frame — yield it (even if data is empty)
                    let frame = KissFrame {
                        command: self.command,
                        data: std::mem::take(&mut self.buffer),
                    };
                    frames.push(frame);
                }
                // Start/reset for next frame
                self.in_frame = true;
                self.escape = false;
                self.has_command = false;
                self.command = 0;
                self.overflow = false;
                self.buffer.clear();
            } else if self.in_frame && !self.overflow {
                if !self.has_command {
                    // First byte after FEND is the command byte.
                    // Strip the port nibble (high 4 bits), keep the command (low 4 bits).
                    self.command = byte & 0x0F;
                    self.has_command = true;
                } else if self.escape {
                    let unescaped = match byte {
                        TFEND => FEND,
                        TFESC => FESC,
                        _ => byte, // malformed, pass through
                    };
                    self.buffer.push(unescaped);
                    self.escape = false;
                    if self.buffer.len() > self.hw_mtu {
                        self.overflow = true;
                    }
                } else if byte == FESC {
                    self.escape = true;
                } else {
                    self.buffer.push(byte);
                    if self.buffer.len() > self.hw_mtu {
                        self.overflow = true;
                    }
                }
            }
            // If overflow or not in frame, silently drop bytes.
        }

        frames
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_data_no_special_bytes() {
        let data = b"hello";
        let encoded = encode_data(data);
        assert_eq!(encoded[0], FEND);
        assert_eq!(encoded[1], CMD_DATA);
        assert_eq!(&encoded[2..7], b"hello");
        assert_eq!(encoded[7], FEND);
    }

    #[test]
    fn encode_data_escapes_fend_and_fesc() {
        let data = &[FEND, FESC, 0x42];
        let encoded = encode_data(data);
        assert_eq!(
            encoded,
            vec![FEND, CMD_DATA, FESC, TFEND, FESC, TFESC, 0x42, FEND]
        );
    }

    #[test]
    fn encode_command_wraps_correctly() {
        let data = &[0x01, 0x02];
        let encoded = encode_command(0x05, data);
        assert_eq!(encoded, vec![FEND, 0x05, 0x01, 0x02, FEND]);
    }

    #[test]
    fn round_trip_via_decoder() {
        let data = vec![0x00, FEND, FESC, 0xFF, 0x42];
        let encoded = encode_data(&data);
        let mut decoder = KissDecoder::new(1024);
        let frames = decoder.feed(&encoded);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].command, CMD_DATA);
        assert_eq!(frames[0].data, data);
    }

    #[test]
    fn decoder_strips_port_nibble() {
        // Simulate a command byte with port nibble set: port=1, cmd=0 → 0x10
        let frame = vec![FEND, 0x10, 0xAA, 0xBB, FEND];
        let mut decoder = KissDecoder::new(1024);
        let frames = decoder.feed(&frame);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].command, CMD_DATA); // 0x10 & 0x0F = 0x00
        assert_eq!(frames[0].data, vec![0xAA, 0xBB]);
    }

    #[test]
    fn decoder_multiple_frames() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&encode_data(b"one"));
        stream.extend_from_slice(&encode_data(b"two"));
        stream.extend_from_slice(&encode_data(b"three"));

        let mut decoder = KissDecoder::new(1024);
        let frames = decoder.feed(&stream);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].data, b"one");
        assert_eq!(frames[1].data, b"two");
        assert_eq!(frames[2].data, b"three");
    }

    #[test]
    fn decoder_discards_oversized() {
        let big = vec![0x42; 100];
        let encoded = encode_data(&big);
        let mut decoder = KissDecoder::new(50);
        let frames = decoder.feed(&encoded);
        assert!(frames.is_empty());
    }

    #[test]
    fn decoder_chunked_input() {
        let data = vec![FEND, FESC, 0x42, 0xFF];
        let encoded = encode_data(&data);
        let mut decoder = KissDecoder::new(1024);

        let mut all_frames = Vec::new();
        for &b in &encoded {
            all_frames.extend(decoder.feed(&[b]));
        }
        assert_eq!(all_frames.len(), 1);
        assert_eq!(all_frames[0].command, CMD_DATA);
        assert_eq!(all_frames[0].data, data);
    }

    #[test]
    fn decoder_empty_frame_ignored() {
        // Two consecutive FENDs with nothing between them
        let stream = vec![FEND, FEND];
        let mut decoder = KissDecoder::new(1024);
        let frames = decoder.feed(&stream);
        assert!(frames.is_empty());
    }

    #[test]
    fn decoder_command_frame() {
        let encoded = encode_command(CMD_TXDELAY, &[0x28]);
        let mut decoder = KissDecoder::new(1024);
        let frames = decoder.feed(&encoded);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].command, CMD_TXDELAY);
        assert_eq!(frames[0].data, vec![0x28]);
    }
}
