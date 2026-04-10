// HDLC framing codec — simplified HDLC-like byte-stuffing, similar to PPP.
//
// Used by Serial, Pipe, TCP (default), Local, I2P, Backbone, and Weave interfaces
// to packetize Reticulum data on byte-stream transports.

/// HDLC frame delimiter.
pub const FLAG: u8 = 0x7E;
/// HDLC escape byte.
pub const ESC: u8 = 0x7D;
/// XOR mask applied to escaped bytes.
pub const ESC_MASK: u8 = 0x20;

/// Encode a payload into an HDLC frame: `[FLAG, escaped_data, FLAG]`.
///
/// Escapes all occurrences of FLAG and ESC in the data by replacing them
/// with `[ESC, byte ^ ESC_MASK]`. ESC bytes are escaped first to avoid
/// double-escaping FLAG replacements.
pub fn encode(data: &[u8]) -> Vec<u8> {
    // Worst case: every byte needs escaping (2x) + 2 FLAG delimiters
    let mut out = Vec::with_capacity(data.len() * 2 + 2);
    out.push(FLAG);
    for &b in data {
        if b == ESC {
            out.push(ESC);
            out.push(ESC ^ ESC_MASK);
        } else if b == FLAG {
            out.push(ESC);
            out.push(FLAG ^ ESC_MASK);
        } else {
            out.push(b);
        }
    }
    out.push(FLAG);
    out
}

/// Decode a single HDLC frame by unescaping the contents.
///
/// Input should be the raw bytes between two FLAG delimiters (exclusive),
/// still containing ESC sequences. Returns the unescaped payload.
pub fn decode(frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(frame.len());
    let mut escape = false;
    for &b in frame {
        if escape {
            out.push(b ^ ESC_MASK);
            escape = false;
        } else if b == ESC {
            escape = true;
        } else {
            out.push(b);
        }
    }
    out
}

/// Streaming HDLC decoder that accumulates bytes and yields complete frames.
///
/// Feed arbitrary chunks of bytes via [`feed`](HdlcDecoder::feed). When a
/// complete frame (delimited by FLAG bytes) is received, it is unescaped and
/// returned. Frames whose decoded length exceeds `hw_mtu` are silently discarded.
pub struct HdlcDecoder {
    buffer: Vec<u8>,
    in_frame: bool,
    escape: bool,
    overflow: bool,
    hw_mtu: usize,
}

impl HdlcDecoder {
    /// Create a new streaming decoder. `hw_mtu` is the maximum decoded frame
    /// size; frames exceeding this are discarded.
    pub fn new(hw_mtu: usize) -> Self {
        Self {
            buffer: Vec::new(),
            in_frame: false,
            escape: false,
            overflow: false,
            hw_mtu,
        }
    }

    /// Feed a chunk of bytes into the decoder.
    ///
    /// Returns a `Vec` of complete decoded frames extracted from the stream.
    /// Frames exceeding `hw_mtu` are silently discarded.
    pub fn feed(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();

        for &byte in data {
            if self.in_frame && byte == FLAG {
                // End of frame — yield if non-empty and not overflowed
                self.in_frame = false;
                self.escape = false;
                if !self.buffer.is_empty() && !self.overflow {
                    let frame = std::mem::take(&mut self.buffer);
                    frames.push(frame);
                } else {
                    self.buffer.clear();
                }
                self.overflow = false;
            } else if byte == FLAG {
                // Start of a new frame
                self.in_frame = true;
                self.escape = false;
                self.overflow = false;
                self.buffer.clear();
            } else if self.in_frame && !self.overflow {
                // Accumulate bytes with inline unescaping
                if byte == ESC {
                    self.escape = true;
                } else if self.escape {
                    self.buffer.push(byte ^ ESC_MASK);
                    self.escape = false;
                    if self.buffer.len() > self.hw_mtu {
                        self.overflow = true;
                    }
                } else {
                    self.buffer.push(byte);
                    if self.buffer.len() > self.hw_mtu {
                        self.overflow = true;
                    }
                }
            }
            // If overflow, silently drop remaining bytes until the next FLAG.
        }

        frames
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_no_special_bytes() {
        let data = b"hello";
        let encoded = encode(data);
        assert_eq!(encoded[0], FLAG);
        assert_eq!(&encoded[1..6], b"hello");
        assert_eq!(encoded[6], FLAG);
    }

    #[test]
    fn encode_escapes_flag_and_esc() {
        let data = &[FLAG, ESC, 0x42];
        let encoded = encode(data);
        assert_eq!(
            encoded,
            vec![FLAG, ESC, FLAG ^ ESC_MASK, ESC, ESC ^ ESC_MASK, 0x42, FLAG]
        );
    }

    #[test]
    fn decode_unescapes() {
        // Escaped FLAG and ESC
        let frame = &[ESC, FLAG ^ ESC_MASK, ESC, ESC ^ ESC_MASK, 0x42];
        let decoded = decode(frame);
        assert_eq!(decoded, vec![FLAG, ESC, 0x42]);
    }

    #[test]
    fn round_trip() {
        let data = vec![0x00, FLAG, ESC, 0xFF, 0x42];
        let encoded = encode(&data);
        // Strip FLAG delimiters, then decode the escaped content
        let inner = &encoded[1..encoded.len() - 1];
        let decoded = decode(inner);
        assert_eq!(decoded, data);
    }

    #[test]
    fn streaming_decoder_single_frame() {
        let data = b"test";
        let encoded = encode(data);
        let mut decoder = HdlcDecoder::new(1024);
        let frames = decoder.feed(&encoded);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], data);
    }

    #[test]
    fn streaming_decoder_multiple_frames() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&encode(b"one"));
        stream.extend_from_slice(&encode(b"two"));
        stream.extend_from_slice(&encode(b"three"));

        let mut decoder = HdlcDecoder::new(1024);
        let frames = decoder.feed(&stream);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0], b"one");
        assert_eq!(frames[1], b"two");
        assert_eq!(frames[2], b"three");
    }

    #[test]
    fn streaming_decoder_discards_oversized() {
        let big = vec![0x42; 100];
        let encoded = encode(&big);
        let mut decoder = HdlcDecoder::new(50); // MTU smaller than payload
        let frames = decoder.feed(&encoded);
        assert!(frames.is_empty());
    }

    #[test]
    fn streaming_decoder_chunked_input() {
        let data = vec![FLAG, ESC, 0x42, 0xFF];
        let encoded = encode(&data);
        let mut decoder = HdlcDecoder::new(1024);

        // Feed one byte at a time
        let mut all_frames = Vec::new();
        for &b in &encoded {
            all_frames.extend(decoder.feed(&[b]));
        }
        assert_eq!(all_frames.len(), 1);
        assert_eq!(all_frames[0], data);
    }

    #[test]
    fn streaming_decoder_empty_frame_ignored() {
        // Two consecutive FLAGs with nothing between them
        let stream = vec![FLAG, FLAG];
        let mut decoder = HdlcDecoder::new(1024);
        let frames = decoder.feed(&stream);
        assert!(frames.is_empty());
    }
}
