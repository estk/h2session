use bytes::Bytes;

/// HTTP/3 frame types (RFC 9114 Section 7.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data,
    Headers,
    CancelPush,
    Settings,
    PushPromise,
    Goaway,
    MaxPushId,
    Unknown(u64),
}

impl From<u64> for FrameType {
    fn from(val: u64) -> Self {
        match val {
            0x00 => FrameType::Data,
            0x01 => FrameType::Headers,
            0x03 => FrameType::CancelPush,
            0x04 => FrameType::Settings,
            0x05 => FrameType::PushPromise,
            0x07 => FrameType::Goaway,
            0x0d => FrameType::MaxPushId,
            other => FrameType::Unknown(other),
        }
    }
}

/// A parsed HTTP/3 frame
#[derive(Debug, Clone)]
pub struct Frame {
    pub frame_type: FrameType,
    pub payload: Bytes,
}

/// Decode a QUIC variable-length integer (RFC 9000 Section 16).
/// Returns (value, bytes_consumed) or None if not enough data.
pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }

    let first = buf[0];
    let prefix = first >> 6;
    let len = 1 << prefix;

    if buf.len() < len {
        return None;
    }

    let value = match len {
        1 => (first & 0x3f) as u64,
        2 => {
            let raw = u16::from_be_bytes([buf[0], buf[1]]);
            (raw & 0x3fff) as u64
        }
        4 => {
            let raw = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            (raw & 0x3fff_ffff) as u64
        }
        8 => {
            let raw = u64::from_be_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]);
            raw & 0x3fff_ffff_ffff_ffff
        }
        _ => unreachable!(),
    };

    Some((value, len))
}

/// Parse HTTP/3 frames from a byte buffer.
/// Returns frames parsed and number of bytes consumed.
/// Leaves incomplete trailing data unconsumed.
pub fn parse_frames(buf: &[u8]) -> (Vec<Frame>, usize) {
    let mut frames = Vec::new();
    let mut offset = 0;

    loop {
        let remaining = &buf[offset..];

        // Parse frame type (varint)
        let Some((frame_type_val, type_len)) = decode_varint(remaining) else {
            break;
        };

        let after_type = &remaining[type_len..];

        // Parse frame length (varint)
        let Some((payload_len, len_len)) = decode_varint(after_type) else {
            break;
        };

        let header_size = type_len + len_len;
        let total_frame_size = header_size + payload_len as usize;

        // Check we have the full payload
        if remaining.len() < total_frame_size {
            break;
        }

        let payload_start = offset + header_size;
        let payload_end = payload_start + payload_len as usize;
        let payload = Bytes::copy_from_slice(&buf[payload_start..payload_end]);

        frames.push(Frame {
            frame_type: FrameType::from(frame_type_val),
            payload,
        });

        offset += total_frame_size;
    }

    (frames, offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_varint_1byte() {
        assert_eq!(decode_varint(&[0x25]), Some((37, 1)));
        assert_eq!(decode_varint(&[0x00]), Some((0, 1)));
        assert_eq!(decode_varint(&[0x3f]), Some((63, 1)));
    }

    #[test]
    fn test_decode_varint_2byte() {
        // 0x40 prefix (2 bytes), value = 0x01 << 8 | 0x01 = 0x0101 & 0x3fff = 257
        assert_eq!(decode_varint(&[0x41, 0x01]), Some((257, 2)));
        // Example from RFC 9000: 494878333 would be 4-byte
        assert_eq!(decode_varint(&[0x7b, 0xbd]), Some((15293, 2)));
    }

    #[test]
    fn test_decode_varint_4byte() {
        assert_eq!(
            decode_varint(&[0x9d, 0x7f, 0x3e, 0x7d]),
            Some((494878333, 4))
        );
    }

    #[test]
    fn test_decode_varint_insufficient_data() {
        assert_eq!(decode_varint(&[]), None);
        assert_eq!(decode_varint(&[0x41]), None); // needs 2 bytes
        assert_eq!(decode_varint(&[0x80, 0x00, 0x00]), None); // needs 4 bytes
    }

    #[test]
    fn test_parse_data_frame() {
        // DATA frame: type=0x00, length=5, payload="hello"
        let buf = [0x00, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let (frames, consumed) = parse_frames(&buf);
        assert_eq!(consumed, 7);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].frame_type, FrameType::Data);
        assert_eq!(&frames[0].payload[..], b"hello");
    }

    #[test]
    fn test_parse_multiple_frames() {
        // Two DATA frames back to back
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x03, b'a', b'b', b'c']); // DATA "abc"
        buf.extend_from_slice(&[0x00, 0x02, b'd', b'e']); // DATA "de"
        let (frames, consumed) = parse_frames(&buf);
        assert_eq!(consumed, buf.len());
        assert_eq!(frames.len(), 2);
        assert_eq!(&frames[0].payload[..], b"abc");
        assert_eq!(&frames[1].payload[..], b"de");
    }

    #[test]
    fn test_parse_incomplete_frame() {
        // DATA frame header says 10 bytes but only 3 present
        let buf = [0x00, 0x0a, b'h', b'i', b'!'];
        let (frames, consumed) = parse_frames(&buf);
        assert_eq!(consumed, 0);
        assert_eq!(frames.len(), 0);
    }

    #[test]
    fn test_parse_headers_frame_type() {
        // HEADERS frame: type=0x01, length=0 (empty for this test)
        let buf = [0x01, 0x00];
        let (frames, consumed) = parse_frames(&buf);
        assert_eq!(consumed, 2);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].frame_type, FrameType::Headers);
    }
}
