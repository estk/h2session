use crate::state::{ParseError, ParseErrorKind, StreamId};

/// HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
pub const CONNECTION_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Frame types
pub(crate) const FRAME_TYPE_DATA: u8 = 0x00;
pub(crate) const FRAME_TYPE_HEADERS: u8 = 0x01;
pub(crate) const FRAME_TYPE_PRIORITY: u8 = 0x02;
pub(crate) const FRAME_TYPE_RST_STREAM: u8 = 0x03;
pub(crate) const FRAME_TYPE_SETTINGS: u8 = 0x04;
pub(crate) const FRAME_TYPE_PUSH_PROMISE: u8 = 0x05;
pub(crate) const FRAME_TYPE_PING: u8 = 0x06;
pub(crate) const FRAME_TYPE_GOAWAY: u8 = 0x07;
pub(crate) const FRAME_TYPE_WINDOW_UPDATE: u8 = 0x08;
pub(crate) const FRAME_TYPE_CONTINUATION: u8 = 0x09;

/// Frame flags
pub(crate) const FLAG_END_STREAM: u8 = 0x01;
pub(crate) const FLAG_END_HEADERS: u8 = 0x04;
pub(crate) const FLAG_PADDED: u8 = 0x08;
pub(crate) const FLAG_PRIORITY: u8 = 0x20;

/// Frame header size (9 bytes)
pub(crate) const FRAME_HEADER_SIZE: usize = 9;

/// Maximum allowed frame payload length (2^24 - 1, per RFC 7540 §4.2)
pub(crate) const MAX_FRAME_PAYLOAD_LENGTH: u32 = (1 << 24) - 1;

/// Parsed HTTP/2 frame header
#[derive(Debug, Clone)]
pub(crate) struct FrameHeader {
    pub(crate) length: u32,
    pub(crate) frame_type: u8,
    pub(crate) flags: u8,
    pub(crate) stream_id: StreamId,
}

/// Check if buffer starts with HTTP/2 connection preface
pub fn is_http2_preface(buffer: &[u8]) -> bool {
    buffer.len() >= CONNECTION_PREFACE.len() && buffer.starts_with(CONNECTION_PREFACE)
}

/// Heuristic check if buffer looks like an HTTP/2 frame header.
/// Checks for valid frame type and reasonable length.
pub fn looks_like_http2_frame(buffer: &[u8]) -> bool {
    if buffer.len() < FRAME_HEADER_SIZE {
        return false;
    }

    // Parse length (24-bit)
    let length = u32::from_be_bytes([0, buffer[0], buffer[1], buffer[2]]);

    // Frame type should be a known type (0-9 are defined)
    let frame_type = buffer[3];
    if frame_type > 9 {
        return false;
    }

    // Stream ID should have high bit clear (reserved bit)
    let raw_stream_id = u32::from_be_bytes([buffer[5] & 0x7F, buffer[6], buffer[7], buffer[8]]);

    // Reasonable heuristics:
    // - Length should be reasonable (< 16MB default max frame size)
    // - For SETTINGS frames on stream 0, length should be multiple of 6
    if length > MAX_FRAME_PAYLOAD_LENGTH {
        return false;
    }

    if frame_type == FRAME_TYPE_SETTINGS && raw_stream_id == 0 && !length.is_multiple_of(6) {
        return false;
    }

    true
}

/// Parse the 9-byte frame header.
///
/// Zero-length frames are valid per RFC 7540 (e.g., SETTINGS ACK, empty
/// DATA with END_STREAM, PING). This function does not reject length == 0.
pub(crate) fn parse_frame_header(buffer: &[u8]) -> Result<FrameHeader, ParseError> {
    if buffer.len() < FRAME_HEADER_SIZE {
        return Err(ParseError::new(ParseErrorKind::Http2BufferTooSmall));
    }

    let length = u32::from_be_bytes([0, buffer[0], buffer[1], buffer[2]]);
    let frame_type = buffer[3];
    let flags = buffer[4];
    let stream_id = StreamId(u32::from_be_bytes([
        buffer[5] & 0x7F,
        buffer[6],
        buffer[7],
        buffer[8],
    ]));

    Ok(FrameHeader {
        length,
        frame_type,
        flags,
        stream_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_http2_preface() {
        assert!(is_http2_preface(CONNECTION_PREFACE));
        assert!(is_http2_preface(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nextra"));
        assert!(!is_http2_preface(b"GET / HTTP/1.1\r\n"));
        assert!(!is_http2_preface(b"PRI"));
    }

    #[test]
    fn test_looks_like_http2_frame() {
        // Valid SETTINGS frame header (type 4, length 0, stream 0)
        let settings_frame = [0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(looks_like_http2_frame(&settings_frame));

        // Invalid: too short
        assert!(!looks_like_http2_frame(&[0x00, 0x00]));

        // Invalid: unknown frame type (> 9)
        let bad_type = [0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(!looks_like_http2_frame(&bad_type));
    }

    #[test]
    fn test_parse_frame_header() {
        // HEADERS frame, length 10, flags 0x04, stream 1
        let data = [0x00, 0x00, 0x0A, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01];
        let header = parse_frame_header(&data).unwrap();
        assert_eq!(header.length, 10);
        assert_eq!(header.frame_type, FRAME_TYPE_HEADERS);
        assert_eq!(header.flags, 0x04);
        assert_eq!(header.stream_id, StreamId(1));
    }

    #[test]
    fn test_parse_frame_header_too_small() {
        let data = [0x00, 0x00, 0x0A];
        assert!(matches!(
            parse_frame_header(&data),
            Err(ref e) if matches!(e.kind, ParseErrorKind::Http2BufferTooSmall)
        ));
    }
}
