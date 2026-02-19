#![allow(clippy::vec_init_then_push, clippy::too_many_arguments, dead_code)]
//! HTTP/2 frame building helpers for tests
//!
//! These functions construct raw HTTP/2 frames for precise testing of
//! frame parsing and stream tracking.

/// Frame type constants
pub const FRAME_TYPE_DATA: u8 = 0x00;
pub const FRAME_TYPE_HEADERS: u8 = 0x01;
pub const FRAME_TYPE_PRIORITY: u8 = 0x02;
pub const FRAME_TYPE_RST_STREAM: u8 = 0x03;
pub const FRAME_TYPE_SETTINGS: u8 = 0x04;
pub const FRAME_TYPE_PUSH_PROMISE: u8 = 0x05;
pub const FRAME_TYPE_PING: u8 = 0x06;
pub const FRAME_TYPE_GOAWAY: u8 = 0x07;
pub const FRAME_TYPE_WINDOW_UPDATE: u8 = 0x08;
pub const FRAME_TYPE_CONTINUATION: u8 = 0x09;

/// Frame flags
pub const FLAG_END_STREAM: u8 = 0x01;
pub const FLAG_END_HEADERS: u8 = 0x04;
pub const FLAG_PADDED: u8 = 0x08;
pub const FLAG_PRIORITY: u8 = 0x20;
pub const FLAG_ACK: u8 = 0x01; // For SETTINGS and PING

/// HTTP/2 connection preface
pub const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Build a raw HTTP/2 frame header (9 bytes)
fn build_frame_header(length: u32, frame_type: u8, flags: u8, stream_id: u32) -> Vec<u8> {
    let mut header = Vec::with_capacity(9);
    // Length (24-bit)
    header.push((length >> 16) as u8);
    header.push((length >> 8) as u8);
    header.push(length as u8);
    // Type
    header.push(frame_type);
    // Flags
    header.push(flags);
    // Stream ID (31-bit, high bit reserved)
    header.push((stream_id >> 24) as u8 & 0x7F);
    header.push((stream_id >> 16) as u8);
    header.push((stream_id >> 8) as u8);
    header.push(stream_id as u8);
    header
}

/// Build a DATA frame
///
/// # Arguments
/// * `stream_id` - Stream identifier (must be odd for client-initiated)
/// * `data` - The actual data payload
/// * `end_stream` - Whether to set END_STREAM flag
pub fn build_data_frame(stream_id: u32, data: &[u8], end_stream: bool) -> Vec<u8> {
    let flags = if end_stream { FLAG_END_STREAM } else { 0 };
    let mut frame = build_frame_header(data.len() as u32, FRAME_TYPE_DATA, flags, stream_id);
    frame.extend_from_slice(data);
    frame
}

/// Build a DATA frame with padding
pub fn build_data_frame_padded(
    stream_id: u32,
    data: &[u8],
    padding_len: u8,
    end_stream: bool,
) -> Vec<u8> {
    let mut flags = FLAG_PADDED;
    if end_stream {
        flags |= FLAG_END_STREAM;
    }
    let total_len = 1 + data.len() + padding_len as usize;
    let mut frame = build_frame_header(total_len as u32, FRAME_TYPE_DATA, flags, stream_id);
    frame.push(padding_len);
    frame.extend_from_slice(data);
    frame.extend(std::iter::repeat_n(0u8, padding_len as usize));
    frame
}

/// Build a HEADERS frame
///
/// # Arguments
/// * `stream_id` - Stream identifier
/// * `hpack_block` - HPACK-encoded header block
/// * `flags` - Frame flags (END_STREAM, END_HEADERS, PADDED, PRIORITY)
pub fn build_headers_frame(stream_id: u32, hpack_block: &[u8], flags: u8) -> Vec<u8> {
    let mut frame = build_frame_header(
        hpack_block.len() as u32,
        FRAME_TYPE_HEADERS,
        flags,
        stream_id,
    );
    frame.extend_from_slice(hpack_block);
    frame
}

/// Build a HEADERS frame with common flags set
///
/// Convenience method that sets both END_HEADERS and END_STREAM
pub fn build_complete_headers_frame(stream_id: u32, hpack_block: &[u8]) -> Vec<u8> {
    build_headers_frame(stream_id, hpack_block, FLAG_END_HEADERS | FLAG_END_STREAM)
}

/// Build a HEADERS frame without END_STREAM (expects body to follow)
pub fn build_headers_frame_with_body(stream_id: u32, hpack_block: &[u8]) -> Vec<u8> {
    build_headers_frame(stream_id, hpack_block, FLAG_END_HEADERS)
}

/// Build a HEADERS frame with PADDED flag
pub fn build_headers_frame_padded(
    stream_id: u32,
    hpack_block: &[u8],
    padding_len: u8,
    end_stream: bool,
    end_headers: bool,
) -> Vec<u8> {
    let mut flags = FLAG_PADDED;
    if end_stream {
        flags |= FLAG_END_STREAM;
    }
    if end_headers {
        flags |= FLAG_END_HEADERS;
    }
    let total_len = 1 + hpack_block.len() + padding_len as usize;
    let mut frame = build_frame_header(total_len as u32, FRAME_TYPE_HEADERS, flags, stream_id);
    frame.push(padding_len);
    frame.extend_from_slice(hpack_block);
    frame.extend(std::iter::repeat_n(0u8, padding_len as usize));
    frame
}

/// Build a HEADERS frame with PRIORITY flag
/// Priority: 5 bytes = [E (1 bit) + Stream Dependency (31 bits)] + [Weight (8
/// bits)]
pub fn build_headers_frame_priority(
    stream_id: u32,
    hpack_block: &[u8],
    stream_dependency: u32,
    exclusive: bool,
    weight: u8,
    end_stream: bool,
    end_headers: bool,
) -> Vec<u8> {
    let mut flags = FLAG_PRIORITY;
    if end_stream {
        flags |= FLAG_END_STREAM;
    }
    if end_headers {
        flags |= FLAG_END_HEADERS;
    }
    let total_len = 5 + hpack_block.len();
    let mut frame = build_frame_header(total_len as u32, FRAME_TYPE_HEADERS, flags, stream_id);
    // Stream dependency with exclusive bit
    let dep = if exclusive {
        stream_dependency | 0x80000000
    } else {
        stream_dependency
    };
    frame.extend_from_slice(&dep.to_be_bytes());
    frame.push(weight);
    frame.extend_from_slice(hpack_block);
    frame
}

/// Build a HEADERS frame with both PADDED and PRIORITY flags
pub fn build_headers_frame_padded_priority(
    stream_id: u32,
    hpack_block: &[u8],
    padding_len: u8,
    stream_dependency: u32,
    exclusive: bool,
    weight: u8,
    end_stream: bool,
    end_headers: bool,
) -> Vec<u8> {
    let mut flags = FLAG_PADDED | FLAG_PRIORITY;
    if end_stream {
        flags |= FLAG_END_STREAM;
    }
    if end_headers {
        flags |= FLAG_END_HEADERS;
    }
    // Layout: [Pad Length (1)] [E + Stream Dep (4)] [Weight (1)] [Header Block]
    // [Padding]
    let total_len = 1 + 5 + hpack_block.len() + padding_len as usize;
    let mut frame = build_frame_header(total_len as u32, FRAME_TYPE_HEADERS, flags, stream_id);
    frame.push(padding_len);
    let dep = if exclusive {
        stream_dependency | 0x80000000
    } else {
        stream_dependency
    };
    frame.extend_from_slice(&dep.to_be_bytes());
    frame.push(weight);
    frame.extend_from_slice(hpack_block);
    frame.extend(std::iter::repeat_n(0u8, padding_len as usize));
    frame
}

/// Build a CONTINUATION frame
///
/// # Arguments
/// * `stream_id` - Stream identifier (must match preceding HEADERS)
/// * `hpack_block` - Continuation of HPACK-encoded header block
/// * `end_headers` - Whether to set END_HEADERS flag
pub fn build_continuation_frame(stream_id: u32, hpack_block: &[u8], end_headers: bool) -> Vec<u8> {
    let flags = if end_headers { FLAG_END_HEADERS } else { 0 };
    let mut frame = build_frame_header(
        hpack_block.len() as u32,
        FRAME_TYPE_CONTINUATION,
        flags,
        stream_id,
    );
    frame.extend_from_slice(hpack_block);
    frame
}

/// Build a SETTINGS frame
///
/// # Arguments
/// * `settings` - Array of (identifier, value) pairs
///   - 0x01: HEADER_TABLE_SIZE
///   - 0x02: ENABLE_PUSH
///   - 0x03: MAX_CONCURRENT_STREAMS
///   - 0x04: INITIAL_WINDOW_SIZE
///   - 0x05: MAX_FRAME_SIZE
///   - 0x06: MAX_HEADER_LIST_SIZE
pub fn build_settings_frame(settings: &[(u16, u32)]) -> Vec<u8> {
    let payload_len = settings.len() * 6;
    let mut frame = build_frame_header(payload_len as u32, FRAME_TYPE_SETTINGS, 0, 0);
    for (id, value) in settings {
        frame.extend_from_slice(&id.to_be_bytes());
        frame.extend_from_slice(&value.to_be_bytes());
    }
    frame
}

/// Build an empty SETTINGS frame (common initial frame)
pub fn build_empty_settings_frame() -> Vec<u8> {
    build_frame_header(0, FRAME_TYPE_SETTINGS, 0, 0)
}

/// Build a SETTINGS ACK frame
pub fn build_settings_ack_frame() -> Vec<u8> {
    build_frame_header(0, FRAME_TYPE_SETTINGS, FLAG_ACK, 0)
}

/// Build a WINDOW_UPDATE frame
///
/// # Arguments
/// * `stream_id` - Stream identifier (0 for connection-level)
/// * `increment` - Window size increment (1 to 2^31-1)
pub fn build_window_update_frame(stream_id: u32, increment: u32) -> Vec<u8> {
    let mut frame = build_frame_header(4, FRAME_TYPE_WINDOW_UPDATE, 0, stream_id);
    // Increment value (31-bit, high bit reserved)
    frame.extend_from_slice(&(increment & 0x7FFFFFFF).to_be_bytes());
    frame
}

/// Build a PING frame
pub fn build_ping_frame(data: &[u8; 8], ack: bool) -> Vec<u8> {
    let flags = if ack { FLAG_ACK } else { 0 };
    let mut frame = build_frame_header(8, FRAME_TYPE_PING, flags, 0);
    frame.extend_from_slice(data);
    frame
}

/// Build a GOAWAY frame
pub fn build_goaway_frame(last_stream_id: u32, error_code: u32) -> Vec<u8> {
    let mut frame = build_frame_header(8, FRAME_TYPE_GOAWAY, 0, 0);
    frame.extend_from_slice(&(last_stream_id & 0x7FFFFFFF).to_be_bytes());
    frame.extend_from_slice(&error_code.to_be_bytes());
    frame
}

/// Build a RST_STREAM frame
pub fn build_rst_stream_frame(stream_id: u32, error_code: u32) -> Vec<u8> {
    let mut frame = build_frame_header(4, FRAME_TYPE_RST_STREAM, 0, stream_id);
    frame.extend_from_slice(&error_code.to_be_bytes());
    frame
}

/// HPACK helper: Encode a literal header with incremental indexing
///
/// This adds the header to the dynamic table so it can be referenced by later
/// frames. Format: 0b01xxxxxx (index 0 for new name)
pub fn hpack_literal_with_indexing(name: &str, value: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    // Literal with incremental indexing, new name (index 0)
    encoded.push(0x40);
    // Name length (7-bit prefix)
    encoded.push(name.len() as u8);
    encoded.extend_from_slice(name.as_bytes());
    // Value length (7-bit prefix)
    encoded.push(value.len() as u8);
    encoded.extend_from_slice(value.as_bytes());
    encoded
}

/// HPACK helper: Encode a literal header without indexing
///
/// This does NOT add to the dynamic table.
/// Format: 0b0000xxxx
pub fn hpack_literal_without_indexing(name: &str, value: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    // Literal without indexing, new name (index 0)
    encoded.push(0x00);
    // Name length (4-bit prefix, no huffman)
    encoded.push(name.len() as u8);
    encoded.extend_from_slice(name.as_bytes());
    // Value length (7-bit prefix, no huffman)
    encoded.push(value.len() as u8);
    encoded.extend_from_slice(value.as_bytes());
    encoded
}

/// HPACK helper: Encode an indexed header field
///
/// References either static table or dynamic table entry.
/// Format: 0b1xxxxxxx
pub fn hpack_indexed(index: u8) -> Vec<u8> {
    // Single byte for indices 1-127
    vec![0x80 | index]
}

/// HPACK helper: Encode common pseudo-headers using static table
pub mod hpack_static {
    /// :method: GET (index 2)
    pub fn method_get() -> Vec<u8> {
        vec![0x82]
    }
    /// :method: POST (index 3)
    pub fn method_post() -> Vec<u8> {
        vec![0x83]
    }
    /// :path: / (index 4)
    pub fn path_root() -> Vec<u8> {
        vec![0x84]
    }
    /// :path: /index.html (index 5)
    pub fn path_index_html() -> Vec<u8> {
        vec![0x85]
    }
    /// :scheme: http (index 6)
    pub fn scheme_http() -> Vec<u8> {
        vec![0x86]
    }
    /// :scheme: https (index 7)
    pub fn scheme_https() -> Vec<u8> {
        vec![0x87]
    }
    /// :status: 200 (index 8)
    pub fn status_200() -> Vec<u8> {
        vec![0x88]
    }
    /// :status: 204 (index 9)
    pub fn status_204() -> Vec<u8> {
        vec![0x89]
    }
    /// :status: 206 (index 10)
    pub fn status_206() -> Vec<u8> {
        vec![0x8a]
    }
    /// :status: 304 (index 11)
    pub fn status_304() -> Vec<u8> {
        vec![0x8b]
    }
    /// :status: 400 (index 12)
    pub fn status_400() -> Vec<u8> {
        vec![0x8c]
    }
    /// :status: 404 (index 13)
    pub fn status_404() -> Vec<u8> {
        vec![0x8d]
    }
    /// :status: 500 (index 14)
    pub fn status_500() -> Vec<u8> {
        vec![0x8e]
    }
}

/// Build a minimal valid HPACK block for a GET request
pub fn hpack_get_request(path: &str, authority: &str) -> Vec<u8> {
    let mut block = Vec::new();
    // :method: GET
    block.extend(hpack_static::method_get());
    // :scheme: https
    block.extend(hpack_static::scheme_https());
    // :path (literal without indexing if not / or /index.html)
    if path == "/" {
        block.extend(hpack_static::path_root());
    } else {
        block.extend(hpack_literal_without_indexing(":path", path));
    }
    // :authority (literal without indexing)
    block.extend(hpack_literal_without_indexing(":authority", authority));
    block
}

/// Build a minimal valid HPACK block for a POST request
pub fn hpack_post_request(path: &str, authority: &str) -> Vec<u8> {
    let mut block = Vec::new();
    // :method: POST
    block.extend(hpack_static::method_post());
    // :scheme: https
    block.extend(hpack_static::scheme_https());
    // :path
    if path == "/" {
        block.extend(hpack_static::path_root());
    } else {
        block.extend(hpack_literal_without_indexing(":path", path));
    }
    // :authority
    block.extend(hpack_literal_without_indexing(":authority", authority));
    block
}

/// Build a complete HTTP/2 connection start (preface + settings)
pub fn connection_start() -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(CONNECTION_PREFACE);
    data.extend(build_empty_settings_frame());
    data
}

/// HPACK Huffman encoding module
/// Pre-computed Huffman-encoded values for testing (RFC 7541 Appendix B)
pub mod hpack_huffman {
    /// Encode a string length with Huffman flag set (high bit = 1)
    fn huffman_length(len: usize) -> Vec<u8> {
        if len < 127 {
            vec![0x80 | len as u8]
        } else {
            // For lengths >= 127, use multi-byte encoding
            let mut result = vec![0xFF]; // 127 with huffman bit
            let mut remaining = len - 127;
            while remaining >= 128 {
                result.push(0x80 | (remaining & 0x7F) as u8);
                remaining >>= 7;
            }
            result.push(remaining as u8);
            result
        }
    }

    /// Huffman-encode "www.example.com" (pre-computed)
    /// This is a common test value from RFC 7541 examples
    pub fn www_example_com() -> Vec<u8> {
        // Huffman encoding of "www.example.com" = f1e3c2e5f23a6ba0ab90f4ff
        vec![
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ]
    }

    /// Huffman-encode "no-cache" (pre-computed)
    pub fn no_cache() -> Vec<u8> {
        // Huffman encoding of "no-cache" = a8eb10649cbf
        vec![0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]
    }

    /// Huffman-encode "custom-key" (pre-computed)
    pub fn custom_key() -> Vec<u8> {
        // Huffman encoding of "custom-key" = 25a849e95ba97d7f
        vec![0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f]
    }

    /// Huffman-encode "custom-value" (pre-computed)
    pub fn custom_value() -> Vec<u8> {
        // Huffman encoding of "custom-value" = 25a849e95bb8e8b4bf
        vec![0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf]
    }

    /// Build literal header with Huffman-encoded name and value (without
    /// indexing)
    pub fn literal_huffman(name_huffman: &[u8], value_huffman: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();
        // Literal without indexing, new name
        encoded.push(0x00);
        // Name length with Huffman flag
        encoded.extend(huffman_length(name_huffman.len()));
        encoded.extend_from_slice(name_huffman);
        // Value length with Huffman flag
        encoded.extend(huffman_length(value_huffman.len()));
        encoded.extend_from_slice(value_huffman);
        encoded
    }

    /// Build literal header with Huffman-encoded value only (indexed name)
    /// Uses static table index for the name
    pub fn literal_indexed_name_huffman_value(name_index: u8, value_huffman: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();
        // Literal without indexing, indexed name (4-bit prefix)
        encoded.push(name_index & 0x0F);
        // Value length with Huffman flag
        encoded.extend(huffman_length(value_huffman.len()));
        encoded.extend_from_slice(value_huffman);
        encoded
    }
}

/// Build a large HPACK block that will fill the dynamic table
/// Creates entries until we exceed the given table size
pub fn hpack_fill_dynamic_table(table_size: usize) -> Vec<u8> {
    let mut block = Vec::new();
    let mut total_size = 0;
    let mut i = 0;

    // Each entry overhead is 32 bytes (RFC 7541 Section 4.1)
    // Entry size = name length + value length + 32
    while total_size < table_size + 100 {
        let name = format!("x-header-{:04}", i);
        let value = format!("value-{:04}", i);
        let entry_size = name.len() + value.len() + 32;

        block.extend(super::hpack_literal_with_indexing(&name, &value));
        total_size += entry_size;
        i += 1;
    }

    block
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_data_frame() {
        let frame = build_data_frame(1, b"hello", false);
        assert_eq!(frame.len(), 9 + 5); // header + payload
        assert_eq!(frame[3], FRAME_TYPE_DATA);
        assert_eq!(frame[4], 0); // no flags
        assert_eq!(&frame[9..], b"hello");
    }

    #[test]
    fn test_build_data_frame_end_stream() {
        let frame = build_data_frame(1, b"hello", true);
        assert_eq!(frame[4], FLAG_END_STREAM);
    }

    #[test]
    fn test_build_settings_frame() {
        let frame = build_settings_frame(&[(0x04, 65535)]);
        assert_eq!(frame.len(), 9 + 6);
        assert_eq!(frame[3], FRAME_TYPE_SETTINGS);
    }

    #[test]
    fn test_build_window_update_frame() {
        let frame = build_window_update_frame(0, 1000);
        assert_eq!(frame.len(), 9 + 4);
        assert_eq!(frame[3], FRAME_TYPE_WINDOW_UPDATE);
    }

    #[test]
    fn test_hpack_indexed() {
        let encoded = hpack_indexed(2);
        assert_eq!(encoded, vec![0x82]); // :method: GET
    }
}
