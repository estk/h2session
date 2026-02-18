// HTTP/2 session management crate
// Provides connection-level state tracking for HTTP/2 parsing

mod frame;
mod http_types;
mod parse;
mod state;

#[cfg(feature = "tracing")]
macro_rules! trace_warn {
    ($($arg:tt)*) => { ::tracing::warn!($($arg)*) }
}
#[cfg(not(feature = "tracing"))]
macro_rules! trace_warn {
    ($($arg:tt)*) => {};
}
pub(crate) use trace_warn;

// Public re-exports for direct state management
use dashmap::DashMap;
pub use frame::{CONNECTION_PREFACE, is_http2_preface, looks_like_http2_frame};
pub use http_types::{HttpRequest, HttpResponse};
pub use state::{H2ConnectionState, H2Limits, ParseError, ParsedH2Message};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;

/// HTTP/2 session cache with generic connection keys.
///
/// Uses `DashMap<K, Mutex<H2ConnectionState>>` to provide per-key serialization.
/// The DashMap shard lock is held only briefly (to look up or insert the entry),
/// while the per-key Mutex serializes concurrent same-key calls to `parse()`.
/// This prevents the remove-and-reinsert race where two threads would both
/// create default state for the same key, losing one thread's HPACK table.
pub struct H2SessionCache<K> {
    connections: DashMap<K, Mutex<H2ConnectionState>>,
}

impl<K: Hash + Eq + Clone> H2SessionCache<K> {
    /// Create a new cache
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
        }
    }

    /// Parse buffer with connection state
    ///
    /// If the connection key doesn't exist, creates new state automatically.
    /// Returns completed HTTP/2 messages indexed by stream_id. The map may be
    /// empty if no streams completed yet — this is not an error.
    pub fn parse(
        &self,
        key: K,
        buffer: &[u8],
    ) -> Result<HashMap<u32, ParsedH2Message>, ParseError> {
        // Ensure entry exists (brief shard write lock)
        if !self.connections.contains_key(&key) {
            self.connections
                .insert(key.clone(), Mutex::new(H2ConnectionState::default()));
        }
        // Get shared shard read lock + per-key mutex lock
        let entry = self.connections.get(&key).expect("just ensured exists");
        let mut state = entry.lock().unwrap_or_else(|e| e.into_inner());
        parse::parse_frames_stateful(buffer, &mut state)
    }

    /// Remove connection state (call when connection closes)
    pub fn remove(&self, key: &K) -> Option<H2ConnectionState> {
        self.connections
            .remove(key)
            .map(|(_, mutex)| mutex.into_inner().unwrap_or_else(|e| e.into_inner()))
    }

    /// Check if connection state exists
    pub fn contains(&self, key: &K) -> bool {
        self.connections.contains_key(key)
    }

    /// Get number of tracked connections
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }
}

impl<K: Hash + Eq + Clone> Default for H2SessionCache<K> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_frames_stateful;

    // Helper to create a minimal SETTINGS frame
    fn create_settings_frame() -> Vec<u8> {
        vec![
            0x00, 0x00, 0x00, // Length: 0
            0x04, // Type: SETTINGS
            0x00, // Flags: none
            0x00, 0x00, 0x00, 0x00, // Stream ID: 0
        ]
    }

    // Helper to create a minimal HEADERS frame with END_HEADERS and END_STREAM flags
    fn create_headers_frame(stream_id: u32, header_block: &[u8]) -> Vec<u8> {
        let mut frame = vec![
            0x00,
            0x00,
            header_block.len() as u8, // Length
            0x01,                     // Type: HEADERS
            0x05,                     // Flags: END_STREAM | END_HEADERS
            0x00,
            0x00,
            0x00,
            stream_id as u8, // Stream ID
        ];
        frame.extend_from_slice(header_block);
        frame
    }

    #[test]
    fn test_cache_new() {
        let cache: H2SessionCache<String> = H2SessionCache::new();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_operations() {
        let cache = H2SessionCache::new();
        let key = "conn1".to_string();

        // Initially empty
        assert!(!cache.contains(&key));
        assert_eq!(cache.len(), 0);

        // Parse some data to create state
        let preface = frame::CONNECTION_PREFACE.to_vec();
        let settings = create_settings_frame();
        let mut buffer = preface;
        buffer.extend_from_slice(&settings);

        // This should create state and return Ok(empty) (no complete messages)
        let result = cache.parse(key.clone(), &buffer);
        assert!(matches!(result, Ok(ref m) if m.is_empty()));

        // Now state should exist
        assert!(cache.contains(&key));
        assert_eq!(cache.len(), 1);

        // Remove state
        let removed = cache.remove(&key);
        assert!(removed.is_some());
        assert!(!cache.contains(&key));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_hpack_persistence() {
        let cache = H2SessionCache::new();
        let key = "conn1".to_string();

        // First message with indexed header
        let mut buffer1 = frame::CONNECTION_PREFACE.to_vec();
        buffer1.extend_from_slice(&create_settings_frame());

        // HPACK encoded ":method: GET" using indexed header
        let header_block1 = vec![0x82]; // :method: GET (index 2)
        buffer1.extend_from_slice(&create_headers_frame(1, &header_block1));

        let result1 = cache.parse(key.clone(), &buffer1);
        assert!(result1.is_ok());

        // Second parse should still work with the same dynamic table
        let mut buffer2 = Vec::new();
        let header_block2 = vec![0x82]; // Same header reference
        buffer2.extend_from_slice(&create_headers_frame(3, &header_block2));

        let result2 = cache.parse(key.clone(), &buffer2);
        assert!(result2.is_ok());
    }

    #[test]
    fn test_multi_stream_tracking() {
        let cache = H2SessionCache::new();
        let key = "conn1".to_string();

        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame());

        // Stream 1 HEADERS
        let header_block1 = vec![0x82]; // :method: GET
        buffer.extend_from_slice(&create_headers_frame(1, &header_block1));

        // Stream 3 HEADERS
        let header_block2 = vec![0x82]; // :method: GET
        buffer.extend_from_slice(&create_headers_frame(3, &header_block2));

        let result = cache.parse(key.clone(), &buffer);
        assert!(result.is_ok());

        // Should return multiple messages (one per completed stream), keyed by stream_id
        let messages = result.unwrap();
        assert!(!messages.is_empty()); // At least one message completed
    }

    #[test]
    fn test_generic_key_string() {
        let cache: H2SessionCache<String> = H2SessionCache::new();

        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame());
        let header_block = vec![0x82];
        buffer.extend_from_slice(&create_headers_frame(1, &header_block));

        let result = cache.parse("session_123".to_string(), &buffer);
        assert!(result.is_ok());
        assert!(cache.contains(&"session_123".to_string()));
    }

    #[test]
    fn test_generic_key_tuple() {
        let cache: H2SessionCache<(u32, u32)> = H2SessionCache::new();

        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame());
        let header_block = vec![0x82];
        buffer.extend_from_slice(&create_headers_frame(1, &header_block));

        let result = cache.parse((1234, 5678), &buffer);
        assert!(result.is_ok());
        assert!(cache.contains(&(1234, 5678)));
    }

    #[test]
    fn test_parse_returns_hashmap_keyed_by_stream_id() {
        let cache = H2SessionCache::new();
        let key = "conn1".to_string();

        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame());

        // Stream 1 HEADERS
        let header_block1 = vec![0x82]; // :method: GET
        buffer.extend_from_slice(&create_headers_frame(1, &header_block1));

        // Stream 3 HEADERS
        let header_block2 = vec![0x82]; // :method: GET
        buffer.extend_from_slice(&create_headers_frame(3, &header_block2));

        let result = cache.parse(key.clone(), &buffer);
        assert!(result.is_ok());

        let messages = result.unwrap();
        // Verify messages are keyed by stream_id
        assert!(messages.contains_key(&1) || messages.contains_key(&3));

        // Verify stream_id matches the key
        for (stream_id, msg) in &messages {
            assert_eq!(*stream_id, msg.stream_id);
        }
    }

    // =========================================================================
    // CRITICAL-1: HPACK decompression bomb protection
    // =========================================================================

    /// Build an HPACK block with many literal headers (no indexing) to exceed limits
    fn build_many_headers_hpack(count: usize) -> Vec<u8> {
        let mut block = Vec::new();
        for i in 0..count {
            let name = format!("x-header-{i:04}");
            let value = format!("value-{i:04}");
            // Literal without indexing, new name (0x00)
            block.push(0x00);
            block.push(name.len() as u8);
            block.extend_from_slice(name.as_bytes());
            block.push(value.len() as u8);
            block.extend_from_slice(value.as_bytes());
        }
        block
    }

    /// Build a complete HEADERS frame with END_HEADERS | END_STREAM
    fn build_test_headers_frame(stream_id: u32, hpack_block: &[u8]) -> Vec<u8> {
        let mut frame = vec![
            0x00, 0x00, 0x00, // Length placeholder
            0x01, // Type: HEADERS
            0x05, // Flags: END_STREAM | END_HEADERS
            0x00, 0x00, 0x00, 0x00, // Stream ID placeholder
        ];
        let len = hpack_block.len();
        frame[0] = (len >> 16) as u8;
        frame[1] = (len >> 8) as u8;
        frame[2] = len as u8;
        frame[5] = (stream_id >> 24) as u8 & 0x7F;
        frame[6] = (stream_id >> 16) as u8;
        frame[7] = (stream_id >> 8) as u8;
        frame[8] = stream_id as u8;
        frame.extend_from_slice(hpack_block);
        frame
    }

    #[test]
    fn test_header_count_limit_exceeded() {
        // With default max_header_count = 128, sending 200 headers should fail
        let mut state = H2ConnectionState::new();
        let hpack = build_many_headers_hpack(200);

        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame());
        buffer.extend(build_test_headers_frame(1, &hpack));

        let result = state.feed(&buffer, 1_000_000);
        // Should be non-fatal (headers rejected but parsing continues)
        assert!(result.is_ok(), "Header limit violation should be non-fatal");
        // Stream should NOT have completed successfully
        assert!(
            state.try_pop().is_none(),
            "Stream should not complete with too many headers"
        );
    }

    #[test]
    fn test_header_count_within_limit() {
        let mut state = H2ConnectionState::new();
        // 50 headers + pseudo-headers should be well within the 128 limit
        let mut hpack = Vec::new();
        hpack.push(0x82); // :method: GET
        hpack.extend(build_many_headers_hpack(50));

        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame());
        buffer.extend(build_test_headers_frame(1, &hpack));

        let result = state.feed(&buffer, 1_000_000);
        assert!(result.is_ok());
        let msg = state.try_pop();
        assert!(
            msg.is_some(),
            "Stream should complete with headers within limit"
        );
    }

    #[test]
    fn test_header_list_size_limit_exceeded() {
        // Create headers with large values to exceed the 64KB total limit
        let mut hpack = Vec::new();
        for i in 0..20 {
            let name = format!("x-big-{i:02}");
            // Each value is 4KB, 20 headers * (4KB + name + 32) > 64KB
            let value = "X".repeat(4096);
            hpack.push(0x00);
            hpack.push(name.len() as u8);
            hpack.extend_from_slice(name.as_bytes());
            // Value length > 127 needs multi-byte encoding
            let vlen = value.len();
            if vlen < 127 {
                hpack.push(vlen as u8);
            } else {
                hpack.push(0x7F);
                let mut remaining = vlen - 127;
                while remaining >= 128 {
                    hpack.push(0x80 | (remaining & 0x7F) as u8);
                    remaining >>= 7;
                }
                hpack.push(remaining as u8);
            }
            hpack.extend_from_slice(value.as_bytes());
        }

        let mut state = H2ConnectionState::new();
        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame());
        buffer.extend(build_test_headers_frame(1, &hpack));

        let result = state.feed(&buffer, 1_000_000);
        assert!(
            result.is_ok(),
            "Header size limit violation should be non-fatal"
        );
        assert!(
            state.try_pop().is_none(),
            "Stream should not complete when header list too large"
        );
    }

    #[test]
    fn test_individual_header_value_size_limit() {
        // Create a header with a value > 8KB (default max_header_value_size)
        let mut hpack = Vec::new();
        let name = "x-huge-value";
        let value = "Y".repeat(9000); // 9KB, exceeds 8KB limit
        hpack.push(0x00);
        hpack.push(name.len() as u8);
        hpack.extend_from_slice(name.as_bytes());
        let vlen = value.len();
        hpack.push(0x7F);
        let mut remaining = vlen - 127;
        while remaining >= 128 {
            hpack.push(0x80 | (remaining & 0x7F) as u8);
            remaining >>= 7;
        }
        hpack.push(remaining as u8);
        hpack.extend_from_slice(value.as_bytes());

        let mut state = H2ConnectionState::new();
        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame());
        buffer.extend(build_test_headers_frame(1, &hpack));

        let result = state.feed(&buffer, 1_000_000);
        assert!(
            result.is_ok(),
            "Header value size violation should be non-fatal"
        );
        assert!(
            state.try_pop().is_none(),
            "Stream should not complete with oversized header value"
        );
    }

    // =========================================================================
    // MED-1: Invalid UTF-8 header encoding rejected
    // =========================================================================

    #[test]
    fn test_invalid_utf8_header_rejected() {
        // HPACK literal header with invalid UTF-8 value (0xFF is not valid UTF-8)
        let mut hpack = Vec::new();
        hpack.push(0x82); // :method: GET (static)
        hpack.push(0x87); // :scheme: https (static)
        hpack.push(0x84); // :path: / (static)
        // Literal without indexing, new name "x-bad"
        hpack.push(0x00);
        hpack.push(0x05); // name length 5
        hpack.extend_from_slice(b"x-bad");
        hpack.push(0x03); // value length 3
        hpack.extend_from_slice(&[0xFF, 0xFE, 0x41]); // invalid UTF-8

        let mut state = H2ConnectionState::new();
        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame());
        buffer.extend(build_test_headers_frame(1, &hpack));

        let result = state.feed(&buffer, 1_000_000);
        assert!(
            result.is_ok(),
            "Invalid UTF-8 should be non-fatal via feed()"
        );
        // Stream should not complete because encoding error drops it
        assert!(
            state.try_pop().is_none(),
            "Stream with invalid UTF-8 header should not complete"
        );
    }

    #[test]
    fn test_invalid_utf8_returns_encoding_error_variant() {
        // Verify that parse_frames_stateful returns Http2InvalidHeaderEncoding
        // (not Http2HeaderListTooLarge) for UTF-8 failures.
        let mut hpack = Vec::new();
        hpack.push(0x82); // :method: GET (static)
        hpack.push(0x87); // :scheme: https (static)
        hpack.push(0x84); // :path: / (static)
        // Literal without indexing, new name "x-bad"
        hpack.push(0x00);
        hpack.push(0x05); // name length 5
        hpack.extend_from_slice(b"x-bad");
        hpack.push(0x03); // value length 3
        hpack.extend_from_slice(&[0xFF, 0xFE, 0x41]); // invalid UTF-8

        let mut state = H2ConnectionState::new();
        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame());
        buffer.extend(build_test_headers_frame(1, &hpack));

        let result = parse_frames_stateful(&buffer, &mut state);
        assert!(
            matches!(result, Err(ParseError::Http2InvalidHeaderEncoding)),
            "Should return Http2InvalidHeaderEncoding, got: {result:?}"
        );
    }

    #[test]
    fn test_valid_ascii_headers_accepted() {
        // Normal ASCII headers should work fine
        let mut hpack = Vec::new();
        hpack.push(0x82); // :method: GET (static)
        hpack.push(0x87); // :scheme: https (static)
        hpack.push(0x84); // :path: / (static)
        // Literal without indexing, new name "x-good"
        hpack.push(0x00);
        hpack.push(0x06); // name length 6
        hpack.extend_from_slice(b"x-good");
        hpack.push(0x05); // value length 5
        hpack.extend_from_slice(b"hello");

        let mut state = H2ConnectionState::new();
        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame());
        buffer.extend(build_test_headers_frame(1, &hpack));

        let result = state.feed(&buffer, 1_000_000);
        assert!(result.is_ok());
        let msg = state.try_pop();
        assert!(
            msg.is_some(),
            "Stream with valid ASCII headers should complete"
        );
    }

    // =========================================================================
    // HIGH-1: SETTINGS HEADER_TABLE_SIZE applied to decoder
    // =========================================================================

    #[test]
    fn test_settings_header_table_size_applied() {
        // Send SETTINGS with HEADER_TABLE_SIZE = 0, then try to use dynamic table
        let mut state = H2ConnectionState::new();

        // First: connection preface + SETTINGS table_size=0
        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        // SETTINGS frame with HEADER_TABLE_SIZE = 0
        let settings_payload = [0x00u8, 0x01, 0x00, 0x00, 0x00, 0x00]; // id=1, value=0
        let mut settings_frame = vec![
            0x00, 0x00, 0x06, // length = 6
            0x04, // type = SETTINGS
            0x00, // flags
            0x00, 0x00, 0x00, 0x00, // stream_id = 0
        ];
        settings_frame.extend_from_slice(&settings_payload);
        buffer.extend(settings_frame);

        // Add a header with indexing (tries to add to dynamic table)
        let mut hpack = Vec::new();
        hpack.push(0x82); // :method: GET (static, fine)
        // Literal with incremental indexing: tries to add "x-test: value" to dynamic table
        hpack.push(0x40); // Literal with indexing, new name
        hpack.push(0x06); // name length
        hpack.extend_from_slice(b"x-test");
        hpack.push(0x05); // value length
        hpack.extend_from_slice(b"value");
        buffer.extend(build_test_headers_frame(1, &hpack));

        let result = state.feed(&buffer, 1_000_000);
        // With table size 0, the dynamic table should be empty.
        // The decoder should still work — it just won't store the entry.
        assert!(
            result.is_ok(),
            "Parsing should succeed with table_size=0: {result:?}"
        );
    }

    // =========================================================================
    // CRITICAL-2: Stream eviction and concurrent stream limits
    // =========================================================================

    #[test]
    fn test_stream_timeout_eviction() {
        let mut state = H2ConnectionState::with_limits(H2Limits {
            stream_timeout_ns: 1_000_000_000, // 1 second
            max_concurrent_streams: 100,
            ..H2Limits::default()
        });

        // Feed a HEADERS frame (without END_STREAM) at t=1s
        let hpack = vec![0x82]; // :method: GET
        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame());
        // HEADERS with END_HEADERS only (no END_STREAM — stream stays open)
        let mut headers = vec![
            0x00,
            0x00,
            hpack.len() as u8,
            0x01, // HEADERS
            0x04, // END_HEADERS only
            0x00,
            0x00,
            0x00,
            0x01, // stream 1
        ];
        headers.extend(&hpack);
        buffer.extend(headers);

        let _ = state.feed(&buffer, 1_000_000_000);
        assert_eq!(state.active_streams.len(), 1, "Stream 1 should be active");

        // Feed empty data at t=3s (>1s timeout) to trigger eviction
        let _ = state.feed(&[], 3_000_000_000);
        assert_eq!(
            state.active_streams.len(),
            0,
            "Stream should be evicted after timeout"
        );
    }

    #[test]
    fn test_max_concurrent_streams_enforced() {
        let mut state = H2ConnectionState::with_limits(H2Limits {
            max_concurrent_streams: 2,
            stream_timeout_ns: 60_000_000_000, // 60s, won't trigger
            ..H2Limits::default()
        });

        let hpack = vec![0x82]; // :method: GET

        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame());

        // Open 2 streams (at capacity)
        for &stream_id in &[1u32, 3] {
            let mut headers = vec![
                0x00,
                0x00,
                hpack.len() as u8,
                0x01,
                0x04, // HEADERS, END_HEADERS only
                (stream_id >> 24) as u8 & 0x7F,
                (stream_id >> 16) as u8,
                (stream_id >> 8) as u8,
                stream_id as u8,
            ];
            headers.extend(&hpack);
            buffer.extend(headers);
        }

        let _ = state.feed(&buffer, 1_000_000);
        assert_eq!(
            state.active_streams.len(),
            2,
            "Should have 2 active streams"
        );

        // Try to open a 3rd stream — should be rejected (non-fatal)
        let mut buffer2 = Vec::new();
        let mut headers3 = vec![
            0x00,
            0x00,
            hpack.len() as u8,
            0x01,
            0x04,
            0x00,
            0x00,
            0x00,
            0x05, // stream 5
        ];
        headers3.extend(&hpack);
        buffer2.extend(headers3);

        let result = state.feed(&buffer2, 2_000_000);
        assert!(
            result.is_ok(),
            "Exceeding max concurrent streams should be non-fatal"
        );
        assert_eq!(
            state.active_streams.len(),
            2,
            "Should still have only 2 streams"
        );
    }

    #[test]
    fn test_body_size_limit_drops_stream() {
        let mut state = H2ConnectionState::with_limits(H2Limits {
            max_body_size: 10, // Very small limit for testing
            ..H2Limits::default()
        });

        let hpack = vec![0x82, 0x87, 0x84]; // GET, https, /
        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame());
        // HEADERS with END_HEADERS only (0x04), NOT END_STREAM (body follows)
        let hpack_len = hpack.len();
        let mut headers_frame = vec![
            (hpack_len >> 16) as u8,
            (hpack_len >> 8) as u8,
            hpack_len as u8,
            0x01, // HEADERS
            0x04, // END_HEADERS only
            0x00,
            0x00,
            0x00,
            0x01, // stream 1
        ];
        headers_frame.extend(&hpack);
        buffer.extend(headers_frame);

        // DATA frame with 20 bytes (exceeds 10 byte limit), END_STREAM
        let body = vec![0x41u8; 20];
        let body_len = body.len();
        let mut data_frame = vec![
            (body_len >> 16) as u8,
            (body_len >> 8) as u8,
            body_len as u8,
            0x00, // DATA
            0x01, // END_STREAM
            0x00,
            0x00,
            0x00,
            0x01, // stream 1
        ];
        data_frame.extend(&body);
        buffer.extend(data_frame);

        let result = parse_frames_stateful(&buffer, &mut state);
        assert!(result.is_ok(), "Body size limit should be non-fatal");
        // Stream should have been dropped, so no completed messages
        assert!(
            result.unwrap().is_empty(),
            "Stream exceeding body size limit should be dropped"
        );
        assert_eq!(
            state.active_streams.len(),
            0,
            "Stream should be removed after exceeding body limit"
        );
    }

    // =========================================================================
    // TEST-3: Concurrent access to H2SessionCache
    // =========================================================================

    #[test]
    fn test_h2session_cache_concurrent_different_connections() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(H2SessionCache::new());
        let num_threads = 8;

        let handles: Vec<_> = (0..num_threads)
            .map(|i| {
                let cache = Arc::clone(&cache);
                thread::spawn(move || {
                    let key = format!("conn_{i}");
                    let mut buffer = frame::CONNECTION_PREFACE.to_vec();
                    buffer.extend_from_slice(&create_settings_frame());

                    // Use a unique stream id per thread (odd numbers)
                    let stream_id = (i * 2 + 1) as u32;
                    let hpack = vec![0x82]; // :method: GET (static)
                    buffer.extend(create_headers_frame(stream_id, &hpack));

                    let result = cache.parse(key.clone(), &buffer);
                    assert!(result.is_ok(), "Thread {i} parse should succeed");
                    assert!(cache.contains(&key));
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("Thread should not panic");
        }

        assert_eq!(cache.len(), num_threads);
    }

    #[test]
    fn test_h2session_cache_concurrent_same_connection() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(H2SessionCache::new());
        let key = "shared_conn".to_string();

        // Pre-populate with preface + settings
        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame());
        let _ = cache.parse(key.clone(), &buffer);

        let num_threads = 4;
        let handles: Vec<_> = (0..num_threads)
            .map(|i| {
                let cache = Arc::clone(&cache);
                let key = key.clone();
                thread::spawn(move || {
                    // Each thread sends a HEADERS frame on a different stream
                    let stream_id = (i * 2 + 1) as u32;
                    let hpack = vec![0x82]; // :method: GET
                    let frame = create_headers_frame(stream_id, &hpack);
                    let result = cache.parse(key, &frame);
                    assert!(result.is_ok(), "Thread {i} same-conn parse should succeed");
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("Thread should not panic");
        }

        assert!(cache.contains(&key));
    }

    // =========================================================================
    // C2: Buffer growth cap
    // =========================================================================

    #[test]
    fn test_buffer_growth_cap_rejects_oversized_feed() {
        let mut state = H2ConnectionState::with_limits(H2Limits {
            max_buffer_size: 100,
            ..H2Limits::default()
        });

        // Single feed exceeding the limit
        let chunk = vec![0x00u8; 101];
        let result = state.feed(&chunk, 1_000_000);
        assert!(
            matches!(result, Err(ParseError::Http2BufferTooLarge)),
            "Feed exceeding buffer cap should return Http2BufferTooLarge, got: {result:?}"
        );
    }

    #[test]
    fn test_buffer_growth_cap_exact_limit_succeeds() {
        let mut state = H2ConnectionState::with_limits(H2Limits {
            max_buffer_size: 100,
            ..H2Limits::default()
        });

        // Feed exactly 100 bytes — at limit, should succeed
        let chunk = vec![0x00u8; 100];
        assert!(
            state.feed(&chunk, 1_000_000).is_ok(),
            "Feed at exact limit should succeed"
        );
    }

    // =========================================================================
    // C4: checked_add for frame size calculation
    // =========================================================================

    #[test]
    fn test_checked_add_max_24bit_length() {
        // Frame with max 24-bit length (16,777,215). On 64-bit this fits but
        // the checked path should still work correctly.
        let max_length: u32 = 0x00FF_FFFF; // 16,777,215
        let frame = vec![
            (max_length >> 16) as u8,
            (max_length >> 8) as u8,
            max_length as u8,
            0x00, // DATA
            0x00, // flags
            0x00,
            0x00,
            0x00,
            0x01, // stream 1
        ];
        // Only the frame header is present (no payload). The max_frame_size
        // check fires before the incomplete-frame check.

        let mut state = H2ConnectionState::new();
        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame());
        buffer.extend_from_slice(&frame);

        // parse_frames_stateful should not panic — it should just see an incomplete frame
        let result = parse_frames_stateful(&buffer, &mut state);
        // The max_frame_size check will reject this before the incomplete frame check
        assert!(
            matches!(result, Err(ParseError::Http2FrameSizeError)),
            "Max 24-bit length frame should trigger FrameSizeError, got: {result:?}"
        );
    }

    // =========================================================================
    // H1: Enforce max_frame_size
    // =========================================================================

    #[test]
    fn test_max_frame_size_rejects_oversized_frame() {
        // Default max_frame_size is 16384. A frame with length 16385 should be rejected.
        let length: u32 = 16385; // 1 over default
        let mut frame_header = vec![
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
            0x00, // DATA
            0x01, // END_STREAM
            0x00,
            0x00,
            0x00,
            0x01, // stream 1
        ];
        frame_header.extend(vec![0x41u8; length as usize]);

        let mut state = H2ConnectionState::new();
        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame());
        // First open a stream with HEADERS
        let hpack = vec![0x82]; // :method: GET
        buffer.extend(build_test_headers_frame(1, &hpack));
        buffer.extend(frame_header);

        let result = parse_frames_stateful(&buffer, &mut state);
        assert!(
            matches!(result, Err(ParseError::Http2FrameSizeError)),
            "Frame exceeding default max_frame_size should be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_max_frame_size_respects_settings() {
        // After SETTINGS sets max_frame_size to 32768, a 20000-byte DATA frame should succeed
        let mut state = H2ConnectionState::new();

        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        // SETTINGS: max_frame_size (0x05) = 32768
        let settings_payload = [0x00u8, 0x05, 0x00, 0x00, 0x80, 0x00]; // id=5, value=32768
        let mut settings_frame = vec![
            0x00, 0x00, 0x06, // length = 6
            0x04, // type = SETTINGS
            0x00, // flags
            0x00, 0x00, 0x00, 0x00, // stream_id = 0
        ];
        settings_frame.extend_from_slice(&settings_payload);
        buffer.extend(settings_frame);

        // HEADERS with END_HEADERS only (body follows)
        let hpack = vec![0x82]; // :method: GET
        let hpack_len = hpack.len();
        let mut headers = vec![
            (hpack_len >> 16) as u8,
            (hpack_len >> 8) as u8,
            hpack_len as u8,
            0x01, // HEADERS
            0x04, // END_HEADERS only
            0x00,
            0x00,
            0x00,
            0x01,
        ];
        headers.extend(&hpack);
        buffer.extend(headers);

        // DATA frame with 20000 bytes
        let data_len: u32 = 20000;
        let mut data_frame = vec![
            (data_len >> 16) as u8,
            (data_len >> 8) as u8,
            data_len as u8,
            0x00, // DATA
            0x01, // END_STREAM
            0x00,
            0x00,
            0x00,
            0x01,
        ];
        data_frame.extend(vec![0x41u8; data_len as usize]);
        buffer.extend(data_frame);

        let result = parse_frames_stateful(&buffer, &mut state);
        assert!(
            result.is_ok(),
            "20000-byte frame should succeed with max_frame_size=32768: {result:?}"
        );

        let messages = result.unwrap();
        assert!(messages.contains_key(&1), "Stream 1 should complete");
        assert_eq!(messages[&1].body.len(), 20000, "Body should be 20000 bytes");
    }

    // =========================================================================
    // H4: CONTINUATION ordering validation
    // =========================================================================

    #[test]
    fn test_continuation_expected_but_got_data() {
        // HEADERS without END_HEADERS, then DATA on same stream — should be rejected
        let mut state = H2ConnectionState::new();
        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame());

        // HEADERS without END_HEADERS (flags=0x00)
        let hpack = vec![0x82]; // :method: GET
        let mut headers = vec![
            0x00,
            0x00,
            hpack.len() as u8,
            0x01, // HEADERS
            0x00, // No flags (no END_HEADERS, no END_STREAM)
            0x00,
            0x00,
            0x00,
            0x01, // stream 1
        ];
        headers.extend(&hpack);
        buffer.extend(headers);

        // DATA on stream 1 (should expect CONTINUATION instead)
        let data_frame = vec![
            0x00, 0x00, 0x05, // length 5
            0x00, // DATA
            0x01, // END_STREAM
            0x00, 0x00, 0x00, 0x01, // stream 1
            0x68, 0x65, 0x6c, 0x6c, 0x6f, // "hello"
        ];
        buffer.extend(data_frame);

        let result = parse_frames_stateful(&buffer, &mut state);
        assert!(
            matches!(result, Err(ParseError::Http2ContinuationExpected)),
            "DATA after HEADERS without END_HEADERS should trigger ContinuationExpected, got: {result:?}"
        );
    }

    #[test]
    fn test_continuation_wrong_stream_rejected() {
        // HEADERS without END_HEADERS on stream 1, then CONTINUATION on stream 3
        let mut state = H2ConnectionState::new();
        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame());

        // HEADERS without END_HEADERS on stream 1
        let hpack = vec![0x82]; // :method: GET
        let mut headers = vec![
            0x00,
            0x00,
            hpack.len() as u8,
            0x01, // HEADERS
            0x00, // No flags
            0x00,
            0x00,
            0x00,
            0x01, // stream 1
        ];
        headers.extend(&hpack);
        buffer.extend(headers);

        // CONTINUATION on stream 3 (wrong stream)
        let cont_payload = vec![0x84]; // :path: /
        let cont_frame = vec![
            0x00,
            0x00,
            cont_payload.len() as u8,
            0x09, // CONTINUATION
            0x04, // END_HEADERS
            0x00,
            0x00,
            0x00,
            0x03, // stream 3 (wrong!)
        ];
        buffer.extend(cont_frame);
        buffer.extend(cont_payload);

        let result = parse_frames_stateful(&buffer, &mut state);
        assert!(
            matches!(result, Err(ParseError::Http2ContinuationExpected)),
            "CONTINUATION on wrong stream should trigger ContinuationExpected, got: {result:?}"
        );
    }

    #[test]
    fn test_continuation_correct_ordering_succeeds() {
        // HEADERS without END_HEADERS, then CONTINUATION with END_HEADERS — should succeed
        let mut state = H2ConnectionState::new();
        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame());

        // HEADERS without END_HEADERS
        let hpack_part1 = vec![0x82]; // :method: GET
        let mut headers = vec![
            0x00,
            0x00,
            hpack_part1.len() as u8,
            0x01, // HEADERS
            0x01, // END_STREAM only (no END_HEADERS)
            0x00,
            0x00,
            0x00,
            0x01, // stream 1
        ];
        headers.extend(&hpack_part1);
        buffer.extend(headers);

        // CONTINUATION on same stream with END_HEADERS
        let hpack_part2 = vec![0x84]; // :path: /
        let mut cont = vec![
            0x00,
            0x00,
            hpack_part2.len() as u8,
            0x09, // CONTINUATION
            0x04, // END_HEADERS
            0x00,
            0x00,
            0x00,
            0x01, // stream 1
        ];
        cont.extend(&hpack_part2);
        buffer.extend(cont);

        let result = parse_frames_stateful(&buffer, &mut state);
        assert!(
            result.is_ok(),
            "Correct CONTINUATION ordering should succeed: {result:?}"
        );

        let messages = result.unwrap();
        assert!(
            messages.contains_key(&1),
            "Stream 1 should complete with HEADERS + CONTINUATION"
        );
    }

    // =========================================================================
    // H3: SETTINGS payload length validation
    // =========================================================================

    #[test]
    fn test_settings_payload_not_multiple_of_6() {
        // SETTINGS frame with 7-byte payload (not a multiple of 6)
        let mut state = H2ConnectionState::new();
        let mut buffer = frame::CONNECTION_PREFACE.to_vec();

        let settings_frame = vec![
            0x00, 0x00, 0x07, // length = 7
            0x04, // type = SETTINGS
            0x00, // flags
            0x00, 0x00, 0x00, 0x00, // stream_id = 0
            0x00, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, // 7 bytes (invalid)
        ];
        buffer.extend(settings_frame);

        let result = parse_frames_stateful(&buffer, &mut state);
        assert!(
            matches!(result, Err(ParseError::Http2SettingsLengthError)),
            "SETTINGS with 7-byte payload should trigger SettingsLengthError, got: {result:?}"
        );
    }

    #[test]
    fn test_settings_empty_payload_ack_succeeds() {
        // SETTINGS ACK has empty payload (0 % 6 == 0)
        let mut state = H2ConnectionState::new();
        let mut buffer = frame::CONNECTION_PREFACE.to_vec();
        buffer.extend_from_slice(&create_settings_frame()); // 0-length settings

        let result = parse_frames_stateful(&buffer, &mut state);
        assert!(
            result.is_ok(),
            "SETTINGS ACK (empty payload) should succeed: {result:?}"
        );
    }

    // =========================================================================
    // H5: into_ zero-copy variants
    // =========================================================================

    #[test]
    fn test_into_http_request() {
        let msg = ParsedH2Message {
            method: Some("GET".to_string()),
            path: Some("/foo".to_string()),
            authority: Some("example.com".to_string()),
            scheme: Some("https".to_string()),
            status: None,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            stream_id: 1,
            header_size: 100,
            body: vec![1, 2, 3],
            first_frame_timestamp_ns: 1000,
            end_stream_timestamp_ns: 2000,
        };

        let req = msg
            .into_http_request()
            .expect("should produce an HttpRequest");
        assert_eq!(req.method, http::Method::GET);
        assert_eq!(req.uri, "/foo");
        assert_eq!(req.body, vec![1, 2, 3]);
        assert_eq!(req.timestamp_ns, 2000);
    }

    #[test]
    fn test_into_http_response() {
        let msg = ParsedH2Message {
            method: None,
            path: None,
            authority: None,
            scheme: None,
            status: Some(200),
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            stream_id: 1,
            header_size: 50,
            body: vec![4, 5, 6],
            first_frame_timestamp_ns: 3000,
            end_stream_timestamp_ns: 4000,
        };

        let resp = msg
            .into_http_response()
            .expect("should produce an HttpResponse");
        assert_eq!(resp.status, http::StatusCode::OK);
        assert_eq!(resp.body, vec![4, 5, 6]);
        assert_eq!(resp.timestamp_ns, 3000);
    }

    #[test]
    fn test_into_http_request_returns_none_for_response() {
        let msg = ParsedH2Message {
            method: None,
            path: None,
            authority: None,
            scheme: None,
            status: Some(200),
            headers: vec![],
            stream_id: 1,
            header_size: 10,
            body: vec![],
            first_frame_timestamp_ns: 0,
            end_stream_timestamp_ns: 0,
        };

        assert!(msg.into_http_request().is_none());
    }

    // =========================================================================
    // C1: Per-key Mutex preserves HPACK state across concurrent same-key calls
    // =========================================================================

    #[test]
    fn test_per_key_mutex_preserves_hpack_state() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let cache = Arc::new(H2SessionCache::new());
        let key = "shared".to_string();
        let num_threads = 4;
        let barrier = Arc::new(Barrier::new(num_threads));

        // Pre-populate with preface + settings
        let mut init_buffer = frame::CONNECTION_PREFACE.to_vec();
        init_buffer.extend_from_slice(&create_settings_frame());
        let _ = cache.parse(key.clone(), &init_buffer);

        let handles: Vec<_> = (0..num_threads)
            .map(|i| {
                let cache = Arc::clone(&cache);
                let key = key.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait(); // Force overlapping access
                    let stream_id = (i * 2 + 1) as u32;
                    let hpack = vec![0x82]; // :method: GET
                    let frame = create_headers_frame(stream_id, &hpack);
                    let result = cache.parse(key, &frame);
                    assert!(result.is_ok(), "Thread {i} should succeed");
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("Thread should not panic");
        }

        // HPACK dynamic table should be preserved — parse another request
        let hpack = vec![0x82];
        let frame = create_headers_frame(99, &hpack);
        let result = cache.parse(key.clone(), &frame);
        assert!(
            result.is_ok(),
            "Post-concurrent parse should succeed with intact HPACK state"
        );
    }
}
