// HTTP/2 session management crate
// Provides connection-level state tracking for HTTP/2 parsing

mod frame;
mod http_types;
mod parse;
mod state;

// Public re-exports for direct state management
use dashmap::DashMap;
pub use frame::{CONNECTION_PREFACE, is_http2_preface, looks_like_http2_frame};
pub use http_types::{HttpRequest, HttpResponse};
pub use parse::parse_frames_stateful;
pub use state::{H2ConnectionState, H2Limits, ParseError, ParsedH2Message};
use std::collections::HashMap;
use std::hash::Hash;

/// HTTP/2 session cache with generic connection keys
pub struct H2SessionCache<K> {
    connections: DashMap<K, H2ConnectionState>,
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
        // Get or create connection state
        let mut state_ref = self.connections.entry(key).or_default();

        // Parse with state
        parse_frames_stateful(buffer, state_ref.value_mut())
    }

    /// Remove connection state (call when connection closes)
    pub fn remove(&self, key: &K) -> Option<H2ConnectionState> {
        self.connections.remove(key).map(|(_, v)| v)
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
        assert!(result.is_ok(), "Invalid UTF-8 should be non-fatal");
        // Stream should not complete because invalid header set limit_exceeded
        assert!(
            state.try_pop().is_none(),
            "Stream with invalid UTF-8 header should not complete"
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
}
