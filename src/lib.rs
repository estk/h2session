// HTTP/2 session management crate
// Provides connection-level state tracking for HTTP/2 parsing

mod frame;
mod parse;
mod state;

// Public re-exports for direct state management
use dashmap::DashMap;
pub use frame::{is_http2_preface, looks_like_http2_frame, CONNECTION_PREFACE};
pub use parse::parse_frames_stateful;
pub use state::{H2ConnectionState, ParseError, ParsedH2Message};
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
    /// Returns completed HTTP/2 messages indexed by stream_id (may be empty if
    /// parsing incomplete).
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

        // This should create state but return error (no complete messages)
        let _ = cache.parse(key.clone(), &buffer);

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
        assert!(result.is_ok() || matches!(result, Err(ParseError::Http2BufferTooSmall)));
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
        assert!(result.is_ok() || matches!(result, Err(ParseError::Http2BufferTooSmall)));
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
}
