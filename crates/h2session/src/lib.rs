// HTTP/2 session management crate
// Provides connection-level state tracking for HTTP/2 parsing

mod frame;
mod http_types;
mod parse;
mod state;

#[cfg(test)]
mod tests;

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
pub use state::{
    H2ConnectionState, H2Limits, ParseError, ParseErrorKind, ParsedH2Message, StreamId, TimestampNs,
};
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
    ) -> Result<HashMap<StreamId, ParsedH2Message>, ParseError> {
        // Atomic insert-if-absent
        self.connections
            .entry(key.clone())
            .or_insert_with(|| Mutex::new(H2ConnectionState::default()));

        // Get shared shard read lock + per-key mutex lock
        let entry = self.connections.get(&key).expect("entry was just ensured");
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
