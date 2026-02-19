#![warn(missing_docs)]
//! Stateful HTTP/2 frame parser with HPACK support for passive traffic
//! monitoring.
//!
//! This crate decodes HTTP/2 frames and HPACK-compressed headers from raw
//! byte streams, maintaining per-connection decoder state so that dynamic
//! table entries are preserved across successive `feed()` calls.
//!
//! # Key types
//!
//! - [`H2SessionCache`] — thread-safe cache of many connections keyed by an
//!   arbitrary `K`. Best when you have many connections and want automatic
//!   state management.
//! - [`H2ConnectionState`] — state for a single HTTP/2 connection. Use
//!   [`feed()`](H2ConnectionState::feed) to push data incrementally and
//!   [`try_pop()`](H2ConnectionState::try_pop) to retrieve completed messages.
//!
//! # Examples
//!
//! ## Multi-connection cache
//!
//! ```no_run
//! use h2session::{H2SessionCache, ParsedH2Message};
//!
//! let cache = H2SessionCache::<u64>::new();
//!
//! // Parse a buffer for connection 42
//! let completed = cache.parse(42, &raw_bytes).unwrap();
//! for (stream_id, msg) in &completed {
//!     if msg.is_request() {
//!         println!(
//!             "{} {}",
//!             msg.method.as_deref().unwrap_or("?"),
//!             msg.path.as_deref().unwrap_or("/")
//!         );
//!     }
//! }
//! # let raw_bytes: Vec<u8> = vec![];
//! ```
//!
//! ## Single-connection incremental parsing
//!
//! ```no_run
//! use h2session::{H2ConnectionState, TimestampNs};
//!
//! let mut state = H2ConnectionState::new();
//!
//! // Feed data as it arrives
//! state.feed(&chunk, TimestampNs(0)).unwrap();
//!
//! // Pop completed messages
//! while let Some((stream_id, msg)) = state.try_pop() {
//!     println!("stream {stream_id}: request={}", msg.is_request());
//! }
//! # let chunk: Vec<u8> = vec![];
//! ```
//!
//! # Feature flags
//!
//! - **`tracing`** — emit `tracing::warn!` events for non-fatal parse issues
//!   (stale stream eviction, etc.)

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
use std::{collections::HashMap, hash::Hash, sync::Mutex};

// Public re-exports for direct state management
use dashmap::DashMap;
pub use frame::{CONNECTION_PREFACE, is_http2_preface, looks_like_http2_frame};
pub use http_types::{HttpRequest, HttpResponse};
pub use state::{
    H2ConnectionState,
    H2Limits,
    ParseError,
    ParseErrorKind,
    ParsedH2Message,
    StreamId,
    TimestampNs,
};
pub(crate) use trace_warn;

/// HTTP/2 session cache with generic connection keys.
///
/// Uses `DashMap<K, Mutex<H2ConnectionState>>` to provide per-key
/// serialization. The DashMap shard lock is held only briefly (to look up or
/// insert the entry), while the per-key Mutex serializes concurrent same-key
/// calls to `parse()`. This prevents the remove-and-reinsert race where two
/// threads would both create default state for the same key, losing one
/// thread's HPACK table.
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
