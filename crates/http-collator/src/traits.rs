//! Traits for abstracting data event sources
//!
//! These traits allow the collator to work with any data source that provides
//! the necessary information about network traffic direction and payload.

use bytes::Bytes;

/// Direction of data flow for a network event.
///
/// `Read` and `Write` correspond to the socket operation (recv/send) observed
/// by the tracing layer. Whether Read or Write carries requests vs. responses
/// depends on the vantage point: on a client, Write = outgoing requests and
/// Read = incoming responses; on a server the mapping is reversed. The
/// collator classifies messages by inspecting content (pseudo-headers), not
/// by assuming a fixed direction-to-role mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Data received via a socket read (recv) operation
    Read,
    /// Data sent via a socket write (send) operation
    Write,
    /// Non-data events (ignored by collator)
    Other,
}

/// Trait for data events that can be collated into HTTP exchanges.
///
/// Implement this trait for your data source (e.g., eBPF events, pcap packets)
/// to enable HTTP collation.
pub trait DataEvent {
    /// The raw payload bytes of this event
    fn payload(&self) -> &[u8];

    /// Timestamp in nanoseconds (monotonic, for latency calculation)
    fn timestamp_ns(&self) -> u64;

    /// Direction of the data flow
    fn direction(&self) -> Direction;

    /// Connection identifier (0 if unavailable, falls back to process_id)
    fn connection_id(&self) -> u64;

    /// Process ID for connection tracking
    fn process_id(&self) -> u32;

    /// Remote port (0 if unknown)
    fn remote_port(&self) -> u16;

    /// Consume self and return the payload as `Bytes`.
    ///
    /// The default implementation copies via `payload().to_vec()`. Implementors
    /// that already own a `Bytes` (or `Vec<u8>`) should override this to avoid
    /// the copy.
    fn into_payload(self) -> Bytes
    where
        Self: Sized,
    {
        Bytes::from(self.payload().to_vec())
    }
}
