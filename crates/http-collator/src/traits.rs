//! Traits for abstracting data event sources
//!
//! These traits allow the collator to work with any data source that provides
//! the necessary information about network traffic direction and payload.

/// Direction of data flow for a network event
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Response data (inbound from server)
    Read,
    /// Request data (outbound to server)
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
}
