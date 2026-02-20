//! Connection state tracking for HTTP collation

use std::collections::{HashMap, HashSet};

use bytes::Bytes;
use h2session::{H2ConnectionState, ParsedH2Message, StreamId, TimestampNs};

use crate::{
    h1::{HttpRequest, HttpResponse},
    traits::Direction,
};

/// Protocol detected for a connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// Protocol has not been identified yet
    Unknown,
    /// HTTP/1.x (HTTP/1.0 or HTTP/1.1)
    Http1,
    /// HTTP/2
    Http2,
}

/// A chunk of data received from a data source
#[derive(Debug, Clone)]
pub(crate) struct DataChunk {
    pub(crate) data:         Bytes,
    pub(crate) timestamp_ns: TimestampNs,
    #[allow(dead_code)]
    pub(crate) direction:    Direction,
}

/// Tracks state for a single connection
pub(crate) struct Connection {
    pub(crate) process_id:        u32,
    /// Remote port, None if unavailable (e.g., SSL without socket fd)
    pub(crate) remote_port:       Option<u16>,
    pub(crate) protocol:          Protocol,
    pub(crate) request_chunks:    Vec<DataChunk>,
    pub(crate) response_chunks:   Vec<DataChunk>,
    pub(crate) last_activity_ns:  TimestampNs,
    pub(crate) request_complete:  bool,
    pub(crate) response_complete: bool,

    // HTTP/1 growable buffers — new data is appended as it arrives, avoiding
    // repeated clone-and-concatenate of all previous chunks.
    pub(crate) h1_write_buffer: Vec<u8>,
    pub(crate) h1_read_buffer:  Vec<u8>,

    // Accumulated body size per direction for enforcing max_body_size limit
    pub(crate) request_body_size:  usize,
    pub(crate) response_body_size: usize,

    // HTTP/1 parsed messages (when complete)
    pub(crate) h1_request:  Option<HttpRequest>,
    pub(crate) h1_response: Option<HttpResponse>,

    // HTTP/1 per-direction parse tracking — have we extracted a message from
    // this direction's buffer? Prevents redundant re-parsing on subsequent chunks.
    pub(crate) h1_write_parsed: bool,
    pub(crate) h1_read_parsed:  bool,

    // HTTP/1 emission tracking - have we already emitted Message events for these?
    pub(crate) h1_request_emitted:  bool,
    pub(crate) h1_response_emitted: bool,

    // HTTP/2 state: separate parsers per direction to avoid corrupting
    // frame boundaries when Read and Write events interleave.
    pub(crate) h2_write_state: H2ConnectionState,
    pub(crate) h2_read_state:  H2ConnectionState,

    // Completed messages from h2session, keyed by stream_id
    pub(crate) pending_requests:  HashMap<StreamId, ParsedH2Message>,
    pub(crate) pending_responses: HashMap<StreamId, ParsedH2Message>,

    // HTTP/2 emission tracking - which stream_ids have we emitted Message events for?
    pub(crate) h2_emitted_requests:  HashSet<StreamId>,
    pub(crate) h2_emitted_responses: HashSet<StreamId>,

    // Stream IDs that have both a pending request and pending response,
    // enabling O(1) lookup for complete exchange pairs.
    pub(crate) ready_streams: HashSet<StreamId>,
}

impl Connection {
    pub(crate) fn new(process_id: u32, remote_port: u16) -> Self {
        Self {
            process_id,
            // Store None for port 0 (unavailable from SSL)
            remote_port: if remote_port == 0 {
                None
            } else {
                Some(remote_port)
            },
            protocol: Protocol::Unknown,
            request_chunks: Vec::new(),
            response_chunks: Vec::new(),
            last_activity_ns: TimestampNs(0),
            request_complete: false,
            response_complete: false,
            h1_write_buffer: Vec::new(),
            h1_read_buffer: Vec::new(),
            request_body_size: 0,
            response_body_size: 0,
            h1_request: None,
            h1_response: None,
            h1_write_parsed: false,
            h1_read_parsed: false,
            h1_request_emitted: false,
            h1_response_emitted: false,
            h2_write_state: H2ConnectionState::new(),
            h2_read_state: H2ConnectionState::new(),
            pending_requests: HashMap::new(),
            pending_responses: HashMap::new(),
            h2_emitted_requests: HashSet::new(),
            h2_emitted_responses: HashSet::new(),
            ready_streams: HashSet::new(),
        }
    }
}
