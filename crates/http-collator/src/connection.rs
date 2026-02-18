//! Connection state tracking for HTTP collation

use crate::h1::{HttpRequest, HttpResponse};
use crate::traits::Direction;
use h2session::{H2ConnectionState, ParsedH2Message};
use std::collections::{HashMap, HashSet};

/// Protocol detected for a connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Unknown,
    Http1,
    Http2,
}

/// A chunk of data received from a data source
#[derive(Debug, Clone)]
pub struct DataChunk {
    pub data: Vec<u8>,
    pub timestamp_ns: u64,
    pub direction: Direction,
}

/// Tracks state for a single connection
pub struct Connection {
    pub process_id: u32,
    /// Remote port, None if unavailable (e.g., SSL without socket fd)
    pub remote_port: Option<u16>,
    pub protocol: Protocol,
    pub request_chunks: Vec<DataChunk>,
    pub response_chunks: Vec<DataChunk>,
    pub last_activity_ns: u64,
    pub request_complete: bool,
    pub response_complete: bool,

    // HTTP/1 growable buffers — new data is appended as it arrives, avoiding
    // repeated clone-and-concatenate of all previous chunks.
    pub(crate) h1_request_buffer: Vec<u8>,
    pub(crate) h1_response_buffer: Vec<u8>,

    // Accumulated body size per direction for enforcing max_body_size limit
    pub(crate) request_body_size: usize,
    pub(crate) response_body_size: usize,

    // HTTP/1 parsed messages (when complete)
    pub(crate) h1_request: Option<HttpRequest>,
    pub(crate) h1_response: Option<HttpResponse>,

    // HTTP/1 emission tracking - have we already emitted Message events for these?
    pub(crate) h1_request_emitted: bool,
    pub(crate) h1_response_emitted: bool,

    // HTTP/2 state: separate parsers per direction to avoid corrupting
    // frame boundaries when Read and Write events interleave.
    pub(crate) h2_write_state: H2ConnectionState,
    pub(crate) h2_read_state: H2ConnectionState,

    // Completed messages from h2session, keyed by stream_id
    pub(crate) pending_requests: HashMap<u32, ParsedH2Message>,
    pub(crate) pending_responses: HashMap<u32, ParsedH2Message>,

    // HTTP/2 emission tracking - which stream_ids have we emitted Message events for?
    pub(crate) h2_emitted_requests: HashSet<u32>,
    pub(crate) h2_emitted_responses: HashSet<u32>,

    // Stream IDs that have both a pending request and pending response,
    // enabling O(1) lookup for complete exchange pairs.
    pub(crate) ready_streams: HashSet<u32>,
}

impl Connection {
    pub fn new(process_id: u32, remote_port: u16) -> Self {
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
            last_activity_ns: 0,
            request_complete: false,
            response_complete: false,
            h1_request_buffer: Vec::new(),
            h1_response_buffer: Vec::new(),
            request_body_size: 0,
            response_body_size: 0,
            h1_request: None,
            h1_response: None,
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
