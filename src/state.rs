use std::collections::HashMap;

/// Connection-level HTTP/2 state (internal to crate)
pub(crate) struct H2ConnectionState {
    /// Persistent HPACK decoder with dynamic table
    pub(crate) decoder: hpack::Decoder<'static>,

    /// Active streams being tracked
    pub(crate) active_streams: HashMap<u32, StreamState>,

    /// Connection settings (from SETTINGS frames)
    pub(crate) settings: H2Settings,

    /// Whether the connection preface has been seen
    pub(crate) preface_received: bool,

    /// Highest stream ID seen (for protocol validation)
    pub(crate) highest_stream_id: u32,
}

/// Per-stream state (internal to crate)
pub(crate) struct StreamState {
    pub(crate) stream_id: u32,

    /// Accumulated headers (from HEADERS + CONTINUATION)
    pub(crate) headers: Vec<(String, String)>,

    /// Request pseudo-headers
    pub(crate) method: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) authority: Option<String>,
    pub(crate) scheme: Option<String>,

    /// Response pseudo-header
    pub(crate) status: Option<u16>,

    /// Accumulated body from DATA frames
    pub(crate) body: Vec<u8>,

    /// Buffer for incomplete header blocks (CONTINUATION support)
    pub(crate) continuation_buffer: Vec<u8>,

    /// Total size of HEADERS frames
    pub(crate) header_size: usize,

    /// Flags
    pub(crate) end_stream_seen: bool,
    pub(crate) end_headers_seen: bool,
}

/// HTTP/2 connection settings (internal to crate)
#[derive(Clone)]
pub(crate) struct H2Settings {
    pub(crate) header_table_size: u32,
    pub(crate) enable_push: bool,
    pub(crate) max_concurrent_streams: u32,
    pub(crate) initial_window_size: u32,
    pub(crate) max_frame_size: u32,
    pub(crate) max_header_list_size: u32,
}

impl Default for H2Settings {
    fn default() -> Self {
        Self {
            header_table_size: 4096,
            enable_push: true,
            max_concurrent_streams: u32::MAX,
            initial_window_size: 65535,
            max_frame_size: 16384,
            max_header_list_size: u32::MAX,
        }
    }
}

impl H2ConnectionState {
    pub fn new() -> Self {
        Self {
            decoder: hpack::Decoder::new(),
            active_streams: HashMap::new(),
            settings: H2Settings::default(),
            preface_received: false,
            highest_stream_id: 0,
        }
    }
}

impl StreamState {
    pub(crate) fn new(stream_id: u32) -> Self {
        Self {
            stream_id,
            headers: Vec::new(),
            method: None,
            path: None,
            authority: None,
            scheme: None,
            status: None,
            body: Vec::new(),
            continuation_buffer: Vec::new(),
            header_size: 0,
            end_stream_seen: false,
            end_headers_seen: false,
        }
    }
}

/// Parsed HTTP/2 message (public API)
#[derive(Debug, Clone)]
pub struct ParsedH2Message {
    pub method: Option<String>,
    pub path: Option<String>,
    pub authority: Option<String>,
    pub scheme: Option<String>,
    pub status: Option<u16>,
    pub headers: Vec<(String, String)>,
    pub stream_id: u32,
    pub header_size: usize,
    pub body: Vec<u8>,
}

/// Error type for parsing (public API)
#[derive(Debug, Clone)]
pub enum ParseError {
    Http2BufferTooSmall,
    Http2HpackError(String),
    Http2HeadersIncomplete,
    Http2NoMethod,
    Http2NoPath,
    Http2NoStatus,
    Http2InvalidFrame,
}
