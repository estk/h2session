use std::collections::HashMap;

/// Connection-level HTTP/2 state
///
/// Maintains HPACK decoder state and active stream tracking for a single
/// HTTP/2 connection. Create one instance per direction (request/response)
/// when parsing bidirectional traffic.
pub struct H2ConnectionState {
    /// Persistent HPACK decoder with dynamic table
    pub(crate) decoder: loona_hpack::Decoder<'static>,

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

impl Default for H2ConnectionState {
    fn default() -> Self {
        Self {
            decoder: loona_hpack::Decoder::new(),
            active_streams: HashMap::new(),
            settings: H2Settings::default(),
            preface_received: false,
            highest_stream_id: 0,
        }
    }
}

impl H2ConnectionState {
    pub fn new() -> Self {
        Self::default()
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

impl ParsedH2Message {
    /// Returns true if this message is a request (has :method pseudo-header)
    pub fn is_request(&self) -> bool {
        self.method.is_some()
    }

    /// Returns true if this message is a response (has :status pseudo-header)
    pub fn is_response(&self) -> bool {
        self.status.is_some()
    }

    /// Convert :method pseudo-header to http::Method
    pub fn http_method(&self) -> Option<http::Method> {
        self.method
            .as_ref()
            .and_then(|m| http::Method::from_bytes(m.as_bytes()).ok())
    }

    /// Convert :path pseudo-header to http::Uri (defaults to "/" if missing)
    pub fn http_uri(&self) -> Option<http::Uri> {
        let path = self.path.as_deref().unwrap_or("/");
        path.parse().ok()
    }

    /// Convert :status pseudo-header to http::StatusCode
    pub fn http_status(&self) -> Option<http::StatusCode> {
        self.status.and_then(|s| http::StatusCode::from_u16(s).ok())
    }

    /// Convert headers to http::HeaderMap, including :authority as Host header
    pub fn http_headers(&self) -> http::HeaderMap {
        let mut header_map = http::HeaderMap::new();

        // Convert :authority to Host header
        if let Some(authority) = &self.authority {
            if let Ok(v) = http::HeaderValue::from_str(authority) {
                header_map.insert(http::header::HOST, v);
            }
        }

        // Convert regular headers (skip pseudo-headers)
        for (name, value) in &self.headers {
            if name.starts_with(':') {
                continue;
            }
            if let (Ok(n), Ok(v)) = (
                http::header::HeaderName::from_bytes(name.as_bytes()),
                http::HeaderValue::from_str(value),
            ) {
                header_map.insert(n, v);
            }
        }

        header_map
    }
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
