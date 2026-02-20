use std::collections::{HashMap, VecDeque};

/// Newtype for HTTP/2 stream identifiers (RFC 7540 §5.1.1: 31-bit unsigned
/// integer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub u32);

impl std::fmt::Display for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for StreamId {
    fn from(v: u32) -> Self {
        Self(v)
    }
}

impl From<StreamId> for u32 {
    fn from(v: StreamId) -> Self {
        v.0
    }
}

/// Newtype for nanosecond-precision timestamps (monotonic clock).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimestampNs(pub u64);

impl TimestampNs {
    /// Returns `self - other`, clamped to zero on underflow.
    pub fn saturating_sub(self, other: TimestampNs) -> u64 {
        self.0.saturating_sub(other.0)
    }
}

impl std::fmt::Display for TimestampNs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}ns", self.0)
    }
}

impl From<u64> for TimestampNs {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<TimestampNs> for u64 {
    fn from(v: TimestampNs) -> Self {
        v.0
    }
}

/// Configurable limits for HTTP/2 header decoding and stream management.
///
/// These limits defend against resource exhaustion from untrusted input
/// (e.g., HPACK decompression bombs, stream flooding).
#[derive(Debug, Clone)]
pub struct H2Limits {
    /// Maximum total decoded header list size in bytes (default: 65536, RFC
    /// 7540 default)
    pub max_header_list_size:   usize,
    /// Maximum number of headers per HEADERS block (default: 128)
    pub max_header_count:       usize,
    /// Maximum size of any individual header value in bytes (default: 8192)
    pub max_header_value_size:  usize,
    /// Hard cap for HPACK dynamic table size (default: 65536)
    pub max_table_size:         usize,
    /// Maximum concurrent active streams before rejecting new ones (default:
    /// 100)
    pub max_concurrent_streams: usize,
    /// Stream timeout in nanoseconds — streams older than this are evicted
    /// (default: 30s)
    pub stream_timeout_ns:      u64,
    /// Maximum accumulated body size per stream in bytes (default: 10 MiB).
    /// Streams exceeding this limit are dropped to prevent memory exhaustion.
    pub max_body_size:          usize,
    /// Maximum buffer size for incremental parsing in bytes.
    /// Rejects data that would grow the internal buffer beyond this limit.
    /// Default: 1 MiB. This bounds per-connection memory while allowing
    /// normal TCP read sizes and multi-frame chunks to be fed at once.
    pub max_buffer_size:        usize,
}

impl Default for H2Limits {
    fn default() -> Self {
        Self {
            max_header_list_size:   65536,
            max_header_count:       128,
            max_header_value_size:  8192,
            max_table_size:         65536,
            max_concurrent_streams: 100,
            stream_timeout_ns:      30_000_000_000,
            max_body_size:          10 * 1024 * 1024, // 10 MiB
            max_buffer_size:        1024 * 1024,      // 1 MiB
        }
    }
}

/// Connection-level HTTP/2 state
///
/// Maintains HPACK decoder state and active stream tracking for a single
/// HTTP/2 connection. Create one instance per direction (request/response)
/// when parsing bidirectional traffic.
///
/// Use `feed()` to incrementally add data with timestamps, and `try_pop()`
/// to retrieve completed messages.
pub struct H2ConnectionState {
    /// Persistent HPACK decoder with dynamic table
    pub(crate) decoder: loona_hpack::Decoder<'static>,

    /// Active streams being tracked
    pub(crate) active_streams: HashMap<StreamId, StreamState>,

    /// Connection settings (from SETTINGS frames)
    pub(crate) settings: H2Settings,

    /// Resource limits for header decoding and stream management
    pub(crate) limits: H2Limits,

    /// Whether the HTTP/2 connection preface (`PRI *
    /// HTTP/2.0\r\n\r\nSM\r\n\r\n`) has been received on this connection.
    pub preface_received: bool,

    /// Highest stream ID seen (for protocol validation)
    pub(crate) highest_stream_id: StreamId,

    /// Internal buffer for incremental parsing
    pub(crate) buffer: Vec<u8>,

    /// Stream ID expecting a CONTINUATION frame, or None if no CONTINUATION is
    /// pending. When a HEADERS frame arrives without END_HEADERS, this is
    /// set to the stream ID. Cleared when CONTINUATION with END_HEADERS
    /// arrives.
    pub(crate) expecting_continuation: Option<StreamId>,

    /// Completed messages ready to be popped, stored as (stream_id, message)
    pub(crate) completed: VecDeque<(StreamId, ParsedH2Message)>,

    /// Current timestamp for frame processing (set by feed())
    pub(crate) current_timestamp_ns: TimestampNs,
}

/// Phase of a stream's lifecycle (RFC 7540 §5.1).
///
/// Invariant: transitions only move forward through the variants:
///   ReceivingHeaders → ReceivingBody → Complete
///   ReceivingHeaders → Complete  (when END_STREAM arrives with HEADERS)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamPhase {
    /// HEADERS received but END_HEADERS not yet seen; CONTINUATION pending.
    /// `end_stream_seen` tracks whether END_STREAM was set on the HEADERS frame
    /// (the stream will complete once END_HEADERS arrives via CONTINUATION).
    ReceivingHeaders { end_stream_seen: bool },
    /// Headers complete (END_HEADERS seen), awaiting body DATA or END_STREAM.
    ReceivingBody,
    /// Both END_HEADERS and END_STREAM received; stream is complete.
    Complete,
}

/// Per-stream state (internal to crate)
pub(crate) struct StreamState {
    /// Accumulated headers (from HEADERS + CONTINUATION)
    pub(crate) headers: Vec<(String, String)>,

    /// Request pseudo-headers
    pub(crate) method:    Option<String>,
    pub(crate) path:      Option<String>,
    pub(crate) authority: Option<String>,
    pub(crate) scheme:    Option<String>,

    /// Response pseudo-header
    pub(crate) status: Option<u16>,

    /// Accumulated body from DATA frames
    pub(crate) body: Vec<u8>,

    /// Buffer for incomplete header blocks (CONTINUATION support)
    pub(crate) continuation_buffer: Vec<u8>,

    /// Total size of HEADERS frames
    pub(crate) header_size: usize,

    /// Lifecycle phase of this stream
    pub(crate) phase: StreamPhase,

    /// Timestamp when first frame for this stream was received
    pub(crate) first_frame_timestamp_ns: TimestampNs,

    /// Timestamp when END_STREAM was received
    pub(crate) end_stream_timestamp_ns: TimestampNs,
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
        let limits = H2Limits::default();
        let mut decoder = loona_hpack::Decoder::new();
        decoder.set_max_allowed_table_size(limits.max_table_size);
        Self {
            decoder,
            active_streams: HashMap::new(),
            settings: H2Settings::default(),
            limits,
            preface_received: false,
            highest_stream_id: StreamId(0),
            buffer: Vec::new(),
            expecting_continuation: None,
            completed: VecDeque::new(),
            current_timestamp_ns: TimestampNs(0),
        }
    }
}

impl H2ConnectionState {
    /// Create a connection state with default limits.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new H2ConnectionState with custom limits.
    pub fn with_limits(limits: H2Limits) -> Self {
        let mut decoder = loona_hpack::Decoder::new();
        decoder.set_max_allowed_table_size(limits.max_table_size);
        Self {
            decoder,
            active_streams: HashMap::new(),
            settings: H2Settings::default(),
            limits,
            preface_received: false,
            highest_stream_id: StreamId(0),
            buffer: Vec::new(),
            expecting_continuation: None,
            completed: VecDeque::new(),
            current_timestamp_ns: TimestampNs(0),
        }
    }

    /// Feed new data for incremental parsing with a timestamp.
    ///
    /// The timestamp is used to track when frames arrive for latency
    /// measurement. Call this method as data arrives, then use `try_pop()`
    /// to retrieve completed messages.
    ///
    /// Returns Ok(()) if data was processed (even if no messages completed
    /// yet). Returns Err only for fatal parse errors.
    pub fn feed(&mut self, data: &[u8], timestamp_ns: TimestampNs) -> Result<(), ParseError> {
        if self.buffer.len() + data.len() > self.limits.max_buffer_size {
            return Err(ParseError::new(ParseErrorKind::Http2BufferTooLarge));
        }
        self.buffer.extend_from_slice(data);
        self.current_timestamp_ns = timestamp_ns;
        crate::parse::parse_buffer_incremental(self)
    }

    /// Pop a completed message if available.
    ///
    /// Returns the stream_id and parsed message for a completed HTTP/2 stream.
    /// Messages are returned in the order they completed.
    pub fn try_pop(&mut self) -> Option<(StreamId, ParsedH2Message)> {
        self.completed.pop_front()
    }

    /// Check if any completed messages are ready to be popped.
    pub fn has_completed(&self) -> bool {
        !self.completed.is_empty()
    }

    /// Clear the internal buffer (e.g., when connection resets).
    /// Preserves HPACK decoder state for connection persistence.
    pub fn clear_buffer(&mut self) {
        self.buffer.clear();
    }

    /// Returns the number of active (incomplete) streams.
    pub fn active_stream_count(&self) -> usize {
        self.active_streams.len()
    }

    /// Evict stale streams that have exceeded the configured timeout.
    ///
    /// Removes streams whose first frame arrived more than `stream_timeout_ns`
    /// ago. If still over `max_concurrent_streams` after timeout eviction,
    /// removes the oldest streams by `first_frame_timestamp_ns`.
    ///
    /// **Safety invariant**: This only removes *incomplete* streams from
    /// `active_streams`. Complete streams are removed at parse time (via
    /// `check_stream_completion`) and moved to the `completed` queue before
    /// eviction runs. Messages already popped via `try_pop()` are fully owned
    /// by the caller and are unaffected by eviction.
    ///
    /// Callers should invoke this periodically (e.g., during cleanup or
    /// after each parsing pass) to bound memory usage from incomplete streams.
    pub fn evict_stale_streams(&mut self, current_time_ns: TimestampNs) {
        let timeout = self.limits.stream_timeout_ns;
        let max_streams = self.limits.max_concurrent_streams;

        // Evict streams that exceeded the timeout
        self.active_streams.retain(|_id, stream| {
            let stale = current_time_ns
                .0
                .saturating_sub(stream.first_frame_timestamp_ns.0)
                >= timeout;
            if stale {
                crate::trace_warn!("evicting stale stream {_id} (timeout)");
            }
            !stale
        });

        // If still over the limit, evict oldest streams
        while self.active_streams.len() > max_streams {
            let oldest_id = self
                .active_streams
                .iter()
                .min_by_key(|(_, s)| s.first_frame_timestamp_ns)
                .map(|(&id, _)| id);
            if let Some(id) = oldest_id {
                crate::trace_warn!("evicting stream {id} (over max_concurrent_streams)");
                self.active_streams.remove(&id);
            } else {
                break;
            }
        }
    }
}

impl StreamState {
    pub(crate) fn new(_stream_id: StreamId, timestamp_ns: TimestampNs) -> Self {
        Self {
            headers: Vec::new(),
            method: None,
            path: None,
            authority: None,
            scheme: None,
            status: None,
            body: Vec::new(),
            continuation_buffer: Vec::new(),
            header_size: 0,
            phase: StreamPhase::ReceivingHeaders {
                end_stream_seen: false,
            },
            first_frame_timestamp_ns: timestamp_ns,
            end_stream_timestamp_ns: TimestampNs(0),
        }
    }
}

/// A fully parsed HTTP/2 message extracted from a completed stream.
///
/// Contains pseudo-headers (`:method`, `:path`, `:status`, etc.), regular
/// headers, accumulated body data, and timing information. Use
/// [`is_request()`](Self::is_request) / [`is_response()`](Self::is_response)
/// to classify, or the `to_http_*` / `into_http_*` helpers to convert into
/// [`HttpRequest`](crate::HttpRequest) / [`HttpResponse`](crate::HttpResponse).
#[derive(Debug, Clone)]
pub struct ParsedH2Message {
    /// `:method` pseudo-header (present for requests)
    pub method: Option<String>,
    /// `:path` pseudo-header (present for requests)
    pub path: Option<String>,
    /// `:authority` pseudo-header (present for requests, mapped to `Host`)
    pub authority: Option<String>,
    /// `:scheme` pseudo-header (present for requests)
    pub scheme: Option<String>,
    /// `:status` pseudo-header (present for responses)
    pub status: Option<u16>,
    /// Decoded headers (both pseudo and regular, in wire order)
    pub headers: Vec<(String, String)>,
    /// HTTP/2 stream identifier
    pub stream_id: StreamId,
    /// Total decoded header size in bytes
    pub header_size: usize,
    /// Accumulated body from DATA frames
    pub body: Vec<u8>,
    /// Timestamp when first frame for this stream was received
    pub first_frame_timestamp_ns: TimestampNs,
    /// Timestamp when stream completed (END_STREAM received)
    pub end_stream_timestamp_ns: TimestampNs,
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
        if let Some(authority) = &self.authority
            && let Ok(v) = http::HeaderValue::from_str(authority)
        {
            header_map.insert(http::header::HOST, v);
        }

        // Convert regular headers (skip pseudo-headers)
        for (name, value) in &self.headers {
            if name.starts_with(':') {
                continue;
            }
            let parsed = (
                http::header::HeaderName::from_bytes(name.as_bytes()),
                http::HeaderValue::from_str(value),
            );
            if let (Ok(n), Ok(v)) = parsed {
                header_map.append(n, v);
            }
        }

        header_map
    }

    /// Convert this HTTP/2 message to an HttpRequest
    ///
    /// Returns None if this is not a valid request (missing :method or :path).
    /// Uses end_stream_timestamp_ns as the request timestamp (when request was
    /// fully sent).
    pub fn to_http_request(&self) -> Option<crate::HttpRequest> {
        Some(crate::HttpRequest {
            method:       self.http_method()?,
            uri:          self.http_uri()?,
            headers:      self.http_headers(),
            body:         self.body.clone(),
            timestamp_ns: self.end_stream_timestamp_ns,
            version:      None,
        })
    }

    /// Convert this HTTP/2 message to an HttpResponse
    ///
    /// Returns None if this is not a valid response (missing :status).
    /// Uses first_frame_timestamp_ns as the response timestamp (when response
    /// started arriving).
    pub fn to_http_response(&self) -> Option<crate::HttpResponse> {
        Some(crate::HttpResponse {
            status:       self.http_status()?,
            headers:      self.http_headers(),
            body:         self.body.clone(),
            timestamp_ns: self.first_frame_timestamp_ns,
            version:      None,
            reason:       None,
        })
    }

    /// Consume this message and convert to an HttpRequest (zero-copy for body).
    ///
    /// Returns None if this is not a valid request (missing :method or :path).
    pub fn into_http_request(self) -> Option<crate::HttpRequest> {
        let method = self.http_method()?;
        let uri = self.http_uri()?;
        let headers = self.http_headers();
        Some(crate::HttpRequest {
            method,
            uri,
            headers,
            body: self.body,
            timestamp_ns: self.end_stream_timestamp_ns,
            version: None,
        })
    }

    /// Consume this message and convert to an HttpResponse (zero-copy for
    /// body).
    ///
    /// Returns None if this is not a valid response (missing :status).
    pub fn into_http_response(self) -> Option<crate::HttpResponse> {
        let status = self.http_status()?;
        let headers = self.http_headers();
        Some(crate::HttpResponse {
            status,
            headers,
            body: self.body,
            timestamp_ns: self.first_frame_timestamp_ns,
            version: None,
            reason: None,
        })
    }
}

/// Classification of parse errors (public API)
#[derive(Debug, Clone)]
pub enum ParseErrorKind {
    /// Frame header requires 9 bytes but the buffer is shorter
    Http2BufferTooSmall,
    /// HPACK decompression failed (detail in the `String`)
    Http2HpackError(String),
    /// HEADERS block is split across CONTINUATION frames that have not all
    /// arrived yet
    Http2HeadersIncomplete,
    /// Decoded header list exceeds the configured size limit
    Http2HeaderListTooLarge,
    /// Request stream completed without a `:method` pseudo-header
    Http2NoMethod,
    /// Request stream completed without a `:path` pseudo-header
    Http2NoPath,
    /// Response stream completed without a `:status` pseudo-header
    Http2NoStatus,
    /// Frame could not be classified or has an invalid structure
    Http2InvalidFrame,
    /// Rejected because max concurrent streams limit was reached
    Http2MaxConcurrentStreams,
    /// Padded frame has missing or invalid padding
    Http2PaddingError,
    /// PRIORITY flag present but header block too short for priority fields
    Http2PriorityError,
    /// DATA or CONTINUATION frame references a stream that does not exist
    Http2StreamNotFound,
    /// Header contains invalid UTF-8 encoding
    Http2InvalidHeaderEncoding,
    /// Internal buffer would exceed the configured max_buffer_size
    Http2BufferTooLarge,
    /// Frame payload length exceeds the negotiated max_frame_size
    Http2FrameSizeError,
    /// Expected a CONTINUATION frame but received a different frame type or
    /// wrong stream
    Http2ContinuationExpected,
    /// SETTINGS frame payload length is not a multiple of 6 bytes
    Http2SettingsLengthError,
}

impl std::fmt::Display for ParseErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http2BufferTooSmall => write!(f, "HTTP/2 buffer too small to parse frame header"),
            Self::Http2HpackError(msg) => write!(f, "HTTP/2 HPACK decoding error: {msg}"),
            Self::Http2HeadersIncomplete => {
                write!(f, "HTTP/2 headers incomplete (missing CONTINUATION)")
            },
            Self::Http2HeaderListTooLarge => write!(f, "HTTP/2 header list exceeds size limits"),
            Self::Http2NoMethod => write!(f, "HTTP/2 request missing :method pseudo-header"),
            Self::Http2NoPath => write!(f, "HTTP/2 request missing :path pseudo-header"),
            Self::Http2NoStatus => write!(f, "HTTP/2 response missing :status pseudo-header"),
            Self::Http2InvalidFrame => write!(f, "HTTP/2 invalid frame"),
            Self::Http2MaxConcurrentStreams => {
                write!(f, "HTTP/2 max concurrent streams limit reached")
            },
            Self::Http2PaddingError => write!(f, "HTTP/2 frame has missing or invalid padding"),
            Self::Http2PriorityError => {
                write!(f, "HTTP/2 PRIORITY flag present but header block too short")
            },
            Self::Http2StreamNotFound => write!(f, "HTTP/2 frame references unknown stream"),
            Self::Http2InvalidHeaderEncoding => {
                write!(f, "HTTP/2 header contains invalid UTF-8 encoding")
            },
            Self::Http2BufferTooLarge => {
                write!(f, "HTTP/2 internal buffer exceeds max_buffer_size")
            },
            Self::Http2FrameSizeError => {
                write!(f, "HTTP/2 frame payload exceeds negotiated max_frame_size")
            },
            Self::Http2ContinuationExpected => {
                write!(
                    f,
                    "HTTP/2 expected CONTINUATION frame but received different frame type or \
                     stream"
                )
            },
            Self::Http2SettingsLengthError => {
                write!(
                    f,
                    "HTTP/2 SETTINGS frame payload is not a multiple of 6 bytes"
                )
            },
        }
    }
}

/// Parse error with optional stream context (public API)
#[derive(Debug, Clone)]
pub struct ParseError {
    /// What went wrong
    pub kind:      ParseErrorKind,
    /// The stream that caused the error, if applicable
    pub stream_id: Option<StreamId>,
}

impl ParseError {
    /// Create a connection-level parse error (no specific stream).
    pub fn new(kind: ParseErrorKind) -> Self {
        Self {
            kind,
            stream_id: None,
        }
    }

    /// Create a stream-level parse error with the offending stream ID.
    pub fn with_stream(kind: ParseErrorKind, stream_id: StreamId) -> Self {
        Self {
            kind,
            stream_id: Some(stream_id),
        }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(sid) = self.stream_id {
            write!(f, "[stream {sid}] {}", self.kind)
        } else {
            write!(f, "{}", self.kind)
        }
    }
}

impl std::error::Error for ParseError {}
