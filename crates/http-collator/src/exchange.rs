//! HTTP exchange (request/response pair) and collation events

use h2session::{StreamId, TimestampNs};

use crate::{
    connection::Protocol,
    h1::{HttpRequest, HttpResponse},
    traits::Direction,
};

/// Classification of parsed HTTP message
#[derive(Debug, Clone)]
pub enum ParsedHttpMessage {
    /// A parsed HTTP request
    Request(HttpRequest),
    /// A parsed HTTP response
    Response(HttpResponse),
}

impl ParsedHttpMessage {
    /// Returns true if this is a request
    pub fn is_request(&self) -> bool {
        matches!(self, Self::Request(_))
    }

    /// Returns true if this is a response
    pub fn is_response(&self) -> bool {
        matches!(self, Self::Response(_))
    }

    /// Get the request if this is a request, None otherwise
    pub fn as_request(&self) -> Option<&HttpRequest> {
        match self {
            Self::Request(req) => Some(req),
            Self::Response(_) => None,
        }
    }

    /// Get the response if this is a response, None otherwise
    pub fn as_response(&self) -> Option<&HttpResponse> {
        match self {
            Self::Request(_) => None,
            Self::Response(resp) => Some(resp),
        }
    }
}

/// Metadata about a parsed message
#[derive(Debug, Clone)]
pub struct MessageMetadata {
    /// Connection identifier (0 if unavailable, falls back to process_id)
    pub connection_id: u128,
    /// Process ID for connection tracking
    pub process_id:    u32,
    /// Process/command name
    pub command:       String,
    /// Timestamp in nanoseconds
    pub timestamp_ns:  TimestampNs,
    /// Stream ID for HTTP/2 (None for HTTP/1)
    pub stream_id:     Option<StreamId>,
    /// Remote port (None if unavailable)
    pub remote_port:   Option<u16>,
    /// Local port (None if unavailable)
    pub local_port:    Option<u16>,
    /// Protocol detected for this connection
    pub protocol:      Protocol,
    /// Socket direction this message was observed on: `Read` = received
    /// (recv), `Write` = sent (send). For a proxy vantage point a request
    /// observed on `Read` is ingress (client → proxy), on `Write` is egress
    /// (proxy → backend); a response travels the opposite leg. `None` when
    /// the source does not report a direction (e.g. HTTP/3).
    pub direction:     Option<Direction>,
}

/// Events emitted by the collator
#[derive(Debug)]
pub enum CollationEvent {
    /// Individual message parsed and ready for processing
    Message {
        /// The parsed HTTP message (request or response)
        message:  ParsedHttpMessage,
        /// Connection and timing metadata for this message
        metadata: MessageMetadata,
    },
    /// Complete exchange with latency (request + response matched)
    Exchange(Exchange),
}

impl CollationEvent {
    /// Returns true if this is a Message event
    pub fn is_message(&self) -> bool {
        matches!(self, Self::Message { .. })
    }

    /// Returns true if this is an Exchange event
    pub fn is_exchange(&self) -> bool {
        matches!(self, Self::Exchange(_))
    }

    /// Get the message if this is a Message event
    pub fn as_message(&self) -> Option<(&ParsedHttpMessage, &MessageMetadata)> {
        match self {
            Self::Message { message, metadata } => Some((message, metadata)),
            Self::Exchange(_) => None,
        }
    }

    /// Get the exchange if this is an Exchange event
    pub fn as_exchange(&self) -> Option<&Exchange> {
        match self {
            Self::Message { .. } => None,
            Self::Exchange(ex) => Some(ex),
        }
    }
}

/// Configuration for what the collator emits
#[derive(Debug, Clone)]
pub struct CollatorConfig {
    /// Emit Message events when individual requests/responses are parsed
    pub emit_messages:  bool,
    /// Emit Exchange events when request/response pairs complete
    pub emit_exchanges: bool,
    /// Maximum buffer size per chunk
    pub max_buf_size:   usize,
    /// Connection timeout for cleanup in nanoseconds
    pub timeout_ns:     u64,
    /// Maximum accumulated body size per direction before the connection is
    /// reset. Prevents unbounded memory growth from stalled or malicious
    /// connections. Default: 10 MiB.
    pub max_body_size:  usize,
}

impl Default for CollatorConfig {
    fn default() -> Self {
        Self {
            emit_messages:  true,
            emit_exchanges: true,
            max_buf_size:   16384,
            timeout_ns:     5_000_000_000,
            max_body_size:  10 * 1024 * 1024, // 10 MiB
        }
    }
}

impl CollatorConfig {
    /// Create config that only emits messages (for immediate adjudication)
    pub fn messages_only() -> Self {
        Self {
            emit_messages: true,
            emit_exchanges: false,
            ..Default::default()
        }
    }

    /// Create config that only emits exchanges (for monitoring/APM)
    pub fn exchanges_only() -> Self {
        Self {
            emit_messages: false,
            emit_exchanges: true,
            ..Default::default()
        }
    }
}

/// A complete request/response exchange
#[derive(Debug, Clone)]
pub struct Exchange {
    /// The HTTP request
    pub request:        HttpRequest,
    /// The matched HTTP response
    pub response:       HttpResponse,
    /// Metadata captured when the request leg was parsed (connection id,
    /// process/command, ports, protocol, stream id, and the socket direction
    /// the request was observed on). Connection-level fields (process, ports,
    /// protocol) are identical across both legs; `direction` and `timestamp_ns`
    /// are per-leg.
    pub request_meta:   MessageMetadata,
    /// Metadata captured when the response leg was parsed. Carries the
    /// response's own `timestamp_ns` and `direction` (the opposite socket leg
    /// from the request); other fields mirror `request_meta`.
    pub response_meta:  MessageMetadata,
    /// Time between request completion and response start, in nanoseconds
    pub latency_ns:     u64,
    /// Thread ID (TID/LWP) that handled this connection
    pub thread_id:      u32,
    /// Socket file descriptor (-1 if unavailable)
    pub fd:             i32,
    /// Opaque metadata from the data source, propagated for proxy correlation
    pub proxy_metadata: u64,
    /// Stable xxhash3-64 fingerprint of canonicalised request headers
    /// (method, :path, :authority, non-excluded headers; see
    /// `crate::fingerprint::compute_request_fingerprint`). Set at
    /// construction; `None` only for hand-built test fixtures. Used by
    /// the `fifo-fingerprint` correlator to pair ingress↔egress across
    /// HTTP/2 proxy hops where stream IDs are renumbered.
    pub request_fingerprint: Option<u64>,
}

impl Exchange {
    /// Direction the request leg arrived on, relative to the monitored
    /// process: `Read` = the request was received (server/proxy ingress),
    /// `Write` = the request was sent (proxy egress). `None` for hand-built
    /// fixtures, HTTP/3, or sources that don't set it.
    ///
    /// Captured by the collator at the point the request is parsed — it is
    /// **not** recoverable from the assembled exchange, because chunk routing
    /// is by client-convention and a request can be content-parsed from
    /// either direction (see `lib.rs` request routing).
    pub fn request_direction(&self) -> Option<Direction> {
        self.request_meta.direction
    }

    /// Protocol detected for this connection. Connection-level — identical on
    /// both legs; sourced from the request leg.
    pub fn protocol(&self) -> Protocol {
        self.request_meta.protocol
    }

    /// OS process ID that handled this connection. Connection-level.
    pub fn process_id(&self) -> u32 {
        self.request_meta.process_id
    }

    /// Process/command name. Connection-level.
    pub fn command(&self) -> &str {
        &self.request_meta.command
    }

    /// Remote port, `None` if unavailable (e.g. SSL without socket fd).
    /// Connection-level.
    pub fn remote_port(&self) -> Option<u16> {
        self.request_meta.remote_port
    }

    /// Local port, `None` if unavailable. Connection-level.
    pub fn local_port(&self) -> Option<u16> {
        self.request_meta.local_port
    }

    /// Stream ID for HTTP/2 (`None` for HTTP/1). Request and response share the
    /// same stream id within an exchange.
    pub fn stream_id(&self) -> Option<StreamId> {
        self.request_meta.stream_id
    }
}

impl std::fmt::Display for Exchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let proto_str = match self.protocol() {
            Protocol::Http1 => "HTTP/1.1",
            Protocol::Http2 => "HTTP/2",
            Protocol::Http3 => "HTTP/3",
            Protocol::Unknown => "Unknown",
        };
        let latency_ms = self.latency_ns as f64 / 1_000_000.0;
        let port_str = self
            .remote_port()
            .map_or("unavailable".to_string(), |p| p.to_string());

        writeln!(
            f,
            "=== {} Exchange (PID: {}, Command: {}, Port: {}) ===",
            proto_str, self.process_id(), self.command(), port_str
        )?;
        writeln!(f, "Latency: {:.2}ms", latency_ms)?;
        writeln!(f)?;
        writeln!(f, "--- Request ---")?;
        writeln!(f, "{} {}", self.request.method, self.request.uri)?;
        for (key, value) in &self.request.headers {
            writeln!(f, "{}: {}", key, value.to_str().unwrap_or("<binary>"))?;
        }
        if !self.request.body.is_empty() {
            writeln!(f)?;
            writeln!(f, "{}", String::from_utf8_lossy(&self.request.body))?;
        }
        writeln!(f)?;
        writeln!(f, "--- Response ---")?;
        let reason = self.response.status.canonical_reason().unwrap_or("");
        writeln!(f, "{} {}", self.response.status.as_u16(), reason)?;
        for (key, value) in &self.response.headers {
            writeln!(f, "{}: {}", key, value.to_str().unwrap_or("<binary>"))?;
        }
        if !self.response.body.is_empty() {
            writeln!(f)?;
            writeln!(f, "{}", String::from_utf8_lossy(&self.response.body))?;
        }
        Ok(())
    }
}
