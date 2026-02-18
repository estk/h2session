//! HTTP exchange (request/response pair) and collation events

use crate::connection::Protocol;
use crate::h1::{HttpRequest, HttpResponse};
use h2session::{StreamId, TimestampNs};

/// Classification of parsed HTTP message
#[derive(Debug, Clone)]
pub enum ParsedHttpMessage {
    Request(HttpRequest),
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
    pub connection_id: u64,
    /// Process ID for connection tracking
    pub process_id: u32,
    /// Timestamp in nanoseconds
    pub timestamp_ns: TimestampNs,
    /// Stream ID for HTTP/2 (None for HTTP/1)
    pub stream_id: Option<StreamId>,
    /// Remote port (None if unavailable)
    pub remote_port: Option<u16>,
    /// Protocol detected for this connection
    pub protocol: Protocol,
}

/// Events emitted by the collator
#[derive(Debug)]
pub enum CollationEvent {
    /// Individual message parsed and ready for processing
    Message {
        message: ParsedHttpMessage,
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
    pub emit_messages: bool,
    /// Emit Exchange events when request/response pairs complete
    pub emit_exchanges: bool,
    /// Maximum buffer size per chunk
    pub max_buf_size: usize,
    /// Connection timeout for cleanup in nanoseconds
    pub timeout_ns: u64,
    /// Maximum accumulated body size per direction before the connection is
    /// reset. Prevents unbounded memory growth from stalled or malicious
    /// connections. Default: 10 MiB.
    pub max_body_size: usize,
}

impl Default for CollatorConfig {
    fn default() -> Self {
        Self {
            emit_messages: true,
            emit_exchanges: true,
            max_buf_size: 16384,
            timeout_ns: 5_000_000_000,
            max_body_size: 10 * 1024 * 1024, // 10 MiB
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
#[derive(Debug)]
pub struct Exchange {
    pub request: HttpRequest,
    pub response: HttpResponse,
    pub latency_ns: u64,
    pub protocol: Protocol,
    pub process_id: u32,
    /// Remote port, None if unavailable (e.g., SSL without socket fd)
    pub remote_port: Option<u16>,
    /// Stream ID for HTTP/2 (None for HTTP/1)
    pub stream_id: Option<StreamId>,
}

impl std::fmt::Display for Exchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let proto_str = match self.protocol {
            Protocol::Http1 => "HTTP/1.1",
            Protocol::Http2 => "HTTP/2",
            Protocol::Unknown => "Unknown",
        };
        let latency_ms = self.latency_ns as f64 / 1_000_000.0;
        let port_str = self
            .remote_port
            .map_or("unavailable".to_string(), |p| p.to_string());

        writeln!(
            f,
            "=== {} Exchange (PID: {}, Port: {}) ===",
            proto_str, self.process_id, port_str
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
