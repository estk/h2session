//! Generic HTTP request/response types
//!
//! These types represent parsed HTTP messages independent of the HTTP version.
//! They can be used for both HTTP/1.x and HTTP/2 messages.

use http::{HeaderMap, Method, StatusCode, Uri};

use crate::state::TimestampNs;

/// HTTP request parsed from any HTTP version
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// HTTP method (GET, POST, etc.)
    pub method:       Method,
    /// Request target URI
    pub uri:          Uri,
    /// HTTP headers
    pub headers:      HeaderMap,
    /// Request body bytes
    pub body:         Vec<u8>,
    /// When this request was observed (nanosecond monotonic timestamp)
    pub timestamp_ns: TimestampNs,
}

/// HTTP response parsed from any HTTP version
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code (200, 404, etc.)
    pub status:       StatusCode,
    /// HTTP headers
    pub headers:      HeaderMap,
    /// Response body bytes
    pub body:         Vec<u8>,
    /// When this response was observed (nanosecond monotonic timestamp)
    pub timestamp_ns: TimestampNs,
}
