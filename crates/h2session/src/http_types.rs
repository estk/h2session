//! Generic HTTP request/response types
//!
//! These types represent parsed HTTP messages independent of the HTTP version.
//! They can be used for both HTTP/1.x and HTTP/2 messages.

use crate::state::TimestampNs;
use http::{HeaderMap, Method, StatusCode, Uri};

/// HTTP request parsed from any HTTP version
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub timestamp_ns: TimestampNs,
}

/// HTTP response parsed from any HTTP version
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub timestamp_ns: TimestampNs,
}
