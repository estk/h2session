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
    pub method: Method,
    /// Request target URI
    pub uri: Uri,
    /// HTTP headers
    pub headers: HeaderMap,
    /// Request body bytes
    pub body: Vec<u8>,
    /// Kernel-capture time (`bpf_ktime_get_ns`, CLOCK_MONOTONIC) of the first
    /// data chunk that began this request — i.e. when the request started
    /// arriving. For HTTP/2 this is the first frame of the stream.
    pub start_timestamp_ns: TimestampNs,
    /// Userspace CLOCK_MONOTONIC time the first chunk of this request was read
    /// off the ringbuf (when snif first *saw* the request start). Subtract
    /// `start_timestamp_ns` for the eBPF→ringbuf→collator pipeline delay on the
    /// request's leading edge. For HTTP/2 this is chunk-level (the data chunk
    /// carrying the first frame), not frame-exact; `0` when the source reports
    /// no userspace time.
    pub userspace_start_timestamp_ns: TimestampNs,
    /// Kernel-capture time of the last data chunk that completed this request
    /// (the final byte). For HTTP/2 this is the END_STREAM frame.
    pub complete_timestamp_ns: TimestampNs,
    /// Userspace CLOCK_MONOTONIC time the completing chunk was read off the
    /// ringbuf (when the full request became available in userspace). Same
    /// caveats as `userspace_start_timestamp_ns`.
    pub userspace_complete_timestamp_ns: TimestampNs,
    /// HTTP version: None for HTTP/2, Some(0) for HTTP/1.0, Some(1) for
    /// HTTP/1.1
    pub version: Option<u8>,
}

/// HTTP response parsed from any HTTP version
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code (200, 404, etc.)
    pub status: StatusCode,
    /// HTTP headers
    pub headers: HeaderMap,
    /// Response body bytes
    pub body: Vec<u8>,
    /// Kernel-capture time (`bpf_ktime_get_ns`, CLOCK_MONOTONIC) of the first
    /// data chunk that began this response — i.e. response-start. For HTTP/2
    /// this is the first frame of the response stream.
    pub start_timestamp_ns: TimestampNs,
    /// Userspace CLOCK_MONOTONIC time the first chunk of this response was read
    /// off the ringbuf. Subtract `start_timestamp_ns` for pipeline delay on the
    /// response's leading edge. HTTP/2 chunk-level; `0` when unavailable.
    pub userspace_start_timestamp_ns: TimestampNs,
    /// Kernel-capture time of the last data chunk that completed this response
    /// (the final byte). For HTTP/2 this is the END_STREAM frame.
    pub complete_timestamp_ns: TimestampNs,
    /// Userspace CLOCK_MONOTONIC time the completing chunk was read off the
    /// ringbuf (when the full response became available in userspace).
    pub userspace_complete_timestamp_ns: TimestampNs,
    /// HTTP version: None for HTTP/2, Some(0) for HTTP/1.0, Some(1) for
    /// HTTP/1.1
    pub version: Option<u8>,
    /// Reason phrase: None for HTTP/2, Some("OK") etc for HTTP/1
    pub reason: Option<String>,
}
