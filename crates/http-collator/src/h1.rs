//! HTTP/1.x parsing utilities

use h2session::TimestampNs;
// Re-export HTTP types from h2session for use across all HTTP versions
pub use h2session::{HttpRequest, HttpResponse};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};

/// Check if data starts with an HTTP/1.x request
pub fn is_http1_request(data: &[u8]) -> bool {
    data.starts_with(b"GET ")
        || data.starts_with(b"POST ")
        || data.starts_with(b"PUT ")
        || data.starts_with(b"DELETE ")
        || data.starts_with(b"HEAD ")
        || data.starts_with(b"OPTIONS ")
        || data.starts_with(b"PATCH ")
        || data.starts_with(b"CONNECT ")
}

/// Check if data starts with an HTTP/1.x response
pub fn is_http1_response(data: &[u8]) -> bool {
    data.starts_with(b"HTTP/1.0") || data.starts_with(b"HTTP/1.1")
}

/// Try to parse an HTTP/1.x request, returning Some only if complete.
/// This combines header parsing and body completeness checking in one pass.
pub fn try_parse_http1_request(data: &[u8], timestamp_ns: TimestampNs) -> Option<HttpRequest> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    let body_offset = match req.parse(data) {
        Ok(httparse::Status::Complete(len)) => len,
        _ => return None, // Headers incomplete
    };

    let body_data = &data[body_offset..];
    let body = match determine_body(req.headers, body_data, None) {
        BodyResult::Complete(b) => b,
        BodyResult::Incomplete => return None,
    };

    let method = Method::from_bytes(req.method?.as_bytes()).ok()?;
    let uri: Uri = req.path?.parse().ok()?;

    let mut header_map = HeaderMap::new();
    for h in req.headers.iter() {
        let parsed = (
            HeaderName::from_bytes(h.name.as_bytes()),
            HeaderValue::from_bytes(h.value),
        );
        if let (Ok(name), Ok(value)) = parsed {
            header_map.append(name, value);
        }
    }

    Some(HttpRequest {
        method,
        uri,
        headers: header_map,
        body,
        timestamp_ns,
    })
}

/// Try to parse an HTTP/1.x response, returning Some only if complete.
/// This combines header parsing and body completeness checking in one pass.
pub fn try_parse_http1_response(data: &[u8], timestamp_ns: TimestampNs) -> Option<HttpResponse> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut res = httparse::Response::new(&mut headers);

    let body_offset = match res.parse(data) {
        Ok(httparse::Status::Complete(len)) => len,
        _ => return None, // Headers incomplete
    };

    let body_data = &data[body_offset..];
    let body = match determine_body(res.headers, body_data, res.code) {
        BodyResult::Complete(b) => b,
        BodyResult::Incomplete => return None,
    };

    let status = StatusCode::from_u16(res.code?).ok()?;

    let mut header_map = HeaderMap::new();
    for h in res.headers.iter() {
        let parsed = (
            HeaderName::from_bytes(h.name.as_bytes()),
            HeaderValue::from_bytes(h.value),
        );
        if let (Ok(name), Ok(value)) = parsed {
            header_map.append(name, value);
        }
    }

    Some(HttpResponse {
        status,
        headers: header_map,
        body,
        timestamp_ns,
    })
}

/// Finalize an HTTP/1.x response when the connection closes.
///
/// For responses without explicit framing (no Content-Length or
/// Transfer-Encoding), RFC 7230 §3.3.3 says the body is everything until the
/// connection closes. This function parses the headers and takes all remaining
/// data as the body.
pub fn try_finalize_http1_response(data: &[u8], timestamp_ns: TimestampNs) -> Option<HttpResponse> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut res = httparse::Response::new(&mut headers);

    let body_offset = match res.parse(data) {
        Ok(httparse::Status::Complete(len)) => len,
        _ => return None,
    };

    let body = data[body_offset..].to_vec();
    let status = StatusCode::from_u16(res.code?).ok()?;

    let mut header_map = HeaderMap::new();
    for h in res.headers.iter() {
        let parsed = (
            HeaderName::from_bytes(h.name.as_bytes()),
            HeaderValue::from_bytes(h.value),
        );
        if let (Ok(name), Ok(value)) = parsed {
            header_map.append(name, value);
        }
    }

    Some(HttpResponse {
        status,
        headers: header_map,
        body,
        timestamp_ns,
    })
}

/// Result of body determination for an HTTP/1.x message.
enum BodyResult {
    /// Body is complete with the given bytes
    Complete(Vec<u8>),
    /// Not enough data yet
    Incomplete,
}

/// Determine the body of an HTTP/1.x message based on headers and available
/// data.
///
/// - Content-Length: body is exactly `body_data[..content_length]`
/// - Transfer-Encoding: chunked: walks chunk boundaries to decode body
/// - Neither (request): body is empty (no body expected, e.g., GET requests)
/// - Neither (response with body-bearing status): incomplete (RFC 7230 §3.3.3
///   read-until-close semantics)
///
/// `response_status`: `None` for requests, `Some(code)` for responses.
fn determine_body(
    headers: &[httparse::Header<'_>],
    body_data: &[u8],
    response_status: Option<u16>,
) -> BodyResult {
    // Look for Content-Length (case-insensitive via httparse)
    for h in headers.iter() {
        if h.name.eq_ignore_ascii_case("Content-Length") {
            if let Ok(len_str) = std::str::from_utf8(h.value)
                && let Ok(content_length) = len_str.trim().parse::<usize>()
            {
                if body_data.len() >= content_length {
                    return BodyResult::Complete(body_data[..content_length].to_vec());
                }
                return BodyResult::Incomplete;
            }
            return BodyResult::Incomplete; // Invalid Content-Length
        }
    }

    // Check for Transfer-Encoding: chunked
    for h in headers.iter() {
        if h.name.eq_ignore_ascii_case("Transfer-Encoding")
            && let Ok(value) = std::str::from_utf8(h.value)
            && value.to_ascii_lowercase().contains("chunked")
        {
            return decode_chunked_body(body_data);
        }
    }

    // No Content-Length and not chunked
    match response_status {
        // Requests have no body by default
        None => BodyResult::Complete(Vec::new()),
        // 1xx, 204, and 304 responses explicitly have no body (RFC 7230 §3.3.3)
        Some(code) if (100..200).contains(&code) || code == 204 || code == 304 => {
            BodyResult::Complete(Vec::new())
        },
        // Other responses: body is read until connection close
        Some(_) => BodyResult::Incomplete,
    }
}

/// Walk chunk boundaries to decode a chunked transfer-encoded body.
///
/// Chunk format: `[hex-size][;ext=val]\r\n[data]\r\n` terminated by
/// `0\r\n\r\n`. Returns the decoded body or Incomplete if not enough data.
fn decode_chunked_body(data: &[u8]) -> BodyResult {
    let mut decoded = Vec::new();
    let mut pos = 0;

    loop {
        // Find the end of the chunk-size line
        let line_end = match find_crlf(data, pos) {
            Some(idx) => idx,
            None => return BodyResult::Incomplete,
        };

        // Parse hex chunk size (ignore chunk extensions after ';')
        let size_bytes = &data[pos..line_end];
        let size_part = match size_bytes.iter().position(|&b| b == b';') {
            Some(semi_pos) => &size_bytes[..semi_pos],
            None => size_bytes,
        };
        let Ok(size_str) = std::str::from_utf8(size_part) else {
            return BodyResult::Incomplete; // Non-UTF8 chunk size
        };
        let Ok(chunk_size) = usize::from_str_radix(size_str.trim(), 16) else {
            return BodyResult::Incomplete; // Non-hex chunk size
        };

        // Advance past the chunk-size line (including \r\n)
        pos = line_end + 2;

        if chunk_size == 0 {
            // Terminal chunk: expect trailing \r\n (may also have trailers, but
            // for simplicity we just need \r\n after the 0-size chunk line)
            if pos + 2 > data.len() {
                return BodyResult::Incomplete;
            }
            // Verify trailing \r\n
            if data[pos..pos + 2] != *b"\r\n" {
                // Could be trailers; scan for the final \r\n\r\n
                match find_crlf_crlf(data, pos) {
                    Some(_) => return BodyResult::Complete(decoded),
                    None => return BodyResult::Incomplete,
                }
            }
            return BodyResult::Complete(decoded);
        }

        // Read chunk data
        if pos + chunk_size > data.len() {
            return BodyResult::Incomplete;
        }
        decoded.extend_from_slice(&data[pos..pos + chunk_size]);
        pos += chunk_size;

        // Expect \r\n after chunk data
        if pos + 2 > data.len() {
            return BodyResult::Incomplete;
        }
        if data[pos..pos + 2] != *b"\r\n" {
            return BodyResult::Incomplete; // Malformed
        }
        pos += 2;
    }
}

/// Find the position of `\r\n` starting at `from` in `data`.
fn find_crlf(data: &[u8], from: usize) -> Option<usize> {
    if from >= data.len() {
        return None;
    }
    data[from..]
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|p| from + p)
}

/// Find the position of `\r\n\r\n` starting at `from` in `data`.
fn find_crlf_crlf(data: &[u8], from: usize) -> Option<usize> {
    if from >= data.len() {
        return None;
    }
    data[from..]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| from + p)
}

#[cfg(test)]
mod tests;
