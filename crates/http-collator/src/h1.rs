//! HTTP/1.x parsing utilities

use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};

// Re-export HTTP types from h2session for use across all HTTP versions
pub use h2session::{HttpRequest, HttpResponse};

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
pub fn try_parse_http1_request(data: &[u8], timestamp_ns: u64) -> Option<HttpRequest> {
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
pub fn try_parse_http1_response(data: &[u8], timestamp_ns: u64) -> Option<HttpResponse> {
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
/// For responses without explicit framing (no Content-Length or Transfer-Encoding),
/// RFC 7230 §3.3.3 says the body is everything until the connection closes.
/// This function parses the headers and takes all remaining data as the body.
pub fn try_finalize_http1_response(data: &[u8], timestamp_ns: u64) -> Option<HttpResponse> {
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

/// Determine the body of an HTTP/1.x message based on headers and available data.
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
        }
        // Other responses: body is read until connection close
        Some(_) => BodyResult::Incomplete,
    }
}

/// Walk chunk boundaries to decode a chunked transfer-encoded body.
///
/// Chunk format: `[hex-size][;ext=val]\r\n[data]\r\n` terminated by `0\r\n\r\n`.
/// Returns the decoded body or Incomplete if not enough data.
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
mod tests {
    use super::*;

    #[test]
    fn test_is_http1_request() {
        assert!(is_http1_request(b"GET / HTTP/1.1\r\n"));
        assert!(is_http1_request(b"POST /api HTTP/1.1\r\n"));
        assert!(is_http1_request(b"PUT /resource HTTP/1.1\r\n"));
        assert!(is_http1_request(b"DELETE /item HTTP/1.1\r\n"));
        assert!(is_http1_request(b"HEAD / HTTP/1.1\r\n"));
        assert!(is_http1_request(b"OPTIONS * HTTP/1.1\r\n"));
        assert!(is_http1_request(b"PATCH /update HTTP/1.1\r\n"));
        assert!(is_http1_request(b"CONNECT host:443 HTTP/1.1\r\n"));

        assert!(!is_http1_request(b"HTTP/1.1 200 OK\r\n"));
        assert!(!is_http1_request(b"PRI * HTTP/2.0\r\n"));
    }

    #[test]
    fn test_is_http1_response() {
        assert!(is_http1_response(b"HTTP/1.1 200 OK\r\n"));
        assert!(is_http1_response(b"HTTP/1.0 404 Not Found\r\n"));

        assert!(!is_http1_response(b"GET / HTTP/1.1\r\n"));
        assert!(!is_http1_response(b"HTTP/2 200 OK\r\n"));
    }

    // =========================================================================
    // try_parse_http1_request tests
    // =========================================================================

    #[test]
    fn test_try_parse_request_incomplete_headers() {
        // Headers not complete (no \r\n\r\n)
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert!(
            try_parse_http1_request(data, 0).is_none(),
            "Should return None for incomplete headers"
        );
    }

    #[test]
    fn test_try_parse_request_complete_no_body() {
        // GET request with no body - complete after headers
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = try_parse_http1_request(data, 12345);
        assert!(result.is_some(), "Should parse complete GET request");
        let req = result.unwrap();
        assert_eq!(req.method, Method::GET);
        assert_eq!(req.timestamp_ns, 12345);
        assert!(req.body.is_empty());
    }

    #[test]
    fn test_try_parse_request_content_length_complete() {
        let data = b"POST /api HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let result = try_parse_http1_request(data, 0);
        assert!(result.is_some(), "Should parse complete POST with body");
        let req = result.unwrap();
        assert_eq!(req.method, Method::POST);
        assert_eq!(req.body, b"hello");
    }

    #[test]
    fn test_try_parse_request_content_length_incomplete() {
        // Content-Length says 10 but only 5 bytes provided
        let data = b"POST /api HTTP/1.1\r\nContent-Length: 10\r\n\r\nhello";
        assert!(
            try_parse_http1_request(data, 0).is_none(),
            "Should return None when body is incomplete"
        );
    }

    #[test]
    fn test_try_parse_request_content_length_case_insensitive() {
        // Mixed case Content-Length header
        let data = b"POST /api HTTP/1.1\r\ncontent-length: 5\r\n\r\nhello";
        let result = try_parse_http1_request(data, 0);
        assert!(
            result.is_some(),
            "Should handle case-insensitive Content-Length"
        );
        assert_eq!(result.unwrap().body, b"hello");
    }

    #[test]
    fn test_try_parse_request_chunked_complete() {
        let data =
            b"POST /api HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let result = try_parse_http1_request(data, 0);
        assert!(result.is_some(), "Should parse complete chunked request");
        assert_eq!(
            result.unwrap().body,
            b"hello",
            "Chunked body should be decoded"
        );
    }

    #[test]
    fn test_try_parse_request_chunked_incomplete() {
        // Chunked but missing final 0\r\n\r\n
        let data = b"POST /api HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
        assert!(
            try_parse_http1_request(data, 0).is_none(),
            "Should return None for incomplete chunked"
        );
    }

    // =========================================================================
    // try_parse_http1_response tests
    // =========================================================================

    #[test]
    fn test_try_parse_response_incomplete_headers() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n";
        assert!(
            try_parse_http1_response(data, 0).is_none(),
            "Should return None for incomplete response headers"
        );
    }

    #[test]
    fn test_try_parse_response_complete_no_body() {
        let data = b"HTTP/1.1 204 No Content\r\n\r\n";
        let result = try_parse_http1_response(data, 67890);
        assert!(result.is_some(), "Should parse complete 204 response");
        let resp = result.unwrap();
        assert_eq!(resp.status, StatusCode::NO_CONTENT);
        assert_eq!(resp.timestamp_ns, 67890);
    }

    #[test]
    fn test_try_parse_response_content_length_complete() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nHello World";
        let result = try_parse_http1_response(data, 0);
        assert!(result.is_some(), "Should parse complete response with body");
        let resp = result.unwrap();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body, b"Hello World");
    }

    #[test]
    fn test_try_parse_response_content_length_incomplete() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nHello";
        assert!(
            try_parse_http1_response(data, 0).is_none(),
            "Should return None when response body is incomplete"
        );
    }

    #[test]
    fn test_try_parse_response_chunked_complete() {
        let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let result = try_parse_http1_response(data, 0);
        assert!(result.is_some(), "Should parse complete chunked response");
    }

    #[test]
    fn test_try_parse_response_chunked_incomplete() {
        let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
        assert!(
            try_parse_http1_response(data, 0).is_none(),
            "Should return None for incomplete chunked response"
        );
    }

    // =========================================================================
    // Additional try_parse tests (covering old parse_* functionality)
    // =========================================================================

    #[test]
    fn test_try_parse_request_with_path_and_headers() {
        let data = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let request = try_parse_http1_request(data, 12345).unwrap();

        assert_eq!(request.method, Method::GET);
        assert_eq!(request.uri.path(), "/path");
        assert_eq!(
            request.headers.get("host").unwrap().to_str().unwrap(),
            "example.com"
        );
        assert!(request.body.is_empty());
        assert_eq!(request.timestamp_ns, 12345);
    }

    #[test]
    fn test_try_parse_response_with_content_type() {
        let data =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nHello World";
        let response = try_parse_http1_response(data, 67890).unwrap();

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response
                .headers
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap(),
            "text/plain"
        );
        assert_eq!(response.body, b"Hello World");
        assert_eq!(response.timestamp_ns, 67890);
    }

    #[test]
    fn test_try_parse_response_404_without_content_length_is_incomplete() {
        // 404 without Content-Length or Transfer-Encoding: body uses
        // read-until-close semantics (RFC 7230 §3.3.3), so this is incomplete.
        // Use close_connection / try_finalize_http1_response to finalize.
        let data = b"HTTP/1.1 404 Not Found\r\n\r\n";
        assert!(
            try_parse_http1_response(data, 0).is_none(),
            "404 without framing should be incomplete (read-until-close)"
        );
    }

    #[test]
    fn test_try_parse_response_404_with_content_length() {
        let data = b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
        let response = try_parse_http1_response(data, 0).unwrap();
        assert_eq!(response.status, StatusCode::NOT_FOUND);
        assert_eq!(response.body, b"Not Found");
    }

    // =========================================================================
    // HIGH-3: No-body requests should not include trailing data
    // =========================================================================

    #[test]
    fn test_get_request_with_trailing_data_body_empty() {
        // GET with trailing data after headers — body should be empty
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nEXTRA";
        let result = try_parse_http1_request(data, 0);
        assert!(result.is_some());
        let req = result.unwrap();
        assert!(
            req.body.is_empty(),
            "GET body should be empty, not trailing data"
        );
    }

    #[test]
    fn test_post_content_length_ignores_trailing_data() {
        // POST with CL=5 but 9 bytes after headers — body should be "hello" only
        let data = b"POST /api HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        let result = try_parse_http1_request(data, 0);
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().body,
            b"hello",
            "Should truncate to Content-Length"
        );
    }

    // =========================================================================
    // HIGH-2: Proper chunked encoding parsing
    // =========================================================================

    #[test]
    fn test_chunked_body_decoded_correctly() {
        // Standard chunked encoding should decode to "hello"
        let data =
            b"POST /api HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let result = try_parse_http1_request(data, 0);
        assert!(result.is_some());
        assert_eq!(result.unwrap().body, b"hello");
    }

    #[test]
    fn test_chunked_false_positive_0_in_content() {
        // Body data containing "0\r\n\r\n" inside a chunk should not be falsely terminated.
        // Chunk 1: 12 bytes = "0\r\n\r\nhello\r\n" (contains the pattern inside data)
        // Chunk 2: 0 (terminal)
        let data = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nc\r\n0\r\n\r\nhello\r\n\r\n0\r\n\r\n";
        let result = try_parse_http1_request(data, 0);
        assert!(
            result.is_some(),
            "Should parse chunked body with embedded 0\\r\\n\\r\\n"
        );
        assert_eq!(result.unwrap().body, b"0\r\n\r\nhello\r\n");
    }

    #[test]
    fn test_chunked_multi_chunk() {
        // Multiple chunks: "hel" + "lo" = "hello"
        let data =
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nhel\r\n2\r\nlo\r\n0\r\n\r\n";
        let result = try_parse_http1_request(data, 0);
        assert!(result.is_some());
        assert_eq!(result.unwrap().body, b"hello");
    }

    #[test]
    fn test_chunked_with_extensions() {
        // Chunk size line with extension: "5;ext=val\r\nhello\r\n0\r\n\r\n"
        let data =
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=val\r\nhello\r\n0\r\n\r\n";
        let result = try_parse_http1_request(data, 0);
        assert!(result.is_some(), "Should handle chunk extensions");
        assert_eq!(result.unwrap().body, b"hello");
    }

    #[test]
    fn test_chunked_incomplete_missing_terminator() {
        // Missing final 0\r\n\r\n
        let data = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
        assert!(
            try_parse_http1_request(data, 0).is_none(),
            "Should be None for incomplete chunked"
        );
    }

    #[test]
    fn test_chunked_response_decoded() {
        let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let result = try_parse_http1_response(data, 0);
        assert!(result.is_some(), "Should parse complete chunked response");
        assert_eq!(result.unwrap().body, b"hello");
    }

    // =========================================================================
    // C-2: Multi-valued headers preserved via append (not insert)
    // =========================================================================

    #[test]
    fn test_multi_valued_headers_preserved_in_request() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n";
        let req = try_parse_http1_request(data, 0).unwrap();
        let cookies: Vec<_> = req.headers.get_all("cookie").iter().collect();
        assert_eq!(cookies.len(), 2, "Both Cookie headers should be preserved");
    }

    #[test]
    fn test_multi_valued_headers_preserved_in_response() {
        let data =
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n";
        let resp = try_parse_http1_response(data, 0).unwrap();
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(
            cookies.len(),
            2,
            "Both Set-Cookie headers should be preserved"
        );
    }

    // =========================================================================
    // C-3: Response without framing uses read-until-close semantics
    // =========================================================================

    #[test]
    fn test_response_without_framing_is_incomplete() {
        // 200 OK with no Content-Length or Transfer-Encoding: body extends
        // until connection close, so try_parse_http1_response should return None.
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\npartial body";
        assert!(
            try_parse_http1_response(data, 0).is_none(),
            "Response without framing should be incomplete"
        );
    }

    #[test]
    fn test_204_response_without_framing_is_complete() {
        // 204 No Content explicitly has no body per RFC 7230 §3.3.3
        let data = b"HTTP/1.1 204 No Content\r\n\r\n";
        assert!(
            try_parse_http1_response(data, 0).is_some(),
            "204 should be complete without framing"
        );
    }

    #[test]
    fn test_304_response_without_framing_is_complete() {
        // 304 Not Modified explicitly has no body per RFC 7230 §3.3.3
        let data = b"HTTP/1.1 304 Not Modified\r\n\r\n";
        assert!(
            try_parse_http1_response(data, 0).is_some(),
            "304 should be complete without framing"
        );
    }

    #[test]
    fn test_try_finalize_http1_response_takes_all_remaining_data() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nfull body here";
        let resp = try_finalize_http1_response(data, 12345).unwrap();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body, b"full body here");
        assert_eq!(resp.timestamp_ns, 12345);
    }

    #[test]
    fn test_try_finalize_http1_response_empty_body() {
        let data = b"HTTP/1.1 200 OK\r\n\r\n";
        let resp = try_finalize_http1_response(data, 0).unwrap();
        assert!(resp.body.is_empty());
    }

    #[test]
    fn test_try_finalize_incomplete_headers_returns_none() {
        // Headers not complete — can't finalize
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n";
        assert!(try_finalize_http1_response(data, 0).is_none());
    }
}
