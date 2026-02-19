use super::*;
use rstest::rstest;

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
        try_parse_http1_request(data, TimestampNs(0)).is_none(),
        "Should return None for incomplete headers"
    );
}

#[test]
fn test_try_parse_request_complete_no_body() {
    // GET request with no body - complete after headers
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let result = try_parse_http1_request(data, TimestampNs(12345));
    assert!(result.is_some(), "Should parse complete GET request");
    let req = result.unwrap();
    assert_eq!(req.method, Method::GET);
    assert_eq!(req.timestamp_ns, TimestampNs(12345));
    assert!(req.body.is_empty());
}

#[test]
fn test_try_parse_request_content_length_complete() {
    let data = b"POST /api HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
    let result = try_parse_http1_request(data, TimestampNs(0));
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
        try_parse_http1_request(data, TimestampNs(0)).is_none(),
        "Should return None when body is incomplete"
    );
}

#[test]
fn test_try_parse_request_content_length_case_insensitive() {
    // Mixed case Content-Length header
    let data = b"POST /api HTTP/1.1\r\ncontent-length: 5\r\n\r\nhello";
    let result = try_parse_http1_request(data, TimestampNs(0));
    assert!(
        result.is_some(),
        "Should handle case-insensitive Content-Length"
    );
    assert_eq!(result.unwrap().body, b"hello");
}

#[test]
fn test_try_parse_request_chunked_complete() {
    let data = b"POST /api HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let result = try_parse_http1_request(data, TimestampNs(0));
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
        try_parse_http1_request(data, TimestampNs(0)).is_none(),
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
        try_parse_http1_response(data, TimestampNs(0)).is_none(),
        "Should return None for incomplete response headers"
    );
}

#[test]
fn test_try_parse_response_complete_no_body() {
    let data = b"HTTP/1.1 204 No Content\r\n\r\n";
    let result = try_parse_http1_response(data, TimestampNs(67890));
    assert!(result.is_some(), "Should parse complete 204 response");
    let resp = result.unwrap();
    assert_eq!(resp.status, StatusCode::NO_CONTENT);
    assert_eq!(resp.timestamp_ns, TimestampNs(67890));
}

#[test]
fn test_try_parse_response_content_length_complete() {
    let data = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nHello World";
    let result = try_parse_http1_response(data, TimestampNs(0));
    assert!(result.is_some(), "Should parse complete response with body");
    let resp = result.unwrap();
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.body, b"Hello World");
}

#[test]
fn test_try_parse_response_content_length_incomplete() {
    let data = b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nHello";
    assert!(
        try_parse_http1_response(data, TimestampNs(0)).is_none(),
        "Should return None when response body is incomplete"
    );
}

#[test]
fn test_try_parse_response_chunked_complete() {
    let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let result = try_parse_http1_response(data, TimestampNs(0));
    assert!(result.is_some(), "Should parse complete chunked response");
}

#[test]
fn test_try_parse_response_chunked_incomplete() {
    let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
    assert!(
        try_parse_http1_response(data, TimestampNs(0)).is_none(),
        "Should return None for incomplete chunked response"
    );
}

// =========================================================================
// Additional try_parse tests (covering old parse_* functionality)
// =========================================================================

#[test]
fn test_try_parse_request_with_path_and_headers() {
    let data = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let request = try_parse_http1_request(data, TimestampNs(12345)).unwrap();

    assert_eq!(request.method, Method::GET);
    assert_eq!(request.uri.path(), "/path");
    assert_eq!(
        request.headers.get("host").unwrap().to_str().unwrap(),
        "example.com"
    );
    assert!(request.body.is_empty());
    assert_eq!(request.timestamp_ns, TimestampNs(12345));
}

#[test]
fn test_try_parse_response_with_content_type() {
    let data =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nHello World";
    let response = try_parse_http1_response(data, TimestampNs(67890)).unwrap();

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
    assert_eq!(response.timestamp_ns, TimestampNs(67890));
}

#[test]
fn test_try_parse_response_404_without_content_length_is_incomplete() {
    // 404 without Content-Length or Transfer-Encoding: body uses
    // read-until-close semantics (RFC 7230 §3.3.3), so this is incomplete.
    // Use close_connection / try_finalize_http1_response to finalize.
    let data = b"HTTP/1.1 404 Not Found\r\n\r\n";
    assert!(
        try_parse_http1_response(data, TimestampNs(0)).is_none(),
        "404 without framing should be incomplete (read-until-close)"
    );
}

#[test]
fn test_try_parse_response_404_with_content_length() {
    let data = b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
    let response = try_parse_http1_response(data, TimestampNs(0)).unwrap();
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
    let result = try_parse_http1_request(data, TimestampNs(0));
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
    let result = try_parse_http1_request(data, TimestampNs(0));
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
    let data = b"POST /api HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let result = try_parse_http1_request(data, TimestampNs(0));
    assert!(result.is_some());
    assert_eq!(result.unwrap().body, b"hello");
}

#[test]
fn test_chunked_false_positive_0_in_content() {
    // Body data containing "0\r\n\r\n" inside a chunk should not be falsely terminated.
    // Chunk 1: 12 bytes = "0\r\n\r\nhello\r\n" (contains the pattern inside data)
    // Chunk 2: 0 (terminal)
    let data = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nc\r\n0\r\n\r\nhello\r\n\r\n0\r\n\r\n";
    let result = try_parse_http1_request(data, TimestampNs(0));
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
    let result = try_parse_http1_request(data, TimestampNs(0));
    assert!(result.is_some());
    assert_eq!(result.unwrap().body, b"hello");
}

#[test]
fn test_chunked_with_extensions() {
    // Chunk size line with extension: "5;ext=val\r\nhello\r\n0\r\n\r\n"
    let data =
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=val\r\nhello\r\n0\r\n\r\n";
    let result = try_parse_http1_request(data, TimestampNs(0));
    assert!(result.is_some(), "Should handle chunk extensions");
    assert_eq!(result.unwrap().body, b"hello");
}

#[test]
fn test_chunked_incomplete_missing_terminator() {
    // Missing final 0\r\n\r\n
    let data = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
    assert!(
        try_parse_http1_request(data, TimestampNs(0)).is_none(),
        "Should be None for incomplete chunked"
    );
}

#[test]
fn test_chunked_response_decoded() {
    let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let result = try_parse_http1_response(data, TimestampNs(0));
    assert!(result.is_some(), "Should parse complete chunked response");
    assert_eq!(result.unwrap().body, b"hello");
}

// =========================================================================
// C-2: Multi-valued headers preserved via append (not insert)
// =========================================================================

#[test]
fn test_multi_valued_headers_preserved_in_request() {
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n";
    let req = try_parse_http1_request(data, TimestampNs(0)).unwrap();
    let cookies: Vec<_> = req.headers.get_all("cookie").iter().collect();
    assert_eq!(cookies.len(), 2, "Both Cookie headers should be preserved");
}

#[test]
fn test_multi_valued_headers_preserved_in_response() {
    let data =
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n";
    let resp = try_parse_http1_response(data, TimestampNs(0)).unwrap();
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
        try_parse_http1_response(data, TimestampNs(0)).is_none(),
        "Response without framing should be incomplete"
    );
}

#[rstest]
#[case::status_204(204, "No Content")]
#[case::status_304(304, "Not Modified")]
fn test_no_body_status_without_framing_is_complete(#[case] status_code: u16, #[case] reason: &str) {
    // These statuses explicitly have no body per RFC 7230 §3.3.3
    let data = format!("HTTP/1.1 {status_code} {reason}\r\n\r\n");
    assert!(
        try_parse_http1_response(data.as_bytes(), TimestampNs(0)).is_some(),
        "{status_code} should be complete without framing"
    );
}

#[test]
fn test_try_finalize_http1_response_takes_all_remaining_data() {
    let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nfull body here";
    let resp = try_finalize_http1_response(data, TimestampNs(12345)).unwrap();
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.body, b"full body here");
    assert_eq!(resp.timestamp_ns, TimestampNs(12345));
}

#[test]
fn test_try_finalize_http1_response_empty_body() {
    let data = b"HTTP/1.1 200 OK\r\n\r\n";
    let resp = try_finalize_http1_response(data, TimestampNs(0)).unwrap();
    assert!(resp.body.is_empty());
}

#[test]
fn test_try_finalize_incomplete_headers_returns_none() {
    // Headers not complete — can't finalize
    let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n";
    assert!(try_finalize_http1_response(data, TimestampNs(0)).is_none());
}
