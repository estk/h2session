#![allow(unused_mut)]

use super::*;
use rstest::rstest;

/// Test implementation of DataEvent
struct TestEvent {
    payload: Vec<u8>,
    timestamp_ns: u64,
    direction: Direction,
    conn_id: u64,
    process_id: u32,
    remote_port: u16,
}

impl DataEvent for TestEvent {
    fn payload(&self) -> &[u8] {
        &self.payload
    }

    fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }

    fn direction(&self) -> Direction {
        self.direction
    }

    fn connection_id(&self) -> u64 {
        self.conn_id
    }

    fn process_id(&self) -> u32 {
        self.process_id
    }

    fn remote_port(&self) -> u16 {
        self.remote_port
    }
}

/// Helper to create a test event
fn make_event(
    direction: Direction,
    conn_id: u64,
    process_id: u32,
    remote_port: u16,
    timestamp_ns: u64,
    payload: &[u8],
) -> TestEvent {
    TestEvent {
        payload: payload.to_vec(),
        timestamp_ns,
        direction,
        conn_id,
        process_id,
        remote_port,
    }
}

// =========================================================================
// Issue 1: Port shows 0 for SSL connections
// =========================================================================

#[test]
fn test_ssl_port_zero_becomes_none() {
    let mut collator: Collator<TestEvent> = Collator::new();

    // SSL event with port 0 (unavailable)
    let event = make_event(
        Direction::Write,
        0, // SSL uses process_id, not conn_id
        1234,
        0, // Port 0 = unavailable
        1_000_000,
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );

    let _ = collator.add_event(event);

    // Verify the connection was created with None for remote_port
    let conn = collator.ssl_connections.get(&1234).unwrap();
    assert_eq!(conn.remote_port, None, "Port 0 should become None");
}

#[test]
fn test_port_updated_from_later_event() {
    let mut collator: Collator<TestEvent> = Collator::new();

    // First SSL event with port 0
    let event1 = make_event(
        Direction::Write,
        0,
        1234,
        0, // Port unknown
        1_000_000,
        b"GET / HTTP/1.1\r\n",
    );

    let _ = collator.add_event(event1);
    assert_eq!(
        collator.ssl_connections.get(&1234).unwrap().remote_port,
        None
    );

    // Second event with actual port (e.g., from socket event)
    let event2 = make_event(
        Direction::Write,
        0,
        1234,
        8080, // Now we know the port
        2_000_000,
        b"Host: example.com\r\n\r\n",
    );

    let _ = collator.add_event(event2);

    // Port should now be updated
    assert_eq!(
        collator.ssl_connections.get(&1234).unwrap().remote_port,
        Some(8080),
        "Port should be updated from later event"
    );
}

// =========================================================================
// Issue 3: Body appears duplicated (HTTP/2 incremental parsing)
// =========================================================================

/// HTTP/2 connection preface
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Build an empty SETTINGS frame (9 bytes)
fn build_settings_frame() -> Vec<u8> {
    vec![0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]
}

/// Build a HEADERS frame with END_HEADERS (but not END_STREAM, expects DATA)
fn build_headers_frame(stream_id: u32, hpack_block: &[u8]) -> Vec<u8> {
    let len = hpack_block.len();
    let mut frame = vec![
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        0x01, // HEADERS
        0x04, // END_HEADERS only (body follows)
        (stream_id >> 24) as u8 & 0x7F,
        (stream_id >> 16) as u8,
        (stream_id >> 8) as u8,
        stream_id as u8,
    ];
    frame.extend_from_slice(hpack_block);
    frame
}

/// Build a DATA frame with optional END_STREAM
fn build_data_frame(stream_id: u32, data: &[u8], end_stream: bool) -> Vec<u8> {
    let len = data.len();
    let flags = if end_stream { 0x01 } else { 0x00 };
    let mut frame = vec![
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        0x00, // DATA
        flags,
        (stream_id >> 24) as u8 & 0x7F,
        (stream_id >> 16) as u8,
        (stream_id >> 8) as u8,
        stream_id as u8,
    ];
    frame.extend_from_slice(data);
    frame
}

/// Build HPACK for a complete GET request
fn hpack_get_request() -> Vec<u8> {
    let mut block = vec![
        0x82, // :method: GET (static index 2)
        0x87, // :scheme: https (static index 7)
        0x84, // :path: / (static index 4)
        0x01, // Indexed name :authority (index 1)
        0x0b, // Value length 11
    ];
    block.extend_from_slice(b"example.com");
    block
}

/// Build HPACK for :status 200 response
fn hpack_status_200() -> Vec<u8> {
    vec![0x88] // Static table index 8
}

#[test]
fn test_h2_incremental_parsing_no_body_duplication() {
    let mut collator: Collator<TestEvent> = Collator::new();
    let conn_id = 12345u64;
    let process_id = 1000u32;

    // Build HTTP/2 request: preface + settings + headers + data in chunks
    let mut request_chunk1 = H2_PREFACE.to_vec();
    request_chunk1.extend(build_settings_frame());
    request_chunk1.extend(build_headers_frame(1, &hpack_get_request()));

    // First chunk: preface + settings + headers
    let event1 = make_event(
        Direction::Write,
        conn_id,
        process_id,
        8080,
        1_000_000,
        &request_chunk1,
    );
    let _ = collator.add_event(event1);

    // Second chunk: DATA frame with body "hello"
    let data_frame1 = build_data_frame(1, b"hello", false);
    let event2 = make_event(
        Direction::Write,
        conn_id,
        process_id,
        8080,
        2_000_000,
        &data_frame1,
    );
    let _ = collator.add_event(event2);

    // Third chunk: DATA frame with body "world" and END_STREAM
    let data_frame2 = build_data_frame(1, b"world", true);
    let event3 = make_event(
        Direction::Write,
        conn_id,
        process_id,
        8080,
        3_000_000,
        &data_frame2,
    );
    let _ = collator.add_event(event3);

    // Check the pending request body
    let conn = collator.connections.get(&conn_id).unwrap();
    let request = conn.pending_requests.get(&StreamId(1)).unwrap();

    // Body should be "helloworld", NOT "hellohelloworldhelloworldworld" (duplicated)
    assert_eq!(
        request.body, b"helloworld",
        "Body should not be duplicated when parsing incrementally"
    );
}

// =========================================================================
// Large payload: body exceeding max_buf_size should still be captured
// =========================================================================

#[test]
fn test_h2_large_payload_exceeding_max_buf_size() {
    let mut collator: Collator<TestEvent> = Collator::new();
    let conn_id = 54321u64;
    let process_id = 4000u32;

    // Build a single buffer containing: preface + settings + headers + 32KB DATA
    let body = vec![0x41u8; 32768]; // 32KB of 'A'
    let mut payload = H2_PREFACE.to_vec();
    payload.extend(build_settings_frame());
    payload.extend(build_headers_frame(1, &hpack_get_request()));
    payload.extend(build_data_frame(1, &body, true)); // END_STREAM

    // The total payload is ~32KB+ which exceeds MAX_BUF_SIZE (16384).
    // The collator must not truncate this, or the h2 parser will see
    // an incomplete DATA frame and fail to finalize the request.
    assert!(
        payload.len() > MAX_BUF_SIZE,
        "Test payload ({} bytes) must exceed MAX_BUF_SIZE ({MAX_BUF_SIZE})",
        payload.len()
    );

    let event = make_event(
        Direction::Write,
        conn_id,
        process_id,
        8080,
        1_000_000,
        &payload,
    );
    let events = collator.add_event(event);

    // Should have emitted a request Message with the full 32KB body
    let request_msg = events.iter().find_map(|e| {
        if let Some((msg, _)) = e.as_message()
            && msg.is_request()
        {
            return Some(msg.clone());
        }
        None
    });

    let request = request_msg.expect("Large payload request should be parsed and emitted");
    match request {
        ParsedHttpMessage::Request(req) => {
            assert_eq!(
                req.body.len(),
                32768,
                "Body should be 32KB, got {} bytes",
                req.body.len()
            );
            assert!(
                req.body.iter().all(|&b| b == 0x41),
                "Body content should be all 'A' bytes"
            );
        }
        _ => panic!("Expected a request message"),
    }
}

// =========================================================================
// FD reuse: same connection_id with a new h2 preface after GOAWAY
// =========================================================================

#[test]
fn test_h2_fd_reuse_resets_parser_on_new_preface() {
    let mut collator: Collator<TestEvent> = Collator::new();
    let conn_id = 88888u64;
    let process_id = 5000u32;

    // --- First exchange on this connection_id ---
    // Request: preface + settings + headers(END_STREAM)
    let hpack = hpack_get_request();
    let mut req1 = H2_PREFACE.to_vec();
    req1.extend(build_settings_frame());
    let mut headers = vec![
        (hpack.len() >> 16) as u8,
        (hpack.len() >> 8) as u8,
        hpack.len() as u8,
        0x01, // HEADERS
        0x05, // END_HEADERS | END_STREAM
        0x00,
        0x00,
        0x00,
        0x01, // Stream 1
    ];
    headers.extend(&hpack);
    req1.extend(headers);

    let req1_event = make_event(Direction::Read, conn_id, process_id, 80, 1_000_000, &req1);
    let _ = collator.add_event(req1_event);

    // Response: HEADERS with :status 200 (END_STREAM)
    let resp_hpack = hpack_status_200();
    let mut resp1 = vec![
        (resp_hpack.len() >> 16) as u8,
        (resp_hpack.len() >> 8) as u8,
        resp_hpack.len() as u8,
        0x01,
        0x05,
        0x00,
        0x00,
        0x00,
        0x01,
    ];
    resp1.extend(&resp_hpack);

    let resp1_event = make_event(Direction::Write, conn_id, process_id, 80, 2_000_000, &resp1);
    let events1 = collator.add_event(resp1_event);
    assert!(
        events1.iter().any(|e| e.is_exchange()),
        "First exchange should complete"
    );

    // --- Second exchange: same conn_id, new h2 preface (fd reused) ---
    // Build a large request: preface + settings + headers + 32KB DATA
    let body = vec![0x42u8; 32768]; // 32KB of 'B'
    let mut req2 = H2_PREFACE.to_vec();
    req2.extend(build_settings_frame());
    req2.extend(build_headers_frame(1, &hpack_get_request()));
    req2.extend(build_data_frame(1, &body, true));

    let req2_event = make_event(Direction::Read, conn_id, process_id, 80, 3_000_000, &req2);
    let events2 = collator.add_event(req2_event);

    // Should have emitted a request Message for the second connection
    let request_msg = events2.iter().find_map(|e| {
        if let Some((msg, _)) = e.as_message()
            && msg.is_request()
        {
            return Some(msg.clone());
        }
        None
    });
    let request = request_msg.expect("Second h2 connection on reused fd should parse successfully");
    match request {
        ParsedHttpMessage::Request(req) => {
            assert_eq!(
                req.body.len(),
                32768,
                "Body should be 32KB, got {} bytes",
                req.body.len()
            );
        }
        _ => panic!("Expected a request message"),
    }
}

// =========================================================================
// FD reuse: body split across many chunks (mirrors real e2e data flow)
// =========================================================================

#[test]
fn test_h2_fd_reuse_split_chunks_with_response() {
    let mut collator: Collator<TestEvent> = Collator::new();
    let conn_id = 88889u64;
    let process_id = 5001u32;

    // --- First exchange: small GET on stream 1 (server-side monitoring) ---
    // Read = client→server (request), Write = server→client (response)
    let hpack = hpack_get_request();
    let mut req1 = H2_PREFACE.to_vec();
    req1.extend(build_settings_frame());
    let mut headers = vec![
        (hpack.len() >> 16) as u8,
        (hpack.len() >> 8) as u8,
        hpack.len() as u8,
        0x01, // HEADERS
        0x05, // END_HEADERS | END_STREAM
        0x00,
        0x00,
        0x00,
        0x01, // Stream 1
    ];
    headers.extend(&hpack);
    req1.extend(headers);

    let req1_event = make_event(Direction::Read, conn_id, process_id, 80, 1_000_000, &req1);
    let _ = collator.add_event(req1_event);

    // Response on Write direction
    let resp_hpack = hpack_status_200();
    let mut resp1 = vec![
        (resp_hpack.len() >> 16) as u8,
        (resp_hpack.len() >> 8) as u8,
        resp_hpack.len() as u8,
        0x01,
        0x05,
        0x00,
        0x00,
        0x00,
        0x01,
    ];
    resp1.extend(&resp_hpack);

    let resp1_event = make_event(Direction::Write, conn_id, process_id, 80, 2_000_000, &resp1);
    let events1 = collator.add_event(resp1_event);
    assert!(
        events1.iter().any(|e| e.is_exchange()),
        "First exchange should complete"
    );

    // --- GOAWAY on Read direction (server sends to client) ---
    // GOAWAY: type=0x07, flags=0, stream_id=0, payload: last_stream_id(4) + error_code(4)
    let goaway = vec![
        0x00, 0x00, 0x08, // length = 8
        0x07, // type = GOAWAY
        0x00, // flags
        0x00, 0x00, 0x00, 0x00, // stream_id = 0
        0x00, 0x00, 0x00, 0x01, // last_stream_id = 1
        0x00, 0x00, 0x00, 0x00, // error_code = NO_ERROR
    ];
    let goaway_event = make_event(Direction::Read, conn_id, process_id, 80, 2_500_000, &goaway);
    let _ = collator.add_event(goaway_event);

    // --- Second exchange: same conn_id (fd reused), large POST body ---
    // Build the full request data, then split it into realistic chunks
    let body = vec![0x42u8; 32768]; // 32KB of 'B'

    // Use a POST request HPACK block
    let mut post_hpack = vec![
        0x83, // :method: POST (static index 3)
        0x87, // :scheme: https (static index 7)
        0x84, // :path: / (static index 4)
        0x01, // :authority indexed name
        0x0b, // value length 11
    ];
    post_hpack.extend_from_slice(b"example.com");

    let mut full_request = H2_PREFACE.to_vec();
    full_request.extend(build_settings_frame());
    full_request.extend(build_headers_frame(1, &post_hpack));
    // Split body into 2 DATA frames (max_frame_size=16384 default)
    full_request.extend(build_data_frame(1, &body[..16384], false));
    full_request.extend(build_data_frame(1, &body[16384..], true));

    // Split the full request into chunks that mimic kernel read() splits:
    // chunk 1: preface + settings + headers + start of first DATA frame
    // chunk 2-N: remaining data in small pieces
    let split_points = [
        200,   // preface + settings + headers + partial DATA header
        2000,  // more DATA payload
        8000,  // more DATA payload
        16400, // crosses first DATA frame boundary
        20000, // middle of second DATA frame
        32000, // near end
    ];

    let mut prev = 0;
    let mut ts = 3_000_000u64;
    for &split in &split_points {
        let end = split.min(full_request.len());
        if prev >= full_request.len() {
            break;
        }
        let chunk = &full_request[prev..end];
        let event = make_event(Direction::Read, conn_id, process_id, 80, ts, chunk);
        let _ = collator.add_event(event);
        prev = end;
        ts += 100_000;
    }
    // Send remaining data
    if prev < full_request.len() {
        let chunk = &full_request[prev..];
        let event = make_event(Direction::Read, conn_id, process_id, 80, ts, chunk);
        let _ = collator.add_event(event);
        ts += 100_000;
    }

    // Verify the request was parsed (scope the guard to release the read lock
    // before calling add_event below, which needs a write lock on the same shard)
    {
        let conn = collator.connections.get(&conn_id).unwrap();
        assert!(
            conn.pending_requests.contains_key(&StreamId(1)),
            "Second exchange request should be in pending_requests"
        );
        let req = conn.pending_requests.get(&StreamId(1)).unwrap();
        assert_eq!(
            req.body.len(),
            32768,
            "Body should be 32KB, got {} bytes",
            req.body.len()
        );
    }

    // Now send response on Write direction (fresh HPACK context)
    let resp2_hpack = hpack_status_200();
    let mut resp2 = vec![
        (resp2_hpack.len() >> 16) as u8,
        (resp2_hpack.len() >> 8) as u8,
        resp2_hpack.len() as u8,
        0x01,
        0x05,
        0x00,
        0x00,
        0x00,
        0x01,
    ];
    resp2.extend(&resp2_hpack);

    let resp2_event = make_event(Direction::Write, conn_id, process_id, 80, ts, &resp2);
    let events2 = collator.add_event(resp2_event);

    // Should produce a complete exchange
    let exchange = events2
        .iter()
        .find_map(|e| e.as_exchange())
        .expect("Second exchange should complete after fd-reuse with split chunks");

    assert_eq!(exchange.request.method, http::Method::POST);
    assert_eq!(
        exchange.request.body.len(),
        32768,
        "Exchange body should be 32KB"
    );
    assert_eq!(exchange.response.status, http::StatusCode::OK);
}

// =========================================================================
// Issue 2: Latency shows 0.00ms for HTTPS (per-stream timestamps)
// =========================================================================

#[test]
fn test_h2_per_stream_latency() {
    let mut collator: Collator<TestEvent> = Collator::new();
    let conn_id = 99999u64;
    let process_id = 2000u32;

    // Request at t=1_000_000_000 (1 second)
    let mut request = H2_PREFACE.to_vec();
    request.extend(build_settings_frame());
    // HEADERS with END_HEADERS | END_STREAM (0x05)
    let hpack = hpack_get_request();
    let mut headers = vec![
        (hpack.len() >> 16) as u8,
        (hpack.len() >> 8) as u8,
        hpack.len() as u8,
        0x01, // HEADERS
        0x05, // END_HEADERS | END_STREAM
        0x00,
        0x00,
        0x00,
        0x01, // Stream 1
    ];
    headers.extend(&hpack);
    request.extend(headers);

    let req_event = make_event(
        Direction::Write,
        conn_id,
        process_id,
        443,
        1_000_000_000, // Request sent at 1 second
        &request,
    );
    let _ = collator.add_event(req_event);

    // Response at t=1_050_000_000 (1.05 seconds = 50ms later)
    let response_hpack = hpack_status_200();
    let mut response = vec![
        (response_hpack.len() >> 16) as u8,
        (response_hpack.len() >> 8) as u8,
        response_hpack.len() as u8,
        0x01, // HEADERS
        0x05, // END_HEADERS | END_STREAM
        0x00,
        0x00,
        0x00,
        0x01, // Stream 1
    ];
    response.extend(&response_hpack);

    let resp_event = make_event(
        Direction::Read,
        conn_id,
        process_id,
        443,
        1_050_000_000, // Response received at 1.05 seconds
        &response,
    );
    let events = collator.add_event(resp_event);

    // Find the exchange event
    let exchange = events
        .iter()
        .find_map(|e| e.as_exchange())
        .expect("Should produce a complete exchange");

    // Latency should be ~50ms (50_000_000 ns)
    // The per-stream timestamps should give us accurate latency
    assert!(
        exchange.latency_ns > 0,
        "Latency should be > 0, got {} ns",
        exchange.latency_ns
    );

    // Verify it's approximately 50ms (allow some tolerance)
    let expected_latency = 50_000_000u64; // 50ms
    assert!(
        exchange.latency_ns >= expected_latency - 1_000_000
            && exchange.latency_ns <= expected_latency + 1_000_000,
        "Expected latency ~50ms, got {} ns",
        exchange.latency_ns
    );
}

#[rstest]
#[case::port_unavailable(None, "Port: unavailable")]
#[case::port_available(Some(8080), "Port: 8080")]
fn test_exchange_display_port(#[case] remote_port: Option<u16>, #[case] expected_text: &str) {
    let exchange = Exchange {
        request: HttpRequest {
            method: http::Method::GET,
            uri: "/".parse().unwrap(),
            headers: http::HeaderMap::new(),
            body: vec![],
            timestamp_ns: TimestampNs(0),
        },
        response: HttpResponse {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: vec![],
            timestamp_ns: TimestampNs(0),
        },
        latency_ns: 1_000_000,
        protocol: Protocol::Http2,
        process_id: 1234,
        remote_port,
        stream_id: Some(StreamId(1)),
    };

    let display = format!("{exchange}");
    assert!(
        display.contains(expected_text),
        "Display should contain '{expected_text}'"
    );
}

// =========================================================================
// CollatorConfig tests
// =========================================================================

#[rstest]
#[case::messages_only(CollatorConfig::messages_only(), true, false)]
#[case::exchanges_only(CollatorConfig::exchanges_only(), false, true)]
#[case::default_emits_both(CollatorConfig::default(), true, true)]
fn test_collator_config(
    #[case] config: CollatorConfig,
    #[case] expect_messages: bool,
    #[case] expect_exchanges: bool,
) {
    assert_eq!(config.emit_messages, expect_messages);
    assert_eq!(config.emit_exchanges, expect_exchanges);
}

// =========================================================================
// Message emission tests
// =========================================================================

#[test]
fn test_http1_emits_request_message() {
    let mut collator: Collator<TestEvent> = Collator::with_config(CollatorConfig::messages_only());

    let event = make_event(
        Direction::Write,
        1,
        1234,
        8080,
        1_000_000,
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );

    let events = collator.add_event(event);

    // Should emit a Message event for the request
    assert_eq!(events.len(), 1);
    let (msg, metadata) = events[0].as_message().expect("Should be a Message event");
    assert!(msg.is_request());
    assert_eq!(metadata.protocol, Protocol::Http1);
    assert_eq!(metadata.connection_id, 1);
    assert_eq!(metadata.process_id, 1234);
}

#[test]
fn test_http1_emits_response_message() {
    let mut collator: Collator<TestEvent> = Collator::with_config(CollatorConfig::messages_only());

    let event = make_event(
        Direction::Read,
        1,
        1234,
        8080,
        1_000_000,
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    );

    let events = collator.add_event(event);

    // Should emit a Message event for the response
    assert_eq!(events.len(), 1);
    let (msg, metadata) = events[0].as_message().expect("Should be a Message event");
    assert!(msg.is_response());
    assert_eq!(metadata.protocol, Protocol::Http1);
}

#[test]
fn test_http1_complete_exchange_emits_both_types() {
    // With default config, should emit both Message and Exchange events
    let mut collator: Collator<TestEvent> = Collator::new();

    // Send request
    let req_event = make_event(
        Direction::Write,
        1,
        1234,
        8080,
        1_000_000,
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    let events = collator.add_event(req_event);
    assert_eq!(events.len(), 1, "Request should emit 1 Message event");
    assert!(events[0].is_message());

    // Send response
    let resp_event = make_event(
        Direction::Read,
        1,
        1234,
        8080,
        2_000_000,
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    );
    let events = collator.add_event(resp_event);

    // Should have response Message + Exchange
    assert_eq!(events.len(), 2, "Response should emit Message + Exchange");
    assert!(events.iter().any(|e| e.is_message()));
    assert!(events.iter().any(|e| e.is_exchange()));
}

#[test]
fn test_exchanges_only_skips_message_events() {
    let mut collator: Collator<TestEvent> = Collator::with_config(CollatorConfig::exchanges_only());

    // Send request
    let req_event = make_event(
        Direction::Write,
        1,
        1234,
        8080,
        1_000_000,
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    let events = collator.add_event(req_event);
    assert!(events.is_empty(), "Should not emit Message events");

    // Send response
    let resp_event = make_event(
        Direction::Read,
        1,
        1234,
        8080,
        2_000_000,
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    );
    let events = collator.add_event(resp_event);

    // Should only have Exchange, no Message
    assert_eq!(events.len(), 1);
    assert!(events[0].is_exchange());
}

#[test]
fn test_message_not_emitted_twice() {
    let mut collator: Collator<TestEvent> = Collator::with_config(CollatorConfig::messages_only());

    // Send request in two chunks
    let event1 = make_event(
        Direction::Write,
        1,
        1234,
        8080,
        1_000_000,
        b"GET / HTTP/1.1\r\n",
    );
    let events1 = collator.add_event(event1);
    assert!(events1.is_empty(), "Incomplete request should not emit");

    let event2 = make_event(
        Direction::Write,
        1,
        1234,
        8080,
        2_000_000,
        b"Host: example.com\r\n\r\n",
    );
    let events2 = collator.add_event(event2);
    assert_eq!(events2.len(), 1, "Complete request should emit once");

    // Another chunk on same connection (no new request data)
    let event3 = make_event(Direction::Write, 1, 1234, 8080, 3_000_000, b"");
    let events3 = collator.add_event(event3);
    assert!(events3.is_empty(), "Empty payload should not emit");
}

// =========================================================================
// Server-side monitoring (direction inverted from client-side)
// =========================================================================

#[test]
fn test_h2_server_side_monitoring() {
    // Server-side monitoring: Read = request (from client), Write = response (to client)
    // This is inverted from client-side monitoring where Write = request, Read = response
    let mut collator: Collator<TestEvent> = Collator::new();
    let conn_id = 77777u64;
    let process_id = 3000u32;

    // Server receives request on Read (from client)
    let mut request = H2_PREFACE.to_vec();
    request.extend(build_settings_frame());
    // HEADERS with END_HEADERS | END_STREAM (0x05)
    let hpack = hpack_get_request();
    let mut headers = vec![
        (hpack.len() >> 16) as u8,
        (hpack.len() >> 8) as u8,
        hpack.len() as u8,
        0x01, // HEADERS
        0x05, // END_HEADERS | END_STREAM
        0x00,
        0x00,
        0x00,
        0x01, // Stream 1
    ];
    headers.extend(&hpack);
    request.extend(headers);

    // Request arrives on Read direction (server receiving from client)
    let req_event = make_event(
        Direction::Read, // Server reads request FROM client
        conn_id,
        process_id,
        443,
        1_000_000_000,
        &request,
    );
    let events = collator.add_event(req_event);

    // Should have emitted a request Message event
    let request_msg = events.iter().find_map(|e| {
        if let Some((msg, _)) = e.as_message()
            && msg.is_request()
        {
            return Some(msg.clone());
        }
        None
    });
    assert!(
        request_msg.is_some(),
        "Server should see request on Read direction"
    );

    // Server sends response on Write (to client)
    let response_hpack = hpack_status_200();
    let mut response = vec![
        (response_hpack.len() >> 16) as u8,
        (response_hpack.len() >> 8) as u8,
        response_hpack.len() as u8,
        0x01, // HEADERS
        0x05, // END_HEADERS | END_STREAM
        0x00,
        0x00,
        0x00,
        0x01, // Stream 1
    ];
    response.extend(&response_hpack);

    // Response sent on Write direction (server writing to client)
    let resp_event = make_event(
        Direction::Write, // Server writes response TO client
        conn_id,
        process_id,
        443,
        1_050_000_000,
        &response,
    );
    let events = collator.add_event(resp_event);

    // Should have an Exchange event
    let exchange = events
        .iter()
        .find_map(|e| e.as_exchange())
        .expect("Should produce a complete exchange with inverted directions");

    // Verify the exchange is correct
    assert_eq!(
        exchange.request.method,
        http::Method::GET,
        "Request method should be GET"
    );
    assert_eq!(
        exchange.response.status,
        http::StatusCode::OK,
        "Response status should be 200 OK"
    );

    // Verify latency is calculated correctly even with inverted directions
    assert!(
        exchange.latency_ns > 0,
        "Latency should be > 0, got {} ns",
        exchange.latency_ns
    );

    let expected_latency = 50_000_000u64; // 50ms
    assert!(
        exchange.latency_ns >= expected_latency - 1_000_000
            && exchange.latency_ns <= expected_latency + 1_000_000,
        "Expected latency ~50ms, got {} ns",
        exchange.latency_ns
    );
}

// =========================================================================
// CRITICAL-3: cleanup() removes stale connections and evicts stale streams
// =========================================================================

#[test]
fn test_cleanup_removes_stale_connections() {
    let config = CollatorConfig {
        timeout_ns: 5_000_000_000, // 5 seconds
        ..CollatorConfig::default()
    };
    let mut collator: Collator<TestEvent> = Collator::with_config(config);

    // Add event at t=1s
    let event = make_event(
        Direction::Write,
        1,
        1234,
        8080,
        1_000_000_000,
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    let _ = collator.add_event(event);
    assert_eq!(collator.connections.len(), 1);

    // Cleanup at t=3s — connection is only 2s old, should survive
    collator.cleanup(TimestampNs(3_000_000_000));
    assert_eq!(
        collator.connections.len(),
        1,
        "Connection should survive (2s < 5s timeout)"
    );

    // Cleanup at t=7s — connection is 6s old, should be removed
    collator.cleanup(TimestampNs(7_000_000_000));
    assert_eq!(
        collator.connections.len(),
        0,
        "Connection should be removed (6s > 5s timeout)"
    );
}

#[test]
fn test_cleanup_evicts_stale_h2_streams() {
    let mut collator: Collator<TestEvent> = Collator::new();
    let conn_id = 42u64;

    // Send H2 preface + settings + HEADERS (no END_STREAM) at t=1s
    let hpack = hpack_get_request();
    let mut payload = H2_PREFACE.to_vec();
    payload.extend(build_settings_frame());
    // HEADERS with END_HEADERS only (stream stays incomplete)
    let mut headers = vec![
        (hpack.len() >> 16) as u8,
        (hpack.len() >> 8) as u8,
        hpack.len() as u8,
        0x01, // HEADERS
        0x04, // END_HEADERS only
        0x00,
        0x00,
        0x00,
        0x01, // stream 1
    ];
    headers.extend(&hpack);
    payload.extend(headers);

    let event = make_event(
        Direction::Write,
        conn_id,
        1000,
        8080,
        1_000_000_000,
        &payload,
    );
    let _ = collator.add_event(event);

    // Verify stream is active (scope the guard to release the read lock)
    {
        let conn = collator.connections.get(&conn_id).unwrap();
        assert_eq!(conn.h2_write_state.active_stream_count(), 1);
    }

    // Cleanup at t=40s (> default 30s stream timeout) with a recent last_activity
    // First update last_activity so the connection itself survives
    collator
        .connections
        .get_mut(&conn_id)
        .unwrap()
        .last_activity_ns = TimestampNs(39_000_000_000);
    collator.cleanup(TimestampNs(40_000_000_000));

    // Connection should survive but stale stream should be evicted
    assert_eq!(
        collator.connections.len(),
        1,
        "Connection should survive (recent activity)"
    );
    let conn = collator.connections.get(&conn_id).unwrap();
    assert_eq!(
        conn.h2_write_state.active_stream_count(),
        0,
        "Stale H2 stream should be evicted by cleanup"
    );
}

// =========================================================================
// HIGH-4: Body size limit resets connection
// =========================================================================

#[test]
fn test_body_size_limit_resets_connection() {
    let config = CollatorConfig {
        max_body_size: 100, // Very small limit for testing
        ..CollatorConfig::default()
    };
    let mut collator: Collator<TestEvent> = Collator::with_config(config);

    // Send a request that exceeds the body size limit
    let large_body = vec![b'X'; 200];
    let mut payload = b"POST / HTTP/1.1\r\nContent-Length: 200\r\n\r\n".to_vec();
    payload.extend(&large_body);

    // First chunk: headers + partial body (under limit)
    let event1 = make_event(Direction::Write, 1, 1234, 8080, 1_000_000, &payload[..80]);
    let events1 = collator.add_event(event1);
    assert!(events1.is_empty());

    // Second chunk: remaining body (exceeds limit)
    let event2 = make_event(Direction::Write, 1, 1234, 8080, 2_000_000, &payload[80..]);
    let events2 = collator.add_event(event2);
    assert!(
        events2.is_empty(),
        "Should not emit after body limit exceeded"
    );

    // Connection should be reset — protocol should be Unknown again
    let conn = collator.connections.get(&1).unwrap();
    assert_eq!(conn.protocol, Protocol::Unknown);
    assert!(conn.request_chunks.is_empty());
    assert_eq!(conn.request_body_size, 0);
}

#[test]
fn test_body_size_limit_normal_request_works() {
    let config = CollatorConfig {
        max_body_size: 1000,
        ..CollatorConfig::default()
    };
    let mut collator: Collator<TestEvent> = Collator::with_config(config);

    // Request well under the limit
    let event = make_event(
        Direction::Write,
        1,
        1234,
        8080,
        1_000_000,
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    let events = collator.add_event(event);
    assert_eq!(events.len(), 1, "Normal request should parse fine");
    assert!(events[0].is_message());
}

// =========================================================================
// MED-3: FD reuse with protocol change (HTTP/2 → HTTP/1)
// =========================================================================

#[test]
fn test_fd_reuse_http2_to_http1() {
    let mut collator: Collator<TestEvent> = Collator::new();
    let conn_id = 55555u64;

    // First: HTTP/2 exchange
    let hpack = hpack_get_request();
    let mut h2_req = H2_PREFACE.to_vec();
    h2_req.extend(build_settings_frame());
    let mut headers = vec![
        (hpack.len() >> 16) as u8,
        (hpack.len() >> 8) as u8,
        hpack.len() as u8,
        0x01,
        0x05, // END_HEADERS | END_STREAM
        0x00,
        0x00,
        0x00,
        0x01,
    ];
    headers.extend(&hpack);
    h2_req.extend(headers);

    let h2_event = make_event(Direction::Write, conn_id, 1000, 80, 1_000_000, &h2_req);
    let _ = collator.add_event(h2_event);

    // Connection is now HTTP/2
    assert_eq!(
        collator.connections.get(&conn_id).unwrap().protocol,
        Protocol::Http2
    );

    // Now: HTTP/1 data arrives on the same fd (protocol change)
    let h1_req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let h1_event = make_event(Direction::Write, conn_id, 1000, 80, 2_000_000, h1_req);
    let events = collator.add_event(h1_event);

    // Should have reset to HTTP/1 and parsed the request
    let conn = collator.connections.get(&conn_id).unwrap();
    assert_eq!(
        conn.protocol,
        Protocol::Http1,
        "Protocol should switch to HTTP/1"
    );
    assert!(
        events.iter().any(|e| e.is_message()),
        "HTTP/1 request should be parsed after protocol change"
    );
}

// =========================================================================
// C-1: Clock skew in cleanup doesn't panic
// =========================================================================

#[test]
fn test_cleanup_clock_skew_no_panic() {
    let config = CollatorConfig {
        timeout_ns: 5_000_000_000,
        ..CollatorConfig::default()
    };
    let collator: Collator<TestEvent> = Collator::with_config(config);

    // Manually insert a connection with last_activity in the "future"
    collator.connections.insert(1, Conn::new(1234, 8080));
    collator.connections.get_mut(&1).unwrap().last_activity_ns = TimestampNs(10_000_000_000);

    // Cleanup with a current_time BEFORE the last activity (clock skew).
    // With unsigned subtraction this would panic; saturating_sub prevents it.
    collator.cleanup(TimestampNs(5_000_000_000));

    // Connection should be retained (saturating_sub returns 0 < timeout)
    assert_eq!(
        collator.connections.len(),
        1,
        "Connection should survive clock skew"
    );
}

// =========================================================================
// C-3: close_connection finalizes pending HTTP/1 responses
// =========================================================================

#[test]
fn test_close_connection_finalizes_http1_response() {
    let collator: Collator<TestEvent> = Collator::new();

    // Send request
    let req_event = make_event(
        Direction::Write,
        1,
        1234,
        8080,
        1_000_000,
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    let _ = collator.add_event(req_event);

    // Send response WITHOUT Content-Length (read-until-close body)
    let resp_event = make_event(
        Direction::Read,
        1,
        1234,
        8080,
        2_000_000,
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello World",
    );
    let events = collator.add_event(resp_event);
    // Response should NOT be parsed yet (no framing = incomplete)
    assert!(
        !events
            .iter()
            .any(|e| { e.as_message().is_some_and(|(msg, _)| msg.is_response()) }),
        "Response without framing should not be emitted yet"
    );

    // Close the connection — should finalize the response
    let close_events = collator.close_connection(1, 1234);

    // Should have emitted the response and/or exchange
    let has_response = close_events
        .iter()
        .any(|e| e.as_message().is_some_and(|(msg, _)| msg.is_response()));
    let has_exchange = close_events.iter().any(|e| e.is_exchange());
    assert!(
        has_response || has_exchange,
        "close_connection should finalize the pending response"
    );

    // Connection should be removed
    assert!(
        collator.connections.get(&1).is_none(),
        "Connection should be removed after close"
    );
}
