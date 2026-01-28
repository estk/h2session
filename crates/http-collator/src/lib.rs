//! HTTP collation library
//!
//! Collates individual data events (from eBPF, pcap, etc.) into complete
//! HTTP request/response exchanges. Supports both HTTP/1.x and HTTP/2.
//!
//! # Usage
//!
//! Implement the [`DataEvent`] trait for your data source, then feed events
//! to the [`Collator`]:
//!
//! ```ignore
//! use http_collator::{Collator, DataEvent, Direction};
//!
//! struct MyEvent { /* ... */ }
//!
//! impl DataEvent for MyEvent {
//!     fn payload(&self) -> &[u8] { /* ... */ }
//!     fn timestamp_ns(&self) -> u64 { /* ... */ }
//!     fn direction(&self) -> Direction { /* ... */ }
//!     fn connection_id(&self) -> u64 { /* ... */ }
//!     fn process_id(&self) -> u32 { /* ... */ }
//!     fn remote_port(&self) -> u16 { /* ... */ }
//! }
//!
//! let mut collator = Collator::new();
//! if let Some(exchange) = collator.add_event(&my_event) {
//!     println!("Complete exchange: {}", exchange);
//! }
//! ```

mod connection;
mod exchange;
pub mod h1;
mod traits;

pub use connection::{Connection, DataChunk, Protocol};
pub use exchange::Exchange;
pub use h1::{HttpRequest, HttpResponse};
pub use traits::{DataEvent, Direction};

use connection::Connection as Conn;
use h2session::{is_http2_preface, looks_like_http2_frame};
use std::collections::HashMap;
use std::marker::PhantomData;

/// Default maximum buffer size for data events (TLS record size)
pub const MAX_BUF_SIZE: usize = 16384;

/// Collates individual data events into complete request/response exchanges.
///
/// Generic over the event type `E` which must implement [`DataEvent`].
pub struct Collator<E: DataEvent> {
    /// Connections tracked by conn_id (for socket events)
    connections: HashMap<u64, Conn>,
    /// SSL connections tracked by process_id (no conn_id available)
    ssl_connections: HashMap<u32, Conn>,
    /// Connection timeout in nanoseconds (5 seconds)
    timeout_ns: u64,
    /// Maximum buffer size for payloads
    max_buf_size: usize,
    /// Phantom data for the event type
    _phantom: PhantomData<E>,
}

impl<E: DataEvent> Default for Collator<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: DataEvent> Collator<E> {
    /// Create a new collator with default settings
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            ssl_connections: HashMap::new(),
            timeout_ns: 5_000_000_000, // 5 seconds
            max_buf_size: MAX_BUF_SIZE,
            _phantom: PhantomData,
        }
    }

    /// Create a new collator with a custom maximum buffer size
    pub fn with_max_buf_size(max_buf_size: usize) -> Self {
        Self {
            connections: HashMap::new(),
            ssl_connections: HashMap::new(),
            timeout_ns: 5_000_000_000,
            max_buf_size,
            _phantom: PhantomData,
        }
    }

    /// Add a data event and potentially return a complete exchange
    pub fn add_event(&mut self, event: &E) -> Option<Exchange> {
        let payload = event.payload();
        let safe_len = payload.len().min(self.max_buf_size);

        if safe_len == 0 {
            return None;
        }

        let buf = &payload[..safe_len];
        let direction = event.direction();

        // Skip non-data events
        if direction == Direction::Other {
            return None;
        }

        let chunk = DataChunk {
            data: buf.to_vec(),
            timestamp_ns: event.timestamp_ns(),
            direction,
        };

        // Use conn_id for socket events, process_id for SSL events
        let conn_id = event.connection_id();
        let conn = if conn_id != 0 {
            self.connections
                .entry(conn_id)
                .or_insert_with(|| Conn::new(event.process_id(), event.remote_port()))
        } else {
            self.ssl_connections
                .entry(event.process_id())
                .or_insert_with(|| Conn::new(event.process_id(), event.remote_port()))
        };

        conn.last_activity_ns = event.timestamp_ns();

        // Update port if we have a non-zero value (SSL events have 0)
        let remote_port = event.remote_port();
        if remote_port != 0 && conn.remote_port.is_none() {
            conn.remote_port = Some(remote_port);
        }

        // Detect protocol from first chunk if unknown
        if conn.protocol == Protocol::Unknown {
            conn.protocol = detect_protocol(buf);
        }

        // Add chunk to appropriate buffer based on direction
        match direction {
            Direction::Write => {
                conn.request_chunks.push(chunk);

                // Parse incrementally based on protocol
                match conn.protocol {
                    Protocol::Http1 if conn.h1_request.is_none() => {
                        try_parse_http1_request_chunks(conn);
                    }
                    Protocol::Http2 => {
                        parse_http2_request_chunks(conn);
                    }
                    _ => {}
                }

                // Check if request is complete
                if is_request_complete(conn) {
                    conn.request_complete = true;
                }
            }
            Direction::Read => {
                conn.response_chunks.push(chunk);

                // Parse incrementally based on protocol
                match conn.protocol {
                    Protocol::Http1 if conn.h1_response.is_none() => {
                        try_parse_http1_response_chunks(conn);
                    }
                    Protocol::Http2 => {
                        parse_http2_response_chunks(conn);
                    }
                    _ => {}
                }

                // Check if response is complete
                if is_response_complete(conn) {
                    conn.response_complete = true;
                }
            }
            Direction::Other => {
                // Already handled above
                return None;
            }
        }

        // For HTTP/2, a complete stream pair can be detected on either event.
        // Ensure both flags are set when a complete pair exists.
        if conn.protocol == Protocol::Http2 && find_complete_h2_stream(conn).is_some() {
            conn.request_complete = true;
            conn.response_complete = true;
        }

        // If both request and response are complete, emit exchange
        if conn.request_complete && conn.response_complete {
            let exchange = build_exchange(conn);

            // Reset connection for next exchange
            // For HTTP/1: clear everything including parsed messages
            // For HTTP/2: only the matched pair was removed in build_exchange;
            //             clear chunks but keep remaining pending messages
            conn.request_chunks.clear();
            conn.response_chunks.clear();
            conn.h2_request_state.clear_buffer();
            conn.h2_response_state.clear_buffer();
            conn.request_complete = false;
            conn.response_complete = false;

            if conn.protocol == Protocol::Http1 {
                conn.h1_request = None;
                conn.h1_response = None;
                conn.protocol = Protocol::Unknown;
            }
            // Note: For HTTP/2, don't clear pending_requests/pending_responses
            //       as they may contain other streams. The matched pair was
            //       already removed in build_exchange().
            // Note: Keep h2_*_state HPACK decoder for connection persistence.

            return exchange;
        }

        None
    }

    /// Clean up stale connections
    #[allow(dead_code)]
    pub fn cleanup(&mut self, current_time_ns: u64) {
        self.connections
            .retain(|_, conn| current_time_ns - conn.last_activity_ns < self.timeout_ns);
        self.ssl_connections
            .retain(|_, conn| current_time_ns - conn.last_activity_ns < self.timeout_ns);
    }
}

fn detect_protocol(data: &[u8]) -> Protocol {
    // Check for HTTP/2 preface
    if is_http2_preface(data) {
        return Protocol::Http2;
    }

    // Check for HTTP/2 frame header heuristic
    if looks_like_http2_frame(data) {
        return Protocol::Http2;
    }

    // Check for HTTP/1.x request
    if h1::is_http1_request(data) || h1::is_http1_response(data) {
        return Protocol::Http1;
    }

    Protocol::Unknown
}

/// Feed the latest request chunk to h2session for incremental parsing.
/// Uses the new feed() API which maintains internal buffer and parses incrementally.
fn parse_http2_request_chunks(conn: &mut Conn) {
    // Get the latest chunk that was just added
    let chunk = match conn.request_chunks.last() {
        Some(c) => c,
        None => return,
    };

    // Feed the new data to h2session with its timestamp
    // Parse errors are non-fatal, continue
    let _ = conn.h2_request_state.feed(&chunk.data, chunk.timestamp_ns);

    // Pop any completed messages and add to pending
    while let Some((stream_id, msg)) = conn.h2_request_state.try_pop() {
        if msg.is_request() {
            conn.pending_requests.insert(stream_id, msg);
        }
    }
}

/// Feed the latest response chunk to h2session for incremental parsing.
/// Uses the new feed() API which maintains internal buffer and parses incrementally.
fn parse_http2_response_chunks(conn: &mut Conn) {
    // Get the latest chunk that was just added
    let chunk = match conn.response_chunks.last() {
        Some(c) => c,
        None => return,
    };

    // Feed the new data to h2session with its timestamp
    // Parse errors are non-fatal, continue
    let _ = conn.h2_response_state.feed(&chunk.data, chunk.timestamp_ns);

    // Pop any completed messages and add to pending
    while let Some((stream_id, msg)) = conn.h2_response_state.try_pop() {
        if msg.is_response() {
            conn.pending_responses.insert(stream_id, msg);
        }
    }
}

/// Find a stream_id that has both request and response ready
fn find_complete_h2_stream(conn: &Conn) -> Option<u32> {
    conn.pending_requests
        .keys()
        .find(|id| conn.pending_responses.contains_key(id))
        .copied()
}

/// Try to parse HTTP/1 request from accumulated chunks.
/// If complete, stores the parsed request in conn.h1_request.
fn try_parse_http1_request_chunks(conn: &mut Conn) {
    let all_data: Vec<u8> = conn
        .request_chunks
        .iter()
        .flat_map(|c| c.data.clone())
        .collect();
    let timestamp = conn
        .request_chunks
        .last()
        .map(|c| c.timestamp_ns)
        .unwrap_or(0);
    conn.h1_request = h1::try_parse_http1_request(&all_data, timestamp);
}

/// Try to parse HTTP/1 response from accumulated chunks.
/// If complete, stores the parsed response in conn.h1_response.
fn try_parse_http1_response_chunks(conn: &mut Conn) {
    let all_data: Vec<u8> = conn
        .response_chunks
        .iter()
        .flat_map(|c| c.data.clone())
        .collect();
    let timestamp = conn
        .response_chunks
        .first()
        .map(|c| c.timestamp_ns)
        .unwrap_or(0);
    conn.h1_response = h1::try_parse_http1_response(&all_data, timestamp);
}

fn is_request_complete(conn: &Conn) -> bool {
    match conn.protocol {
        Protocol::Http1 => conn.h1_request.is_some(),
        Protocol::Http2 => find_complete_h2_stream(conn).is_some(),
        Protocol::Unknown => false,
    }
}

fn is_response_complete(conn: &Conn) -> bool {
    match conn.protocol {
        Protocol::Http1 => conn.h1_response.is_some(),
        Protocol::Http2 => find_complete_h2_stream(conn).is_some(),
        Protocol::Unknown => false,
    }
}

fn build_exchange(conn: &mut Conn) -> Option<Exchange> {
    let (request, response, stream_id, latency_ns) = match conn.protocol {
        Protocol::Http1 => {
            // Take the already-parsed request and response
            let req = conn.h1_request.take()?;
            let resp = conn.h1_response.take()?;
            let latency = resp.timestamp_ns.saturating_sub(req.timestamp_ns);
            (req, resp, None, latency)
        }
        Protocol::Http2 => {
            let sid = find_complete_h2_stream(conn)?;
            let msg_req = conn.pending_requests.remove(&sid)?;
            let msg_resp = conn.pending_responses.remove(&sid)?;

            // For HTTP/2, use per-stream timestamps from the parsed messages
            // Request complete time: when END_STREAM was seen on request
            // Response start time: when first frame was received on response
            let request_complete_time = msg_req.end_stream_timestamp_ns;
            let response_start_time = msg_resp.first_frame_timestamp_ns;

            let req = msg_req.to_http_request()?;
            let resp = msg_resp.to_http_response()?;

            let latency = response_start_time.saturating_sub(request_complete_time);
            (req, resp, Some(sid), latency)
        }
        Protocol::Unknown => return None,
    };

    Some(Exchange {
        request,
        response,
        latency_ns,
        protocol: conn.protocol,
        process_id: conn.process_id,
        remote_port: conn.remote_port,
        stream_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let _ = collator.add_event(&event);

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

        let _ = collator.add_event(&event1);
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

        let _ = collator.add_event(&event2);

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
        let mut block = Vec::new();
        block.push(0x82); // :method: GET (static index 2)
        block.push(0x87); // :scheme: https (static index 7)
        block.push(0x84); // :path: / (static index 4)
                          // :authority literal without indexing (0x00 + name index 1 (from :authority))
                          // Index 1 is :authority in static table, so use 0x01 for indexed name
        block.push(0x01); // Indexed name :authority (index 1)
        block.push(0x0b); // Value length 11
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
        let _ = collator.add_event(&event1);

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
        let _ = collator.add_event(&event2);

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
        let _ = collator.add_event(&event3);

        // Check the pending request body
        let conn = collator.connections.get(&conn_id).unwrap();
        let request = conn.pending_requests.get(&1).unwrap();

        // Body should be "helloworld", NOT "hellohelloworldhelloworldworld" (duplicated)
        assert_eq!(
            request.body, b"helloworld",
            "Body should not be duplicated when parsing incrementally"
        );
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
        let _ = collator.add_event(&req_event);

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
        let exchange = collator.add_event(&resp_event);

        // Should have a complete exchange
        assert!(exchange.is_some(), "Should produce a complete exchange");

        let exchange = exchange.unwrap();

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

    #[test]
    fn test_exchange_display_port_unavailable() {
        // Create an exchange with None port
        let exchange = Exchange {
            request: HttpRequest {
                method: http::Method::GET,
                uri: "/".parse().unwrap(),
                headers: http::HeaderMap::new(),
                body: vec![],
                timestamp_ns: 0,
            },
            response: HttpResponse {
                status: http::StatusCode::OK,
                headers: http::HeaderMap::new(),
                body: vec![],
                timestamp_ns: 0,
            },
            latency_ns: 1_000_000,
            protocol: Protocol::Http2,
            process_id: 1234,
            remote_port: None, // Port unavailable
            stream_id: Some(1),
        };

        let display = format!("{exchange}");
        assert!(
            display.contains("Port: unavailable"),
            "Should display 'unavailable' for None port"
        );
    }

    #[test]
    fn test_exchange_display_port_available() {
        let exchange = Exchange {
            request: HttpRequest {
                method: http::Method::GET,
                uri: "/".parse().unwrap(),
                headers: http::HeaderMap::new(),
                body: vec![],
                timestamp_ns: 0,
            },
            response: HttpResponse {
                status: http::StatusCode::OK,
                headers: http::HeaderMap::new(),
                body: vec![],
                timestamp_ns: 0,
            },
            latency_ns: 1_000_000,
            protocol: Protocol::Http2,
            process_id: 1234,
            remote_port: Some(8080), // Port available
            stream_id: Some(1),
        };

        let display = format!("{exchange}");
        assert!(
            display.contains("Port: 8080"),
            "Should display actual port number"
        );
    }
}
