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
pub use exchange::{CollationEvent, CollatorConfig, Exchange, MessageMetadata, ParsedHttpMessage};
pub use h1::{HttpRequest, HttpResponse};
pub use traits::{DataEvent, Direction};

use connection::Connection as Conn;
use h2session::{is_http2_preface, looks_like_http2_frame, H2ConnectionState};
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
    /// Configuration for what events to emit
    config: CollatorConfig,
    /// Phantom data for the event type
    _phantom: PhantomData<E>,
}

impl<E: DataEvent> Default for Collator<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: DataEvent> Collator<E> {
    /// Create a new collator with default settings (emits both messages and exchanges)
    pub fn new() -> Self {
        Self::with_config(CollatorConfig::default())
    }

    /// Create a new collator with custom configuration
    pub fn with_config(config: CollatorConfig) -> Self {
        Self {
            connections: HashMap::new(),
            ssl_connections: HashMap::new(),
            config,
            _phantom: PhantomData,
        }
    }

    /// Create a new collator with a custom maximum buffer size
    pub fn with_max_buf_size(max_buf_size: usize) -> Self {
        Self::with_config(CollatorConfig {
            max_buf_size,
            ..Default::default()
        })
    }

    /// Get a reference to the current configuration
    pub fn config(&self) -> &CollatorConfig {
        &self.config
    }

    /// Process a data event, returning all resulting collation events
    ///
    /// Returns Vec because:
    /// - HTTP/2 can have multiple streams complete in one buffer
    /// - A single buffer might contain complete request AND start of next
    /// - Config might emit both messages AND exchanges
    pub fn add_event(&mut self, event: &E) -> Vec<CollationEvent> {
        let payload = event.payload();

        if payload.is_empty() {
            return Vec::new();
        }

        let buf = payload;
        let direction = event.direction();

        // Skip non-data events
        if direction == Direction::Other {
            return Vec::new();
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
                        parse_http2_chunks(conn, direction);
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
                        parse_http2_chunks(conn, direction);
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
                return Vec::new();
            }
        }

        // For HTTP/2, a complete stream pair can be detected on either event.
        // Ensure both flags are set when a complete pair exists.
        if conn.protocol == Protocol::Http2 && find_complete_h2_stream(conn).is_some() {
            conn.request_complete = true;
            conn.response_complete = true;
        }

        // Collect events to emit based on config
        let mut events = Vec::new();

        // Emit Message events for newly parsed messages
        if self.config.emit_messages {
            emit_message_events(conn, conn_id, event.process_id(), &mut events);
        }

        // Emit Exchange event if both request and response are complete
        if self.config.emit_exchanges && conn.request_complete && conn.response_complete {
            if let Some(exchange) = build_exchange(conn) {
                events.push(CollationEvent::Exchange(exchange));
            }

            // Reset connection for next exchange
            reset_connection_after_exchange(conn);
        }

        events
    }

    /// Clean up stale connections
    #[allow(dead_code)]
    pub fn cleanup(&mut self, current_time_ns: u64) {
        self.connections
            .retain(|_, conn| current_time_ns - conn.last_activity_ns < self.config.timeout_ns);
        self.ssl_connections
            .retain(|_, conn| current_time_ns - conn.last_activity_ns < self.config.timeout_ns);
    }

    /// Remove a connection explicitly (e.g., on connection close)
    ///
    /// Call this when a connection is closed to free resources immediately.
    /// If connection_id is 0, removes based on process_id from SSL connections.
    pub fn remove_connection(&mut self, connection_id: u64, process_id: u32) {
        if connection_id != 0 {
            self.connections.remove(&connection_id);
        } else {
            self.ssl_connections.remove(&process_id);
        }
    }
}

/// Emit Message events for any newly parsed messages that haven't been emitted yet
fn emit_message_events(
    conn: &mut Conn,
    conn_id: u64,
    process_id: u32,
    events: &mut Vec<CollationEvent>,
) {
    match conn.protocol {
        Protocol::Http1 => {
            // Emit request if parsed and not yet emitted
            if let Some(ref req) = conn.h1_request {
                if !conn.h1_request_emitted {
                    let metadata = MessageMetadata {
                        connection_id: conn_id,
                        process_id,
                        timestamp_ns: req.timestamp_ns,
                        stream_id: None,
                        remote_port: conn.remote_port,
                        protocol: conn.protocol,
                    };
                    events.push(CollationEvent::Message {
                        message: ParsedHttpMessage::Request(req.clone()),
                        metadata,
                    });
                    conn.h1_request_emitted = true;
                }
            }

            // Emit response if parsed and not yet emitted
            if let Some(ref resp) = conn.h1_response {
                if !conn.h1_response_emitted {
                    let metadata = MessageMetadata {
                        connection_id: conn_id,
                        process_id,
                        timestamp_ns: resp.timestamp_ns,
                        stream_id: None,
                        remote_port: conn.remote_port,
                        protocol: conn.protocol,
                    };
                    events.push(CollationEvent::Message {
                        message: ParsedHttpMessage::Response(resp.clone()),
                        metadata,
                    });
                    conn.h1_response_emitted = true;
                }
            }
        }
        Protocol::Http2 => {
            // Emit newly parsed HTTP/2 requests
            for (&stream_id, msg) in &conn.pending_requests {
                if !conn.h2_emitted_requests.contains(&stream_id) {
                    if let Some(req) = msg.to_http_request() {
                        let metadata = MessageMetadata {
                            connection_id: conn_id,
                            process_id,
                            timestamp_ns: msg.end_stream_timestamp_ns,
                            stream_id: Some(stream_id),
                            remote_port: conn.remote_port,
                            protocol: conn.protocol,
                        };
                        events.push(CollationEvent::Message {
                            message: ParsedHttpMessage::Request(req),
                            metadata,
                        });
                    }
                }
            }
            // Mark all current pending requests as emitted
            conn.h2_emitted_requests
                .extend(conn.pending_requests.keys().copied());

            // Emit newly parsed HTTP/2 responses
            for (&stream_id, msg) in &conn.pending_responses {
                if !conn.h2_emitted_responses.contains(&stream_id) {
                    if let Some(resp) = msg.to_http_response() {
                        let metadata = MessageMetadata {
                            connection_id: conn_id,
                            process_id,
                            timestamp_ns: msg.first_frame_timestamp_ns,
                            stream_id: Some(stream_id),
                            remote_port: conn.remote_port,
                            protocol: conn.protocol,
                        };
                        events.push(CollationEvent::Message {
                            message: ParsedHttpMessage::Response(resp),
                            metadata,
                        });
                    }
                }
            }
            // Mark all current pending responses as emitted
            conn.h2_emitted_responses
                .extend(conn.pending_responses.keys().copied());
        }
        Protocol::Unknown => {}
    }
}

/// Reset connection state after emitting an exchange
fn reset_connection_after_exchange(conn: &mut Conn) {
    // For HTTP/1: clear everything including parsed messages
    // For HTTP/2: only the matched pair was removed in build_exchange;
    //             clear chunks but keep remaining pending messages
    conn.request_chunks.clear();
    conn.response_chunks.clear();
    conn.h2_write_state.clear_buffer();
    conn.h2_read_state.clear_buffer();
    conn.request_complete = false;
    conn.response_complete = false;

    if conn.protocol == Protocol::Http1 {
        conn.h1_request = None;
        conn.h1_response = None;
        conn.h1_request_emitted = false;
        conn.h1_response_emitted = false;
        conn.protocol = Protocol::Unknown;
    }
    // Note: For HTTP/2, don't clear pending_requests/pending_responses
    //       as they may contain other streams. The matched pair was
    //       already removed in build_exchange().
    // Note: Keep h2_*_state HPACK decoder for connection persistence.
    // Note: h2_emitted_* sets are cleaned up in build_exchange when
    //       the stream_id is removed from pending.
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

/// Feed chunk to h2session, classify by content after parsing.
///
/// Uses separate H2ConnectionState per direction to avoid corrupting frame
/// boundaries when Read and Write events interleave (e.g., WINDOW_UPDATEs
/// between DATA frames). Messages are classified by their pseudo-headers
/// (:method = request, :status = response), supporting both client-side
/// monitoring (Write=request, Read=response) and server-side monitoring
/// (Read=request, Write=response).
fn parse_http2_chunks(conn: &mut Conn, direction: Direction) {
    // Check for fd-reuse: a new h2 connection preface on a connection that
    // already processed one means the kernel reused the file descriptor for
    // a new TCP connection. We must reset BOTH directions' parsers since the
    // new connection has fresh HPACK context on both sides.
    let last_chunk_is_preface = match direction {
        Direction::Write => conn
            .request_chunks
            .last()
            .map_or(false, |c| is_http2_preface(&c.data)),
        Direction::Read => conn
            .response_chunks
            .last()
            .map_or(false, |c| is_http2_preface(&c.data)),
        Direction::Other => false,
    };
    let current_state_has_preface = match direction {
        Direction::Write => conn.h2_write_state.preface_received,
        Direction::Read => conn.h2_read_state.preface_received,
        Direction::Other => false,
    };

    if last_chunk_is_preface && current_state_has_preface {
        conn.h2_write_state = H2ConnectionState::new();
        conn.h2_read_state = H2ConnectionState::new();
        conn.pending_requests.clear();
        conn.pending_responses.clear();
        conn.h2_emitted_requests.clear();
        conn.h2_emitted_responses.clear();
    }

    let (chunks, h2_state) = match direction {
        Direction::Write => (&conn.request_chunks, &mut conn.h2_write_state),
        Direction::Read => (&conn.response_chunks, &mut conn.h2_read_state),
        Direction::Other => return,
    };

    let chunk = match chunks.last() {
        Some(c) => c,
        None => return,
    };

    // Feed to direction-specific h2 parser; errors are non-fatal
    let _ = h2_state.feed(&chunk.data, chunk.timestamp_ns);

    // Pop completed messages and classify by content, not direction
    while let Some((stream_id, msg)) = h2_state.try_pop() {
        if msg.is_request() {
            conn.pending_requests.insert(stream_id, msg);
        } else if msg.is_response() {
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

            // Clean up emission tracking for this stream
            conn.h2_emitted_requests.remove(&sid);
            conn.h2_emitted_responses.remove(&sid);

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
        let events = collator.add_event(&event);

        // Should have emitted a request Message with the full 32KB body
        let request_msg = events.iter().find_map(|e| {
            if let Some((msg, _)) = e.as_message() {
                if msg.is_request() {
                    return Some(msg.clone());
                }
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

        let req1_event =
            make_event(Direction::Read, conn_id, process_id, 80, 1_000_000, &req1);
        let _ = collator.add_event(&req1_event);

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

        let resp1_event = make_event(
            Direction::Write,
            conn_id,
            process_id,
            80,
            2_000_000,
            &resp1,
        );
        let events1 = collator.add_event(&resp1_event);
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

        let req2_event = make_event(
            Direction::Read,
            conn_id,
            process_id,
            80,
            3_000_000,
            &req2,
        );
        let events2 = collator.add_event(&req2_event);

        // Should have emitted a request Message for the second connection
        let request_msg = events2.iter().find_map(|e| {
            if let Some((msg, _)) = e.as_message() {
                if msg.is_request() {
                    return Some(msg.clone());
                }
            }
            None
        });
        let request = request_msg.expect(
            "Second h2 connection on reused fd should parse successfully",
        );
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

        let req1_event =
            make_event(Direction::Read, conn_id, process_id, 80, 1_000_000, &req1);
        let _ = collator.add_event(&req1_event);

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

        let resp1_event = make_event(
            Direction::Write,
            conn_id,
            process_id,
            80,
            2_000_000,
            &resp1,
        );
        let events1 = collator.add_event(&resp1_event);
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
        let goaway_event = make_event(
            Direction::Read,
            conn_id,
            process_id,
            80,
            2_500_000,
            &goaway,
        );
        let _ = collator.add_event(&goaway_event);

        // --- Second exchange: same conn_id (fd reused), large POST body ---
        // Build the full request data, then split it into realistic chunks
        let body = vec![0x42u8; 32768]; // 32KB of 'B'

        // Use a POST request HPACK block
        let mut post_hpack = Vec::new();
        post_hpack.push(0x83); // :method: POST (static index 3)
        post_hpack.push(0x87); // :scheme: https (static index 7)
        post_hpack.push(0x84); // :path: / (static index 4)
        post_hpack.push(0x01); // :authority indexed name
        post_hpack.push(0x0b); // value length 11
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
            let _ = collator.add_event(&event);
            prev = end;
            ts += 100_000;
        }
        // Send remaining data
        if prev < full_request.len() {
            let chunk = &full_request[prev..];
            let event = make_event(Direction::Read, conn_id, process_id, 80, ts, chunk);
            let _ = collator.add_event(&event);
            ts += 100_000;
        }

        // Verify the request was parsed
        let conn = collator.connections.get(&conn_id).unwrap();
        assert!(
            conn.pending_requests.contains_key(&1),
            "Second exchange request should be in pending_requests"
        );
        let req = conn.pending_requests.get(&1).unwrap();
        assert_eq!(
            req.body.len(),
            32768,
            "Body should be 32KB, got {} bytes",
            req.body.len()
        );

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

        let resp2_event = make_event(
            Direction::Write,
            conn_id,
            process_id,
            80,
            ts,
            &resp2,
        );
        let events2 = collator.add_event(&resp2_event);

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
        let events = collator.add_event(&resp_event);

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

    // =========================================================================
    // CollatorConfig tests
    // =========================================================================

    #[test]
    fn test_messages_only_config() {
        let config = CollatorConfig::messages_only();
        assert!(config.emit_messages);
        assert!(!config.emit_exchanges);
    }

    #[test]
    fn test_exchanges_only_config() {
        let config = CollatorConfig::exchanges_only();
        assert!(!config.emit_messages);
        assert!(config.emit_exchanges);
    }

    #[test]
    fn test_default_config_emits_both() {
        let config = CollatorConfig::default();
        assert!(config.emit_messages);
        assert!(config.emit_exchanges);
    }

    // =========================================================================
    // Message emission tests
    // =========================================================================

    #[test]
    fn test_http1_emits_request_message() {
        let mut collator: Collator<TestEvent> =
            Collator::with_config(CollatorConfig::messages_only());

        let event = make_event(
            Direction::Write,
            1,
            1234,
            8080,
            1_000_000,
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        );

        let events = collator.add_event(&event);

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
        let mut collator: Collator<TestEvent> =
            Collator::with_config(CollatorConfig::messages_only());

        let event = make_event(
            Direction::Read,
            1,
            1234,
            8080,
            1_000_000,
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        );

        let events = collator.add_event(&event);

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
        let events = collator.add_event(&req_event);
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
        let events = collator.add_event(&resp_event);

        // Should have response Message + Exchange
        assert_eq!(events.len(), 2, "Response should emit Message + Exchange");
        assert!(events.iter().any(|e| e.is_message()));
        assert!(events.iter().any(|e| e.is_exchange()));
    }

    #[test]
    fn test_exchanges_only_skips_message_events() {
        let mut collator: Collator<TestEvent> =
            Collator::with_config(CollatorConfig::exchanges_only());

        // Send request
        let req_event = make_event(
            Direction::Write,
            1,
            1234,
            8080,
            1_000_000,
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        );
        let events = collator.add_event(&req_event);
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
        let events = collator.add_event(&resp_event);

        // Should only have Exchange, no Message
        assert_eq!(events.len(), 1);
        assert!(events[0].is_exchange());
    }

    #[test]
    fn test_message_not_emitted_twice() {
        let mut collator: Collator<TestEvent> =
            Collator::with_config(CollatorConfig::messages_only());

        // Send request in two chunks
        let event1 = make_event(
            Direction::Write,
            1,
            1234,
            8080,
            1_000_000,
            b"GET / HTTP/1.1\r\n",
        );
        let events1 = collator.add_event(&event1);
        assert!(events1.is_empty(), "Incomplete request should not emit");

        let event2 = make_event(
            Direction::Write,
            1,
            1234,
            8080,
            2_000_000,
            b"Host: example.com\r\n\r\n",
        );
        let events2 = collator.add_event(&event2);
        assert_eq!(events2.len(), 1, "Complete request should emit once");

        // Another chunk on same connection (no new request data)
        let event3 = make_event(Direction::Write, 1, 1234, 8080, 3_000_000, b"");
        let events3 = collator.add_event(&event3);
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
        let events = collator.add_event(&req_event);

        // Should have emitted a request Message event
        let request_msg = events.iter().find_map(|e| {
            if let Some((msg, _)) = e.as_message() {
                if msg.is_request() {
                    return Some(msg.clone());
                }
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
        let events = collator.add_event(&resp_event);

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
}
