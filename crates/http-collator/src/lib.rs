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
//! if let Some(exchange) = collator.add_event(my_event) {
//!     println!("Complete exchange: {}", exchange);
//! }
//! ```

mod connection;
mod exchange;
pub mod h1;
mod traits;

use std::marker::PhantomData;

use connection::Connection as Conn;
pub use connection::{Connection, DataChunk, Protocol};
use dashmap::DashMap;
pub use exchange::{CollationEvent, CollatorConfig, Exchange, MessageMetadata, ParsedHttpMessage};
pub use h1::{HttpRequest, HttpResponse};
use h2session::{
    H2ConnectionState,
    StreamId,
    TimestampNs,
    is_http2_preface,
    looks_like_http2_frame,
};
pub use traits::{DataEvent, Direction};

/// Default maximum buffer size for data events (TLS record size)
pub const MAX_BUF_SIZE: usize = 16384;

/// Collates individual data events into complete request/response exchanges.
///
/// Generic over the event type `E` which must implement [`DataEvent`].
/// Uses per-connection locking via `DashMap` so concurrent HTTP/2 connections
/// do not serialize through a single mutex.
pub struct Collator<E: DataEvent> {
    /// Connections tracked by conn_id (for socket events)
    connections:     DashMap<u64, Conn>,
    /// SSL connections tracked by process_id (no conn_id available)
    ssl_connections: DashMap<u32, Conn>,
    /// Configuration for what events to emit
    config:          CollatorConfig,
    /// Phantom data for the event type
    _phantom:        PhantomData<E>,
}

impl<E: DataEvent> Default for Collator<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: DataEvent> Collator<E> {
    /// Create a new collator with default settings (emits both messages and
    /// exchanges)
    pub fn new() -> Self {
        Self::with_config(CollatorConfig::default())
    }

    /// Create a new collator with custom configuration
    pub fn with_config(config: CollatorConfig) -> Self {
        Self {
            connections: DashMap::new(),
            ssl_connections: DashMap::new(),
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

    /// Process a data event, returning all resulting collation events.
    ///
    /// Takes ownership of the event to enable zero-copy transfer of the
    /// payload into `DataChunk` via `into_payload()`.
    ///
    /// Returns Vec because:
    /// - HTTP/2 can have multiple streams complete in one buffer
    /// - A single buffer might contain complete request AND start of next
    /// - Config might emit both messages AND exchanges
    pub fn add_event(&self, event: E) -> Vec<CollationEvent> {
        // Extract all scalar metadata before consuming the event
        let direction = event.direction();
        let timestamp_ns = TimestampNs(event.timestamp_ns());
        let conn_id = event.connection_id();
        let process_id = event.process_id();
        let remote_port = event.remote_port();
        let is_empty = event.payload().is_empty();

        if is_empty {
            return Vec::new();
        }

        // Skip non-data events
        if direction == Direction::Other {
            return Vec::new();
        }

        // Move payload ownership via into_payload() — avoids cloning for
        // implementors that already hold a Bytes or Vec<u8>.
        let data = event.into_payload();

        let chunk = DataChunk {
            data,
            timestamp_ns,
            direction,
        };

        // DashMap entry() locks only the shard for this connection, allowing
        // concurrent access to other connections.
        if conn_id != 0 {
            let mut conn = self
                .connections
                .entry(conn_id)
                .or_insert_with(|| Conn::new(process_id, remote_port));
            Self::process_event_for_conn(
                &mut conn,
                chunk,
                direction,
                timestamp_ns,
                remote_port,
                conn_id,
                process_id,
                &self.config,
            )
        } else {
            let mut conn = self
                .ssl_connections
                .entry(process_id)
                .or_insert_with(|| Conn::new(process_id, remote_port));
            Self::process_event_for_conn(
                &mut conn,
                chunk,
                direction,
                timestamp_ns,
                remote_port,
                conn_id,
                process_id,
                &self.config,
            )
        }
    }

    /// Core event processing logic, called with a mutable reference to the
    /// connection (obtained from a `DashMap` entry guard).
    #[allow(clippy::too_many_arguments)]
    fn process_event_for_conn(
        conn: &mut Conn,
        chunk: DataChunk,
        direction: Direction,
        timestamp_ns: TimestampNs,
        remote_port: u16,
        conn_id: u64,
        process_id: u32,
        config: &CollatorConfig,
    ) -> Vec<CollationEvent> {
        let buf: &[u8] = &chunk.data;

        conn.last_activity_ns = timestamp_ns;
        if remote_port != 0 && conn.remote_port.is_none() {
            conn.remote_port = Some(remote_port);
        }

        // Detect protocol from first chunk if unknown
        if conn.protocol == Protocol::Unknown {
            conn.protocol = detect_protocol(buf);
        }

        // Detect protocol change on an established connection (FD reuse).
        if conn.protocol != Protocol::Unknown {
            let incoming_protocol = detect_protocol(buf);
            if incoming_protocol != Protocol::Unknown && incoming_protocol != conn.protocol {
                reset_connection_for_protocol_change(conn, incoming_protocol);
            }
        }

        // Add chunk to appropriate buffer based on direction
        match direction {
            Direction::Write => {
                conn.request_body_size += buf.len();
                if conn.request_body_size > config.max_body_size {
                    reset_connection_body_limit(conn);
                    return Vec::new();
                }

                if conn.protocol == Protocol::Http1 {
                    conn.h1_request_buffer.extend_from_slice(buf);
                }
                conn.request_chunks.push(chunk);

                match conn.protocol {
                    Protocol::Http1 if conn.h1_request.is_none() => {
                        try_parse_http1_request_chunks(conn);
                    },
                    Protocol::Http2 => {
                        parse_http2_chunks(conn, direction);
                    },
                    _ => {},
                }

                if is_request_complete(conn) {
                    conn.request_complete = true;
                }
            },
            Direction::Read => {
                conn.response_body_size += buf.len();
                if conn.response_body_size > config.max_body_size {
                    reset_connection_body_limit(conn);
                    return Vec::new();
                }

                if conn.protocol == Protocol::Http1 {
                    conn.h1_response_buffer.extend_from_slice(buf);
                }
                conn.response_chunks.push(chunk);

                match conn.protocol {
                    Protocol::Http1 if conn.h1_response.is_none() => {
                        try_parse_http1_response_chunks(conn);
                    },
                    Protocol::Http2 => {
                        parse_http2_chunks(conn, direction);
                    },
                    _ => {},
                }

                if is_response_complete(conn) {
                    conn.response_complete = true;
                }
            },
            Direction::Other => {
                return Vec::new();
            },
        }

        // For HTTP/2, a complete stream pair can be detected on either event.
        if conn.protocol == Protocol::Http2 && find_complete_h2_stream(conn).is_some() {
            conn.request_complete = true;
            conn.response_complete = true;
        }

        let mut events = Vec::new();

        if config.emit_messages {
            emit_message_events(conn, conn_id, process_id, &mut events);
        }

        if config.emit_exchanges && conn.request_complete && conn.response_complete {
            if let Some(exchange) = build_exchange(conn) {
                events.push(CollationEvent::Exchange(exchange));
            }
            reset_connection_after_exchange(conn);
        }

        events
    }

    /// Clean up stale connections and evict stale H2 streams.
    ///
    /// Callers should invoke this periodically to bound memory usage from
    /// abandoned connections and incomplete HTTP/2 streams.
    pub fn cleanup(&self, current_time_ns: TimestampNs) {
        self.connections.retain(|_, conn| {
            current_time_ns.saturating_sub(conn.last_activity_ns) < self.config.timeout_ns
        });
        self.ssl_connections.retain(|_, conn| {
            current_time_ns.saturating_sub(conn.last_activity_ns) < self.config.timeout_ns
        });

        // Evict stale H2 streams within surviving connections
        for mut entry in self.connections.iter_mut() {
            entry.h2_write_state.evict_stale_streams(current_time_ns);
            entry.h2_read_state.evict_stale_streams(current_time_ns);
        }
        for mut entry in self.ssl_connections.iter_mut() {
            entry.h2_write_state.evict_stale_streams(current_time_ns);
            entry.h2_read_state.evict_stale_streams(current_time_ns);
        }
    }

    /// Remove a connection explicitly (e.g., on connection close)
    ///
    /// Call this when a connection is closed to free resources immediately.
    /// If connection_id is 0, removes based on process_id from SSL connections.
    pub fn remove_connection(&self, connection_id: u64, process_id: u32) {
        if connection_id != 0 {
            self.connections.remove(&connection_id);
        } else {
            self.ssl_connections.remove(&process_id);
        }
    }

    /// Close a connection, finalizing any pending HTTP/1 response.
    ///
    /// For HTTP/1 responses without explicit framing (no Content-Length or
    /// Transfer-Encoding), RFC 7230 §3.3.3 says the body extends until the
    /// connection closes. This method finalizes such responses with whatever
    /// body has accumulated so far, emits any resulting events, then removes
    /// the connection.
    pub fn close_connection(&self, connection_id: u64, process_id: u32) -> Vec<CollationEvent> {
        let events = if connection_id != 0 {
            match self.connections.get_mut(&connection_id) {
                Some(mut guard) => {
                    finalize_and_emit(&mut guard, connection_id, process_id, &self.config)
                },
                None => Vec::new(),
            }
        } else {
            match self.ssl_connections.get_mut(&process_id) {
                Some(mut guard) => {
                    finalize_and_emit(&mut guard, connection_id, process_id, &self.config)
                },
                None => Vec::new(),
            }
        };

        // Remove the connection after releasing the guard
        if connection_id != 0 {
            self.connections.remove(&connection_id);
        } else {
            self.ssl_connections.remove(&process_id);
        }

        events
    }
}

/// Finalize any pending HTTP/1 response and emit events on connection close.
fn finalize_and_emit(
    conn: &mut Conn,
    connection_id: u64,
    process_id: u32,
    config: &CollatorConfig,
) -> Vec<CollationEvent> {
    // Finalize any pending HTTP/1 response with body accumulated so far
    if conn.protocol == Protocol::Http1
        && conn.h1_response.is_none()
        && !conn.h1_response_buffer.is_empty()
    {
        let timestamp = conn
            .response_chunks
            .first()
            .map(|c| c.timestamp_ns)
            .unwrap_or(TimestampNs(0));
        conn.h1_response = h1::try_finalize_http1_response(&conn.h1_response_buffer, timestamp);
        if conn.h1_response.is_some() {
            conn.response_complete = true;
        }
    }

    let mut events = Vec::new();

    if config.emit_messages {
        emit_message_events(conn, connection_id, process_id, &mut events);
    }

    if config.emit_exchanges
        && conn.request_complete
        && conn.response_complete
        && let Some(exchange) = build_exchange(conn)
    {
        events.push(CollationEvent::Exchange(exchange));
    }

    events
}

/// Emit Message events for any newly parsed messages that haven't been emitted
/// yet
fn emit_message_events(
    conn: &mut Conn,
    conn_id: u64,
    process_id: u32,
    events: &mut Vec<CollationEvent>,
) {
    match conn.protocol {
        Protocol::Http1 => {
            // Emit request if parsed and not yet emitted
            if let Some(ref req) = conn.h1_request
                && !conn.h1_request_emitted
            {
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

            // Emit response if parsed and not yet emitted
            if let Some(ref resp) = conn.h1_response
                && !conn.h1_response_emitted
            {
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
        },
        Protocol::Http2 => {
            // Emit newly parsed HTTP/2 requests
            for (&stream_id, msg) in &conn.pending_requests {
                if !conn.h2_emitted_requests.contains(&stream_id)
                    && let Some(req) = msg.to_http_request()
                {
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
            // Mark all current pending requests as emitted
            conn.h2_emitted_requests
                .extend(conn.pending_requests.keys().copied());

            // Emit newly parsed HTTP/2 responses
            for (&stream_id, msg) in &conn.pending_responses {
                if !conn.h2_emitted_responses.contains(&stream_id)
                    && let Some(resp) = msg.to_http_response()
                {
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
            // Mark all current pending responses as emitted
            conn.h2_emitted_responses
                .extend(conn.pending_responses.keys().copied());
        },
        Protocol::Unknown => {},
    }
}

/// Reset connection state after emitting an exchange
fn reset_connection_after_exchange(conn: &mut Conn) {
    conn.request_complete = false;
    conn.response_complete = false;

    if conn.protocol == Protocol::Http1 {
        // HTTP/1: clear everything for the next exchange
        conn.request_chunks.clear();
        conn.response_chunks.clear();
        conn.h1_request = None;
        conn.h1_response = None;
        conn.h1_request_emitted = false;
        conn.h1_response_emitted = false;
        conn.h1_request_buffer.clear();
        conn.h1_response_buffer.clear();
        conn.protocol = Protocol::Unknown;
    } else if conn.protocol == Protocol::Http2 {
        // HTTP/2: only clear chunks if no other pending messages remain.
        // The matched pair was already removed in build_exchange().
        // Keep h2_*_state HPACK decoder for connection persistence.
        // h2_emitted_* sets are cleaned up in build_exchange when
        // the stream_id is removed from pending.
        if conn.pending_requests.is_empty() && conn.pending_responses.is_empty() {
            conn.request_chunks.clear();
            conn.response_chunks.clear();
            conn.h2_write_state.clear_buffer();
            conn.h2_read_state.clear_buffer();
        }
    }

    // Reset body size tracking for the next exchange
    conn.request_body_size = 0;
    conn.response_body_size = 0;
}

/// Reset connection when accumulated body size exceeds the limit.
/// Drops all accumulated data and parsed state for this connection.
fn reset_connection_body_limit(conn: &mut Conn) {
    conn.request_chunks.clear();
    conn.response_chunks.clear();
    conn.h1_request_buffer.clear();
    conn.h1_response_buffer.clear();
    conn.h1_request = None;
    conn.h1_response = None;
    conn.h1_request_emitted = false;
    conn.h1_response_emitted = false;
    conn.h2_write_state = H2ConnectionState::new();
    conn.h2_read_state = H2ConnectionState::new();
    conn.pending_requests.clear();
    conn.pending_responses.clear();
    conn.h2_emitted_requests.clear();
    conn.h2_emitted_responses.clear();
    conn.ready_streams.clear();
    conn.request_complete = false;
    conn.response_complete = false;
    conn.request_body_size = 0;
    conn.response_body_size = 0;
    conn.protocol = Protocol::Unknown;
}

/// Reset connection when the detected protocol changes (FD reuse with
/// different protocol, e.g., HTTP/2 followed by HTTP/1 on the same fd).
fn reset_connection_for_protocol_change(conn: &mut Conn, new_protocol: Protocol) {
    conn.request_chunks.clear();
    conn.response_chunks.clear();
    conn.h1_request_buffer.clear();
    conn.h1_response_buffer.clear();
    conn.h1_request = None;
    conn.h1_response = None;
    conn.h1_request_emitted = false;
    conn.h1_response_emitted = false;
    conn.h2_write_state = H2ConnectionState::new();
    conn.h2_read_state = H2ConnectionState::new();
    conn.pending_requests.clear();
    conn.pending_responses.clear();
    conn.h2_emitted_requests.clear();
    conn.h2_emitted_responses.clear();
    conn.ready_streams.clear();
    conn.request_complete = false;
    conn.response_complete = false;
    conn.request_body_size = 0;
    conn.response_body_size = 0;
    conn.protocol = new_protocol;
}

pub fn detect_protocol(data: &[u8]) -> Protocol {
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
            .is_some_and(|c| is_http2_preface(&c.data)),
        Direction::Read => conn
            .response_chunks
            .last()
            .is_some_and(|c| is_http2_preface(&c.data)),
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
        conn.ready_streams.clear();
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

    // Pop completed messages and classify by content, not direction.
    // Maintain ready_streams set for O(1) complete-pair lookup.
    while let Some((stream_id, msg)) = h2_state.try_pop() {
        if msg.is_request() {
            conn.pending_requests.insert(stream_id, msg);
            if conn.pending_responses.contains_key(&stream_id) {
                conn.ready_streams.insert(stream_id);
            }
        } else if msg.is_response() {
            conn.pending_responses.insert(stream_id, msg);
            if conn.pending_requests.contains_key(&stream_id) {
                conn.ready_streams.insert(stream_id);
            }
        }
    }
}

/// Find a stream_id that has both request and response ready (O(1) via
/// ready_streams set)
fn find_complete_h2_stream(conn: &Conn) -> Option<StreamId> {
    conn.ready_streams.iter().next().copied()
}

/// Try to parse HTTP/1 request from accumulated buffer.
/// If complete, stores the parsed request in conn.h1_request.
fn try_parse_http1_request_chunks(conn: &mut Conn) {
    let timestamp = conn
        .request_chunks
        .last()
        .map(|c| c.timestamp_ns)
        .unwrap_or(TimestampNs(0));
    conn.h1_request = h1::try_parse_http1_request(&conn.h1_request_buffer, timestamp);
}

/// Try to parse HTTP/1 response from accumulated buffer.
/// If complete, stores the parsed response in conn.h1_response.
fn try_parse_http1_response_chunks(conn: &mut Conn) {
    let timestamp = conn
        .response_chunks
        .first()
        .map(|c| c.timestamp_ns)
        .unwrap_or(TimestampNs(0));
    conn.h1_response = h1::try_parse_http1_response(&conn.h1_response_buffer, timestamp);
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
        },
        Protocol::Http2 => {
            let sid = find_complete_h2_stream(conn)?;
            let msg_req = conn.pending_requests.remove(&sid)?;
            let msg_resp = conn.pending_responses.remove(&sid)?;

            // Clean up emission and ready tracking for this stream
            conn.h2_emitted_requests.remove(&sid);
            conn.h2_emitted_responses.remove(&sid);
            conn.ready_streams.remove(&sid);

            // For HTTP/2, use per-stream timestamps from the parsed messages
            // Request complete time: when END_STREAM was seen on request
            // Response start time: when first frame was received on response
            let request_complete_time = msg_req.end_stream_timestamp_ns;
            let response_start_time = msg_resp.first_frame_timestamp_ns;

            let req = msg_req.into_http_request()?;
            let resp = msg_resp.into_http_response()?;

            let latency = response_start_time.saturating_sub(request_complete_time);
            (req, resp, Some(sid), latency)
        },
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
mod tests;
