#![warn(missing_docs)]
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
//! ```no_run
//! use http_collator::{Collator, CollationEvent, DataEvent, Direction};
//! use bytes::Bytes;
//!
//! struct MyEvent {
//!     payload: Vec<u8>,
//!     timestamp_ns: u64,
//!     direction: Direction,
//!     connection_id: u128,
//!     process_id: u32,
//!     remote_port: u16,
//! }
//!
//! impl DataEvent for MyEvent {
//!     fn payload(&self) -> &[u8] { &self.payload }
//!     fn timestamp_ns(&self) -> u64 { self.timestamp_ns }
//!     fn direction(&self) -> Direction { self.direction }
//!     fn connection_id(&self) -> u128 { self.connection_id }
//!     fn process_id(&self) -> u32 { self.process_id }
//!     fn remote_port(&self) -> u16 { self.remote_port }
//! }
//!
//! let collator = Collator::<MyEvent>::new();
//! # let my_event = MyEvent { payload: vec![], timestamp_ns: 0, direction: Direction::Write, connection_id: 1, process_id: 1, remote_port: 80 };
//! for event in collator.add_event(my_event) {
//!     match event {
//!         CollationEvent::Message { message, metadata } => {
//!             println!("parsed message for conn {}", metadata.connection_id);
//!         }
//!         CollationEvent::Exchange(exchange) => {
//!             println!("complete exchange: {exchange}");
//!         }
//!     }
//! }
//! ```
//!
//! # Feature flags
//!
//! - **`tracing`** — emit `tracing` spans and events for connection processing
//!   and parse errors. Enables tracing in `h2session` and `h3session`
//!   dependencies as well.

#[cfg(feature = "tracing")]
macro_rules! trace_warn {
    ($($arg:tt)*) => { ::tracing::warn!($($arg)*) }
}
#[cfg(not(feature = "tracing"))]
macro_rules! trace_warn {
    ($($arg:tt)*) => {};
}

mod connection;
mod exchange;
pub mod h1;
mod traits;

use std::marker::PhantomData;

pub use connection::Protocol;
use connection::{Connection as Conn, DataChunk};
pub use exchange::{CollationEvent, CollatorConfig, Exchange, MessageMetadata, ParsedHttpMessage};
pub use h1::{HttpRequest, HttpResponse};
use h2session::{
    H2ConnectionState,
    StreamId,
    TimestampNs,
    is_http2_preface,
    looks_like_http2_frame,
};
use h3session::H3ConnectionState;
use scc::HashMap as ConcurrentMap;
pub use traits::{DataEvent, Direction};

/// Default maximum buffer size for data events (TLS record size)
pub const MAX_BUF_SIZE: usize = 16384;

/// Tracks HTTP/3 state for a single QUIC connection.
/// Each QUIC connection can have multiple concurrent streams (requests).
struct QuicConnection {
    h3_state: H3ConnectionState,
    last_activity_ns: TimestampNs,
    /// Pending requests awaiting their response (keyed by stream_id)
    pending_requests: std::collections::HashMap<i64, HttpRequest>,
    /// Pre-registered response headers from submit_response probes (plaintext,
    /// captured before QPACK encoding). Keyed by stream_id.
    submitted_response_headers: std::collections::HashMap<i64, Vec<(String, String)>>,
}

/// Collates individual data events into complete request/response exchanges.
///
/// Generic over the event type `E` which must implement [`DataEvent`].
/// Uses per-connection locking via `scc::HashMap` so concurrent HTTP/2
/// connections do not serialize through a single mutex.
pub struct Collator<E: DataEvent> {
    /// Connections tracked by conn_id (for socket events)
    connections:      ConcurrentMap<u128, Conn>,
    /// SSL connections tracked by process_id (no conn_id available)
    ssl_connections:  ConcurrentMap<u32, Conn>,
    /// QUIC connections tracked by conn_id (tgid << 64 | conn_ptr)
    quic_connections: ConcurrentMap<u128, QuicConnection>,
    /// Configuration for what events to emit
    config:           CollatorConfig,
    /// Phantom data for the event type
    _phantom:         PhantomData<E>,
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
            connections: ConcurrentMap::new(),
            ssl_connections: ConcurrentMap::new(),
            quic_connections: ConcurrentMap::new(),
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
    #[cfg_attr(feature = "tracing", tracing::instrument(skip_all, fields(
        conn_id = event.connection_id(),
        pid = event.process_id(),
        dir = ?event.direction(),
    )))]
    pub fn add_event(&self, event: E) -> Vec<CollationEvent> {
        // Extract all scalar metadata before consuming the event
        let direction = event.direction();
        let timestamp_ns = TimestampNs(event.timestamp_ns());
        let conn_id = event.connection_id();
        let process_id = event.process_id();
        let remote_port = event.remote_port();
        let local_port = event.local_port();
        let stream_id = event.stream_id();
        let is_fin = event.is_fin();
        let is_empty = event.payload().is_empty();
        let command = event.command_name().to_string();
        let is_submit_response = event.is_submit_response();
        let is_unframed = event.is_quiche_unframed();
        let proxy_metadata = event.proxy_metadata();

        // QUIC/HTTP3 events: route even if empty (FIN-only signals)
        if let Some(sid) = stream_id {
            if is_submit_response {
                let payload = event.into_payload();
                self.register_submit_response(conn_id, sid, &payload, timestamp_ns);
                return Vec::new();
            }
            if is_empty && !is_fin {
                return Vec::new();
            }
            let payload = event.into_payload();
            return self.process_quic_event(
                conn_id,
                process_id,
                &command,
                sid,
                &payload,
                timestamp_ns,
                is_fin,
                is_unframed,
            );
        }

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

        if conn_id != 0 {
            let mut entry = self
                .connections
                .entry(conn_id)
                .or_insert_with(|| Conn::new(process_id, remote_port, local_port, command.clone()));
            let conn = entry.get_mut();
            if conn.proxy_metadata == 0 && proxy_metadata != 0 {
                conn.proxy_metadata = proxy_metadata;
            }
            Self::process_event_for_conn(
                conn,
                chunk,
                direction,
                timestamp_ns,
                remote_port,
                conn_id,
                process_id,
                &command,
                &self.config,
            )
        } else {
            let mut entry = self
                .ssl_connections
                .entry(process_id)
                .or_insert_with(|| Conn::new(process_id, remote_port, local_port, command.clone()));
            let conn = entry.get_mut();
            if conn.proxy_metadata == 0 && proxy_metadata != 0 {
                conn.proxy_metadata = proxy_metadata;
            }
            Self::process_event_for_conn(
                conn,
                chunk,
                direction,
                timestamp_ns,
                remote_port,
                conn_id,
                process_id,
                &command,
                &self.config,
            )
        }
    }

    /// Process a QUIC/HTTP3 event: feed to h3session and check for completed
    /// messages.
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self, payload), fields(conn_id, stream_id, fin))
    )]
    fn process_quic_event(
        &self,
        conn_id: u128,
        process_id: u32,
        command: &str,
        stream_id: i64,
        payload: &[u8],
        timestamp_ns: TimestampNs,
        fin: bool,
        unframed: bool,
    ) -> Vec<CollationEvent> {
        use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};

        let mut quic_entry =
            self.quic_connections
                .entry(conn_id)
                .or_insert_with(|| QuicConnection {
                    h3_state: H3ConnectionState::new(),
                    last_activity_ns: TimestampNs(0),
                    pending_requests: std::collections::HashMap::new(),
                    submitted_response_headers: std::collections::HashMap::new(),
                });
        let quic_conn = quic_entry.get_mut();

        quic_conn.last_activity_ns = timestamp_ns;
        if unframed {
            quic_conn
                .h3_state
                .feed_unframed(stream_id, payload, timestamp_ns.0, fin);
        } else {
            quic_conn
                .h3_state
                .feed(stream_id, payload, timestamp_ns.0, fin);
        }

        let mut events = Vec::new();
        while let Some((sid, msg)) = quic_conn.h3_state.try_pop() {
            // Client-initiated bidirectional streams (sid % 4 == 0) carry
            // request/response pairs. If QPACK decoding failed (empty headers),
            // treat the message as a response on these streams.
            let is_request = msg.is_request();
            let is_response = msg.is_response()
                || (!is_request
                    && sid % 4 == 0
                    && (msg.headers.is_empty() || !msg.body.is_empty()));

            if is_request {
                let Some(method) = msg.method().and_then(|m| m.parse::<Method>().ok()) else {
                    continue;
                };
                let uri: Uri = msg
                    .path()
                    .unwrap_or("/")
                    .parse()
                    .unwrap_or(Uri::from_static("/"));

                let mut headers = HeaderMap::new();
                for (name, value) in &msg.headers {
                    if name == ":method" || name == ":path" {
                        continue;
                    }
                    let header_name = name.strip_prefix(':').unwrap_or(name.as_str());
                    if let (Ok(hn), Ok(hv)) = (
                        HeaderName::from_bytes(header_name.as_bytes()),
                        HeaderValue::from_str(value),
                    ) {
                        headers.append(hn, hv);
                    }
                }

                let request = HttpRequest {
                    method,
                    uri,
                    headers,
                    body: msg.body.to_vec(),
                    timestamp_ns: TimestampNs(msg.end_stream_timestamp_ns),
                    version: None,
                };

                if self.config.emit_messages {
                    events.push(CollationEvent::Message {
                        message:  ParsedHttpMessage::Request(request.clone()),
                        metadata: MessageMetadata {
                            connection_id: conn_id,
                            process_id,
                            command: command.to_string(),
                            timestamp_ns,
                            stream_id: Some(StreamId(sid as u32)),
                            remote_port: None,
                            local_port: None,
                            protocol: Protocol::Http3,
                        },
                    });
                }

                // Store pending request — response will arrive on the same stream
                quic_conn.pending_requests.insert(sid, request);
            } else if is_response {
                // Use pre-registered headers from submit_response if QPACK
                // decode yielded nothing beyond :status
                let submitted = quic_conn.submitted_response_headers.remove(&sid);
                let use_submitted =
                    submitted.is_some() && msg.headers.iter().all(|(n, _)| n.starts_with(':'));

                let effective_headers: &[(String, String)] = if use_submitted {
                    submitted.as_ref().unwrap()
                } else {
                    &msg.headers
                };

                let status = if use_submitted {
                    effective_headers
                        .iter()
                        .find(|(n, _)| n == ":status")
                        .and_then(|(_, v)| v.parse::<u16>().ok())
                        .and_then(|s| StatusCode::from_u16(s).ok())
                        .unwrap_or_else(|| {
                            msg.status()
                                .and_then(|s| StatusCode::from_u16(s).ok())
                                .unwrap_or(StatusCode::OK)
                        })
                } else {
                    msg.status()
                        .and_then(|s| StatusCode::from_u16(s).ok())
                        .unwrap_or(StatusCode::OK)
                };

                let mut headers = HeaderMap::new();
                for (name, value) in effective_headers {
                    if name == ":status" {
                        continue;
                    }
                    let header_name = name.strip_prefix(':').unwrap_or(name.as_str());
                    if let (Ok(hn), Ok(hv)) = (
                        HeaderName::from_bytes(header_name.as_bytes()),
                        HeaderValue::from_str(value),
                    ) {
                        headers.append(hn, hv);
                    }
                }

                let response = HttpResponse {
                    status,
                    headers,
                    body: msg.body.to_vec(),
                    timestamp_ns: TimestampNs(msg.first_frame_timestamp_ns),
                    version: None,
                    reason: None,
                };

                // Pair with pending request on the same stream, or emit with placeholder
                let (request, latency_ns) =
                    if let Some(req) = quic_conn.pending_requests.remove(&sid) {
                        let latency = msg
                            .first_frame_timestamp_ns
                            .saturating_sub(req.timestamp_ns.0);
                        (req, latency)
                    } else {
                        // No captured request (write probe may not have fired)
                        let placeholder = HttpRequest {
                            method:       Method::GET,
                            uri:          Uri::from_static("/"),
                            headers:      HeaderMap::new(),
                            body:         Vec::new(),
                            timestamp_ns: TimestampNs(msg.first_frame_timestamp_ns),
                            version:      None,
                        };
                        (placeholder, 0)
                    };

                let exchange = Exchange {
                    request,
                    response,
                    latency_ns,
                    protocol: Protocol::Http3,
                    process_id,
                    command: command.to_string(),
                    remote_port: None,
                    local_port: None,
                    stream_id: Some(StreamId(sid as u32)),
                    proxy_metadata: 0,
                };

                if self.config.emit_exchanges {
                    events.push(CollationEvent::Exchange(exchange));
                }
            }
        }

        events
    }

    /// Register pre-decoded response headers captured from
    /// nghttp3_conn_submit_response. The payload is "name: value\n" lines
    /// (plaintext, before QPACK encoding).
    fn register_submit_response(
        &self,
        conn_id: u128,
        stream_id: i64,
        payload: &[u8],
        timestamp_ns: TimestampNs,
    ) {
        let payload_str = String::from_utf8_lossy(payload);
        let headers: Vec<(String, String)> = payload_str
            .lines()
            .filter_map(|line| {
                let (name, value) = line.split_once(": ")?;
                Some((name.to_string(), value.to_string()))
            })
            .collect();

        if headers.is_empty() {
            return;
        }

        let mut quic_entry =
            self.quic_connections
                .entry(conn_id)
                .or_insert_with(|| QuicConnection {
                    h3_state: H3ConnectionState::new(),
                    last_activity_ns: TimestampNs(0),
                    pending_requests: std::collections::HashMap::new(),
                    submitted_response_headers: std::collections::HashMap::new(),
                });
        let quic_conn = quic_entry.get_mut();

        quic_conn.last_activity_ns = timestamp_ns;
        quic_conn
            .submitted_response_headers
            .insert(stream_id, headers);
    }

    /// Core event processing logic, called with a mutable reference to the
    /// connection (obtained from an `scc::HashMap` entry guard).
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(feature = "tracing", tracing::instrument(skip_all, fields(
        conn_id, pid = process_id, protocol = ?conn.protocol, dir = ?direction,
    )))]
    fn process_event_for_conn(
        conn: &mut Conn,
        chunk: DataChunk,
        direction: Direction,
        timestamp_ns: TimestampNs,
        remote_port: u16,
        conn_id: u128,
        process_id: u32,
        command: &str,
        config: &CollatorConfig,
    ) -> Vec<CollationEvent> {
        let buf: &[u8] = &chunk.data;

        conn.last_activity_ns = timestamp_ns;
        if remote_port != 0 && conn.remote_port.is_none() {
            conn.remote_port = Some(remote_port);
        }
        if !command.is_empty() && conn.command.is_empty() {
            conn.command = command.to_string();
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

        let mut events = Vec::new();

        // Add chunk to appropriate buffer based on direction
        match direction {
            Direction::Write => {
                conn.request_body_size += buf.len();
                if conn.request_body_size > config.max_body_size {
                    reset_connection_body_limit(conn);
                    return Vec::new();
                }

                // Buffer for HTTP/1 and Unknown (Unknown may resolve to Http1)
                if conn.protocol == Protocol::Http1 || conn.protocol == Protocol::Unknown {
                    conn.h1_write_buffer.extend_from_slice(buf);
                }
                conn.request_chunks.push(chunk);

                match conn.protocol {
                    Protocol::Http1 => {
                        drain_parse_emit_http1_write(
                            conn,
                            conn_id,
                            process_id,
                            config,
                            &mut events,
                        );
                    },
                    Protocol::Http2 => {
                        parse_http2_chunks(conn, direction);
                    },
                    // For Unknown protocol, try HTTP/1 parsing — handles non-standard
                    // methods (WebDAV, etc.) that detect_protocol() doesn't recognize.
                    Protocol::Unknown => {
                        drain_parse_emit_http1_unknown_write(
                            conn,
                            conn_id,
                            process_id,
                            config,
                            &mut events,
                        );
                    },
                    // HTTP/3 is handled via separate quic_connections path
                    Protocol::Http3 => {},
                }

                // Content-based parsing: a response can be parsed from the
                // Write direction (server-side), so check both.
                if is_request_complete(conn) {
                    conn.request_complete = true;
                }
                if is_response_complete(conn) {
                    conn.response_complete = true;
                }
            },
            Direction::Read => {
                conn.response_body_size += buf.len();
                if conn.response_body_size > config.max_body_size {
                    reset_connection_body_limit(conn);
                    return Vec::new();
                }

                // Buffer for HTTP/1 and Unknown (Unknown may resolve to Http1)
                if conn.protocol == Protocol::Http1 || conn.protocol == Protocol::Unknown {
                    conn.h1_read_buffer.extend_from_slice(buf);
                }
                conn.response_chunks.push(chunk);

                match conn.protocol {
                    Protocol::Http1 => {
                        drain_parse_emit_http1_read(conn, conn_id, process_id, config, &mut events);
                    },
                    Protocol::Http2 => {
                        parse_http2_chunks(conn, direction);
                    },
                    // For Unknown protocol, try HTTP/1 parsing — handles non-standard
                    // methods (WebDAV, etc.) that detect_protocol() doesn't recognize.
                    Protocol::Unknown => {
                        drain_parse_emit_http1_unknown_read(
                            conn,
                            conn_id,
                            process_id,
                            config,
                            &mut events,
                        );
                    },
                    // HTTP/3 is handled via separate quic_connections path
                    Protocol::Http3 => {},
                }

                // Content-based parsing: a request can be parsed from the
                // Read direction (server-side), so check both.
                if is_request_complete(conn) {
                    conn.request_complete = true;
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

        // HTTP/1 Messages were already pushed directly by the drain-parse-emit
        // helpers above (so pipelined keep-alive requests all surface). This
        // call is still needed for HTTP/2 messages and for the finalize path
        // where a connection-close produces an h1_response that hasn't been
        // emitted yet.
        if config.emit_messages {
            emit_message_events(conn, conn_id, process_id, &mut events);
        }

        #[cfg(feature = "tracing")]
        tracing::debug!(
            conn_id,
            request_complete = conn.request_complete,
            response_complete = conn.response_complete,
            protocol = ?conn.protocol,
            h1_req = conn.h1_request.is_some(),
            h1_resp = conn.h1_response.is_some(),
            read_buf = conn.h1_read_buffer.len(),
            write_buf = conn.h1_write_buffer.len(),
            "exchange check"
        );

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
            if current_time_ns.saturating_sub(conn.last_activity_ns) >= self.config.timeout_ns {
                return false;
            }
            conn.h2_write_state.evict_stale_streams(current_time_ns);
            conn.h2_read_state.evict_stale_streams(current_time_ns);
            true
        });
        self.ssl_connections.retain(|_, conn| {
            if current_time_ns.saturating_sub(conn.last_activity_ns) >= self.config.timeout_ns {
                return false;
            }
            conn.h2_write_state.evict_stale_streams(current_time_ns);
            conn.h2_read_state.evict_stale_streams(current_time_ns);
            true
        });
        self.quic_connections.retain(|_, conn| {
            if current_time_ns.saturating_sub(conn.last_activity_ns) >= self.config.timeout_ns {
                return false;
            }
            conn.h3_state
                .cleanup_stale_streams(current_time_ns.0, self.config.timeout_ns);
            true
        });
    }

    /// Remove a connection explicitly (e.g., on connection close)
    ///
    /// Call this when a connection is closed to free resources immediately.
    /// If connection_id is 0, removes based on process_id from SSL connections.
    pub fn remove_connection(&self, connection_id: u128, process_id: u32) {
        if connection_id != 0 {
            let _ = self.connections.remove(&connection_id);
        } else {
            let _ = self.ssl_connections.remove(&process_id);
        }
    }

    /// Close a connection, finalizing any pending HTTP/1 response.
    ///
    /// For HTTP/1 responses without explicit framing (no Content-Length or
    /// Transfer-Encoding), RFC 7230 §3.3.3 says the body extends until the
    /// connection closes. This method finalizes such responses with whatever
    /// body has accumulated so far, emits any resulting events, then removes
    /// the connection.
    pub fn close_connection(&self, connection_id: u128, process_id: u32) -> Vec<CollationEvent> {
        let events = if connection_id != 0 {
            match self.connections.get(&connection_id) {
                Some(mut entry) => {
                    finalize_and_emit(entry.get_mut(), connection_id, process_id, &self.config)
                },
                None => Vec::new(),
            }
        } else {
            match self.ssl_connections.get(&process_id) {
                Some(mut entry) => {
                    finalize_and_emit(entry.get_mut(), connection_id, process_id, &self.config)
                },
                None => Vec::new(),
            }
        };

        // Remove the connection after releasing the guard
        if connection_id != 0 {
            let _ = self.connections.remove(&connection_id);
        } else {
            let _ = self.ssl_connections.remove(&process_id);
        }

        events
    }
}

/// Finalize any pending HTTP/1 response and emit events on connection close.
fn finalize_and_emit(
    conn: &mut Conn,
    connection_id: u128,
    process_id: u32,
    config: &CollatorConfig,
) -> Vec<CollationEvent> {
    // Finalize any pending HTTP/1 response with body accumulated so far
    if conn.protocol == Protocol::Http1
        && conn.h1_response.is_none()
        && !conn.h1_read_buffer.is_empty()
    {
        let timestamp = conn
            .response_chunks
            .first()
            .map(|c| c.timestamp_ns)
            .unwrap_or(TimestampNs(0));
        conn.h1_response = h1::try_finalize_http1_response(&conn.h1_read_buffer, timestamp);
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
    conn_id: u128,
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
                    command: conn.command.clone(),
                    timestamp_ns: req.timestamp_ns,
                    stream_id: None,
                    remote_port: conn.remote_port,
                    local_port: conn.local_port,
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
                    command: conn.command.clone(),
                    timestamp_ns: resp.timestamp_ns,
                    stream_id: None,
                    remote_port: conn.remote_port,
                    local_port: conn.local_port,
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
                        command: conn.command.clone(),
                        timestamp_ns: msg.end_stream_timestamp_ns,
                        stream_id: Some(stream_id),
                        remote_port: conn.remote_port,
                        local_port: conn.local_port,
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
                        command: conn.command.clone(),
                        timestamp_ns: msg.first_frame_timestamp_ns,
                        stream_id: Some(stream_id),
                        remote_port: conn.remote_port,
                        local_port: conn.local_port,
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
        Protocol::Unknown | Protocol::Http3 => {},
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
        conn.h1_write_parsed = false;
        conn.h1_read_parsed = false;
        conn.h1_request_emitted = false;
        conn.h1_response_emitted = false;
        conn.h1_write_buffer.clear();
        conn.h1_read_buffer.clear();
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
    conn.h1_write_buffer.clear();
    conn.h1_read_buffer.clear();
    conn.h1_request = None;
    conn.h1_response = None;
    conn.h1_write_parsed = false;
    conn.h1_read_parsed = false;
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
    conn.h1_write_buffer.clear();
    conn.h1_read_buffer.clear();
    conn.h1_request = None;
    conn.h1_response = None;
    conn.h1_write_parsed = false;
    conn.h1_read_parsed = false;
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

/// Detect whether raw bytes look like HTTP/1.x or HTTP/2 traffic.
///
/// Checks for the HTTP/2 connection preface, HTTP/2 frame headers,
/// and HTTP/1.x request/response patterns. Returns [`Protocol::Unknown`]
/// if no pattern matches.
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

    if let Err(_e) = h2_state.feed(&chunk.data, chunk.timestamp_ns) {
        trace_warn!(error = %_e, "h2 parse error (non-fatal, dropping frame)");
    }

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

/// Drain complete HTTP/1 messages from the write-direction buffer, emitting a
/// `Message` event for each one. Supports HTTP/1.1 keep-alive pipelining: as
/// long as the buffer holds another complete request or response, we slice
/// its bytes off and keep parsing.
///
/// The last parsed message (if any) remains in `conn.h1_request` /
/// `conn.h1_response` so the exchange-matching path in
/// `process_event_for_conn` still works for the final unpaired message.
fn drain_parse_emit_http1_write(
    conn: &mut Conn,
    conn_id: u128,
    process_id: u32,
    config: &CollatorConfig,
    events: &mut Vec<CollationEvent>,
) {
    loop {
        let timestamp = conn
            .request_chunks
            .last()
            .map(|c| c.timestamp_ns)
            .unwrap_or(TimestampNs(0));

        // Try request first (client-side), then response (server-side).
        if let Some((req, consumed)) =
            h1::try_parse_http1_request_sized(&conn.h1_write_buffer, timestamp)
        {
            conn.h1_write_buffer.drain(..consumed);
            emit_h1_request(conn, conn_id, process_id, config, events, req);
        } else if let Some((resp, consumed)) =
            h1::try_parse_http1_response_sized(&conn.h1_write_buffer, timestamp)
        {
            conn.h1_write_buffer.drain(..consumed);
            emit_h1_response(conn, conn_id, process_id, config, events, resp);
        } else {
            break;
        }
    }
}

/// Drain complete HTTP/1 messages from the read-direction buffer, emitting a
/// `Message` event for each one. See `drain_parse_emit_http1_write`.
fn drain_parse_emit_http1_read(
    conn: &mut Conn,
    conn_id: u128,
    process_id: u32,
    config: &CollatorConfig,
    events: &mut Vec<CollationEvent>,
) {
    loop {
        let timestamp = conn
            .response_chunks
            .last()
            .map(|c| c.timestamp_ns)
            .unwrap_or(TimestampNs(0));

        // Tries response first (client-side), then request (server-side).
        if let Some((resp, consumed)) =
            h1::try_parse_http1_response_sized(&conn.h1_read_buffer, timestamp)
        {
            conn.h1_read_buffer.drain(..consumed);
            emit_h1_response(conn, conn_id, process_id, config, events, resp);
        } else if let Some((req, consumed)) =
            h1::try_parse_http1_request_sized(&conn.h1_read_buffer, timestamp)
        {
            conn.h1_read_buffer.drain(..consumed);
            emit_h1_request(conn, conn_id, process_id, config, events, req);
        } else {
            break;
        }
    }
}

/// Drain HTTP/1 messages from the write buffer under Unknown protocol; on the
/// first successful parse, promote the connection to Http1 and keep draining.
fn drain_parse_emit_http1_unknown_write(
    conn: &mut Conn,
    conn_id: u128,
    process_id: u32,
    config: &CollatorConfig,
    events: &mut Vec<CollationEvent>,
) {
    let timestamp = conn
        .request_chunks
        .last()
        .map(|c| c.timestamp_ns)
        .unwrap_or(TimestampNs(0));
    if let Some((req, consumed)) =
        h1::try_parse_http1_request_sized(&conn.h1_write_buffer, timestamp)
    {
        conn.protocol = Protocol::Http1;
        conn.h1_write_buffer.drain(..consumed);
        emit_h1_request(conn, conn_id, process_id, config, events, req);
        drain_parse_emit_http1_write(conn, conn_id, process_id, config, events);
    } else if let Some((resp, consumed)) =
        h1::try_parse_http1_response_sized(&conn.h1_write_buffer, timestamp)
    {
        conn.protocol = Protocol::Http1;
        conn.h1_write_buffer.drain(..consumed);
        emit_h1_response(conn, conn_id, process_id, config, events, resp);
        drain_parse_emit_http1_write(conn, conn_id, process_id, config, events);
    }
}

/// Drain HTTP/1 messages from the read buffer under Unknown protocol; on the
/// first successful parse, promote the connection to Http1 and keep draining.
fn drain_parse_emit_http1_unknown_read(
    conn: &mut Conn,
    conn_id: u128,
    process_id: u32,
    config: &CollatorConfig,
    events: &mut Vec<CollationEvent>,
) {
    let timestamp = conn
        .response_chunks
        .last()
        .map(|c| c.timestamp_ns)
        .unwrap_or(TimestampNs(0));
    if let Some((resp, consumed)) =
        h1::try_parse_http1_response_sized(&conn.h1_read_buffer, timestamp)
    {
        conn.protocol = Protocol::Http1;
        conn.h1_read_buffer.drain(..consumed);
        emit_h1_response(conn, conn_id, process_id, config, events, resp);
        drain_parse_emit_http1_read(conn, conn_id, process_id, config, events);
    } else if let Some((req, consumed)) =
        h1::try_parse_http1_request_sized(&conn.h1_read_buffer, timestamp)
    {
        conn.protocol = Protocol::Http1;
        conn.h1_read_buffer.drain(..consumed);
        emit_h1_request(conn, conn_id, process_id, config, events, req);
        drain_parse_emit_http1_read(conn, conn_id, process_id, config, events);
    }
}

/// Push a Message event for an HTTP/1 request and store it on the connection
/// as the "current" parsed request (for exchange matching). Sets
/// `h1_request_emitted` so `emit_message_events` won't re-emit this one.
fn emit_h1_request(
    conn: &mut Conn,
    conn_id: u128,
    process_id: u32,
    config: &CollatorConfig,
    events: &mut Vec<CollationEvent>,
    req: h1::HttpRequest,
) {
    if config.emit_messages {
        let metadata = MessageMetadata {
            connection_id: conn_id,
            process_id,
            command: conn.command.clone(),
            timestamp_ns: req.timestamp_ns,
            stream_id: None,
            remote_port: conn.remote_port,
            local_port: conn.local_port,
            protocol: Protocol::Http1,
        };
        events.push(CollationEvent::Message {
            message: ParsedHttpMessage::Request(req.clone()),
            metadata,
        });
    }
    conn.h1_request = Some(req);
    conn.h1_request_emitted = true;
}

/// Push a Message event for an HTTP/1 response and store it on the connection
/// as the "current" parsed response (for exchange matching). Sets
/// `h1_response_emitted` so `emit_message_events` won't re-emit this one.
fn emit_h1_response(
    conn: &mut Conn,
    conn_id: u128,
    process_id: u32,
    config: &CollatorConfig,
    events: &mut Vec<CollationEvent>,
    resp: h1::HttpResponse,
) {
    if config.emit_messages {
        let metadata = MessageMetadata {
            connection_id: conn_id,
            process_id,
            command: conn.command.clone(),
            timestamp_ns: resp.timestamp_ns,
            stream_id: None,
            remote_port: conn.remote_port,
            local_port: conn.local_port,
            protocol: Protocol::Http1,
        };
        events.push(CollationEvent::Message {
            message: ParsedHttpMessage::Response(resp.clone()),
            metadata,
        });
    }
    conn.h1_response = Some(resp);
    conn.h1_response_emitted = true;
}

fn is_request_complete(conn: &Conn) -> bool {
    match conn.protocol {
        Protocol::Http1 => conn.h1_request.is_some(),
        Protocol::Http2 => find_complete_h2_stream(conn).is_some(),
        Protocol::Unknown | Protocol::Http3 => false,
    }
}

fn is_response_complete(conn: &Conn) -> bool {
    match conn.protocol {
        Protocol::Http1 => conn.h1_response.is_some(),
        Protocol::Http2 => find_complete_h2_stream(conn).is_some(),
        Protocol::Unknown | Protocol::Http3 => false,
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
        Protocol::Unknown | Protocol::Http3 => return None,
    };

    Some(Exchange {
        request,
        response,
        latency_ns,
        protocol: conn.protocol,
        process_id: conn.process_id,
        command: conn.command.clone(),
        remote_port: conn.remote_port,
        local_port: conn.local_port,
        stream_id,
        proxy_metadata: conn.proxy_metadata,
    })
}

#[cfg(test)]
mod tests;
