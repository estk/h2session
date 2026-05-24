use bytes::{Bytes, BytesMut};

use crate::{
    frame::{self, Frame, FrameType},
    qpack::{DecodeError, QpackDecoder},
};

/// A fully parsed HTTP/3 message (request or response) from a single QUIC
/// stream.
#[derive(Debug, Clone)]
pub struct ParsedH3Message {
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    pub stream_id: i64,
    pub first_frame_timestamp_ns: u64,
    pub end_stream_timestamp_ns: u64,
}

impl ParsedH3Message {
    /// Returns true if this message has a :method pseudo-header (is a request).
    pub fn is_request(&self) -> bool {
        self.headers.iter().any(|(name, _)| name == ":method")
    }

    /// Returns true if this message has a :status pseudo-header (is a
    /// response).
    pub fn is_response(&self) -> bool {
        self.headers.iter().any(|(name, _)| name == ":status")
    }

    /// Convert to http_collator-compatible HttpRequest (if this is a request).
    pub fn method(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(name, _)| name == ":method")
            .map(|(_, v)| v.as_str())
    }

    pub fn path(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(name, _)| name == ":path")
            .map(|(_, v)| v.as_str())
    }

    pub fn status(&self) -> Option<u16> {
        self.headers
            .iter()
            .find(|(name, _)| name == ":status")
            .and_then(|(_, v)| v.parse().ok())
    }

    pub fn authority(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(name, _)| name == ":authority")
            .map(|(_, v)| v.as_str())
    }
}

/// Per-stream accumulation state.
#[derive(Debug)]
pub struct H3StreamState {
    buffer:         BytesMut,
    headers:        Option<Vec<(String, String)>>,
    body:           BytesMut,
    first_frame_ts: Option<u64>,
    fin_received:   bool,
}

impl H3StreamState {
    fn new() -> Self {
        Self {
            buffer:         BytesMut::new(),
            headers:        None,
            body:           BytesMut::new(),
            first_frame_ts: None,
            fin_received:   false,
        }
    }

    /// Returns true if the stream has HEADERS and either FIN, body data, or
    /// this is the second message on the stream (i.e. the response after a
    /// request). For server-side instrumentation, we may not see FIN before
    /// the process exits — having parsed HEADERS is sufficient for a response.
    fn is_complete(&self, is_second_on_stream: bool) -> bool {
        if self.headers.is_none() {
            return false;
        }
        self.fin_received || !self.body.is_empty() || is_second_on_stream
    }
}

/// Tracks HTTP/3 state for a single QUIC connection.
///
/// Manages QPACK decoder state (shared across all streams on the connection)
/// and per-stream frame accumulation.
pub struct H3ConnectionState {
    decoder: QpackDecoder,
    streams: std::collections::HashMap<i64, H3StreamState>,
    completed: Vec<(i64, ParsedH3Message)>,
    // Tracks how many times each stream has completed. In HTTP/3, a bidirectional
    // stream carries exactly one request + one response (2 completions max).
    // A 3rd completion is a ghost from a redundant FIN-only event.
    stream_completions: std::collections::HashMap<i64, u8>,
}

impl H3ConnectionState {
    pub fn new() -> Self {
        Self {
            decoder: QpackDecoder::new(),
            streams: std::collections::HashMap::new(),
            completed: Vec::new(),
            stream_completions: std::collections::HashMap::new(),
        }
    }

    /// Feed unframed body data from a specific QUIC stream (quiche only).
    ///
    /// Quiche captures data after frame parsing — the payload IS the body, no
    /// frame headers included. This method skips frame parsing and buffers
    /// directly to the body, completing the message on FIN.
    ///
    /// `stream_id`: the QUIC stream ID this data belongs to
    /// `data`: unframed body bytes (no HTTP/3 frame headers)
    /// `timestamp_ns`: when this data was captured
    /// `fin`: whether this is the final data on the stream
    pub fn feed_unframed(&mut self, stream_id: i64, data: &[u8], timestamp_ns: u64, fin: bool) {
        #[cfg(feature = "tracing")]
        let _span =
            tracing::debug_span!("h3_feed_unframed", stream_id, len = data.len(), fin).entered();

        let completions = *self.stream_completions.get(&stream_id).unwrap_or(&0);
        crate::trace_debug!(completions, "feed_unframed");

        if completions >= 2 {
            crate::trace_debug!("skipped (completions>=2)");
            return;
        }

        let stream = self
            .streams
            .entry(stream_id)
            .or_insert_with(H3StreamState::new);

        if stream.first_frame_ts.is_none() {
            stream.first_frame_ts = Some(timestamp_ns);
        }

        if !data.is_empty() {
            stream.body.extend_from_slice(data);
        }

        if fin {
            stream.fin_received = true;
        }

        // Complete the message on FIN
        if stream.fin_received {
            crate::trace_debug!(
                body_len = stream.body.len(),
                has_headers = stream.headers.is_some(),
                "COMPLETE (unframed)"
            );
            let stream = self
                .streams
                .remove(&stream_id)
                .expect("stream must exist: entry() confirmed presence");
            *self.stream_completions.entry(stream_id).or_insert(0) += 1;
            let msg = ParsedH3Message {
                headers: stream.headers.unwrap_or_default(),
                body: stream.body.freeze(),
                stream_id,
                first_frame_timestamp_ns: stream.first_frame_ts.unwrap_or(timestamp_ns),
                end_stream_timestamp_ns: timestamp_ns,
            };
            self.completed.push((stream_id, msg));
        }
    }

    /// Feed data from a specific QUIC stream.
    ///
    /// `stream_id`: the QUIC stream ID this data belongs to
    /// `data`: plaintext stream bytes (HTTP/3 frames)
    /// `timestamp_ns`: when this data was captured
    /// `fin`: whether this is the final data on the stream
    pub fn feed(&mut self, stream_id: i64, data: &[u8], timestamp_ns: u64, fin: bool) {
        #[cfg(feature = "tracing")]
        let _span = tracing::debug_span!("h3_feed", stream_id, len = data.len(), fin).entered();

        let completions = *self.stream_completions.get(&stream_id).unwrap_or(&0);
        crate::trace_debug!(completions, "feed");

        // HTTP/3 bidirectional streams carry one request + one response (2 messages).
        // A 3rd completion would be a ghost from a redundant FIN-only event.
        if completions >= 2 {
            crate::trace_debug!("skipped (completions>=2)");
            return;
        }

        let stream = self
            .streams
            .entry(stream_id)
            .or_insert_with(H3StreamState::new);

        if stream.first_frame_ts.is_none() {
            stream.first_frame_ts = Some(timestamp_ns);
        }

        stream.buffer.extend_from_slice(data);

        if fin {
            stream.fin_received = true;
        }

        // Parse any complete frames from the buffer
        let (frames, consumed) = frame::parse_frames(&stream.buffer);
        crate::trace_debug!(
            buffer_len = stream.buffer.len(),
            parsed_frames = frames.len(),
            consumed,
            "parsed"
        );
        if consumed > 0 {
            let _ = stream.buffer.split_to(consumed);
        }

        #[cfg(feature = "tracing")]
        for _frame in &frames {
            crate::trace_debug!(
                frame_type = ?_frame.frame_type,
                payload_len = _frame.payload.len(),
                "frame"
            );
        }

        for frame in frames {
            self.process_frame(stream_id, frame, timestamp_ns);
        }

        // Check if stream is complete and move to completed queue
        let is_second = completions >= 1;
        if let Some(stream) = self.streams.get(&stream_id)
            && stream.is_complete(is_second)
        {
            crate::trace_debug!(
                is_second,
                has_headers = stream.headers.is_some(),
                body_len = stream.body.len(),
                fin = stream.fin_received,
                "COMPLETE"
            );
            // BUG: stream must exist here — the if-let guard on line above confirmed it.
            // Only reachable via programming error (concurrent mutation or broken guard
            // logic).
            let stream = self
                .streams
                .remove(&stream_id)
                .expect("stream must exist: is_complete guard confirmed presence");
            *self.stream_completions.entry(stream_id).or_insert(0) += 1;
            let msg = ParsedH3Message {
                headers: stream.headers.unwrap_or_default(),
                body: stream.body.freeze(),
                stream_id,
                first_frame_timestamp_ns: stream.first_frame_ts.unwrap_or(timestamp_ns),
                end_stream_timestamp_ns: timestamp_ns,
            };
            self.completed.push((stream_id, msg));
        }
    }

    fn process_frame(&mut self, stream_id: i64, frame: Frame, _timestamp_ns: u64) {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(s) => s,
            None => return,
        };

        match frame.frame_type {
            FrameType::Headers => {
                match self.decoder.decode_header_block(&frame.payload) {
                    Ok(headers) => {
                        stream.headers = Some(headers);
                    },
                    Err(DecodeError::DynamicTableRequired(_)) => {
                        // Missing dynamic table context (mid-connection attach).
                        // Store empty headers — we can still capture the body.
                        stream.headers = Some(Vec::new());
                    },
                    Err(_) => {
                        // Other decode errors — store empty headers
                        stream.headers = Some(Vec::new());
                    },
                }
            },
            FrameType::Data => {
                stream.body.extend_from_slice(&frame.payload);
            },
            _ => {
                // SETTINGS, GOAWAY, etc. — ignored for message parsing
            },
        }
    }

    /// Pop the next completed message, if any.
    pub fn try_pop(&mut self) -> Option<(i64, ParsedH3Message)> {
        if self.completed.is_empty() {
            None
        } else {
            Some(self.completed.remove(0))
        }
    }

    /// Mark a stream as finished (FIN received without data in this call).
    /// Useful when the eBPF probe signals stream end separately.
    pub fn finish_stream(&mut self, stream_id: i64, timestamp_ns: u64) {
        self.feed(stream_id, &[], timestamp_ns, true);
    }

    /// Remove streams that haven't received data for longer than `timeout_ns`.
    pub fn cleanup_stale_streams(&mut self, now_ns: u64, timeout_ns: u64) {
        self.streams.retain(|_, stream| {
            stream
                .first_frame_ts
                .map(|ts| now_ns.saturating_sub(ts) < timeout_ns)
                .unwrap_or(true)
        });
    }
}

impl Default for H3ConnectionState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_headers_frame(headers_payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0x01); // HEADERS frame type
        // Encode length as varint (assuming < 64)
        buf.push(headers_payload.len() as u8);
        buf.extend_from_slice(headers_payload);
        buf
    }

    fn make_data_frame(data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0x00); // DATA frame type
        buf.push(data.len() as u8);
        buf.extend_from_slice(data);
        buf
    }

    #[test]
    fn test_simple_request_stream() {
        let mut state = H3ConnectionState::new();

        // QPACK encoded: RIC=0, DeltaBase=0, :method GET (static 17), :path / (static
        // 1)
        let qpack_block = vec![0x00, 0x00, 0xd1, 0xc1];
        let headers_frame = make_headers_frame(&qpack_block);

        // Feed HEADERS frame with FIN
        state.feed(0, &headers_frame, 1000, true);

        let (stream_id, msg) = state.try_pop().unwrap();
        assert_eq!(stream_id, 0);
        assert!(msg.is_request());
        assert_eq!(msg.method(), Some("GET"));
        assert_eq!(msg.path(), Some("/"));
        assert!(msg.body.is_empty());
    }

    #[test]
    fn test_request_with_body() {
        let mut state = H3ConnectionState::new();

        let qpack_block = vec![0x00, 0x00, 0xd4]; // :method POST (static 20)
        let headers_frame = make_headers_frame(&qpack_block);
        let data_frame = make_data_frame(b"hello world");

        let mut stream_data = headers_frame;
        stream_data.extend_from_slice(&data_frame);

        state.feed(4, &stream_data, 2000, true);

        let (stream_id, msg) = state.try_pop().unwrap();
        assert_eq!(stream_id, 4);
        assert!(msg.is_request());
        assert_eq!(msg.method(), Some("POST"));
        assert_eq!(&msg.body[..], b"hello world");
    }

    #[test]
    fn test_response_stream() {
        let mut state = H3ConnectionState::new();

        // :status 200 is static index 25: 0xC0 | 25 = 0xD9
        let qpack_block = vec![0x00, 0x00, 0xd9];
        let headers_frame = make_headers_frame(&qpack_block);
        let data_frame = make_data_frame(b"{\"ok\":true}");

        let mut stream_data = headers_frame;
        stream_data.extend_from_slice(&data_frame);

        state.feed(0, &stream_data, 3000, true);

        let (_, msg) = state.try_pop().unwrap();
        assert!(msg.is_response());
        assert_eq!(msg.status(), Some(200));
        assert_eq!(&msg.body[..], b"{\"ok\":true}");
    }

    #[test]
    fn test_incremental_feed() {
        let mut state = H3ConnectionState::new();

        let qpack_block = vec![0x00, 0x00, 0xd1]; // :method GET
        let headers_frame = make_headers_frame(&qpack_block);
        let data_frame = make_data_frame(b"body");

        // Feed headers first (no FIN)
        state.feed(0, &headers_frame, 1000, false);
        assert!(state.try_pop().is_none());

        // Feed data (no FIN)
        state.feed(0, &data_frame, 2000, false);
        assert!(state.try_pop().is_none());

        // Signal FIN
        state.finish_stream(0, 3000);

        let (_, msg) = state.try_pop().unwrap();
        assert!(msg.is_request());
        assert_eq!(&msg.body[..], b"body");
        assert_eq!(msg.first_frame_timestamp_ns, 1000);
        assert_eq!(msg.end_stream_timestamp_ns, 3000);
    }

    #[test]
    fn test_multiple_streams() {
        let mut state = H3ConnectionState::new();

        // Stream 0: request
        let req_headers = make_headers_frame(&[0x00, 0x00, 0xd1]); // GET
        state.feed(0, &req_headers, 1000, true);

        // Stream 4: another request
        let req2_headers = make_headers_frame(&[0x00, 0x00, 0xd4]); // POST
        state.feed(4, &req2_headers, 2000, true);

        let (id1, msg1) = state.try_pop().unwrap();
        let (id2, msg2) = state.try_pop().unwrap();

        assert_eq!(id1, 0);
        assert_eq!(id2, 4);
        assert_eq!(msg1.method(), Some("GET"));
        assert_eq!(msg2.method(), Some("POST"));
    }

    #[test]
    fn test_duplicate_fin_ignored() {
        let mut state = H3ConnectionState::new();

        let qpack_block = vec![0x00, 0x00, 0xd1, 0xc1]; // :method GET, :path /
        let headers_frame = make_headers_frame(&qpack_block);

        // First event: data + FIN completes the stream
        state.feed(0, &headers_frame, 1000, true);
        let (_, msg) = state.try_pop().unwrap();
        assert_eq!(msg.method(), Some("GET"));

        // Second event: redundant FIN-only (zero-length) — must not create a new stream
        state.feed(0, &[], 2000, true);
        assert!(state.try_pop().is_none());
    }
}
