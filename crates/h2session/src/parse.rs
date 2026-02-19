use std::collections::HashMap;

use crate::frame::*;
use crate::state::{
    H2ConnectionState, ParseError, ParseErrorKind, ParsedH2Message, StreamId, StreamPhase,
    StreamState, TimestampNs,
};

/// Parse HTTP/2 frames with connection-level state
///
/// Processes the buffer for HTTP/2 frames and returns completed messages
/// indexed by stream_id. State is accumulated across calls for HPACK decoding
/// and stream tracking.
/// Returns `Ok(HashMap)` which may be empty if no streams completed yet.
///
/// NOTE: This function re-parses the entire buffer from the beginning each call.
/// For incremental parsing, use `H2ConnectionState::feed()` instead.
pub(crate) fn parse_frames_stateful(
    buffer: &[u8],
    state: &mut H2ConnectionState,
) -> Result<HashMap<StreamId, ParsedH2Message>, ParseError> {
    let mut pos = 0;
    let mut completed_messages = HashMap::new();
    let timestamp_ns = state.current_timestamp_ns;

    // Skip connection preface if not yet seen
    if !state.preface_received && buffer.starts_with(CONNECTION_PREFACE) {
        pos += CONNECTION_PREFACE.len();
        state.preface_received = true;
    }

    // Parse frames
    while pos + FRAME_HEADER_SIZE <= buffer.len() {
        let header = parse_frame_header(&buffer[pos..])?;

        // H1: enforce max_frame_size (before checking completeness — reject
        // oversized frames as soon as the header is visible)
        if header.length > state.settings.max_frame_size {
            return Err(ParseError::new(ParseErrorKind::Http2FrameSizeError));
        }

        // C4: checked arithmetic for frame total size
        let frame_total_size = FRAME_HEADER_SIZE
            .checked_add(header.length as usize)
            .ok_or(ParseError::new(ParseErrorKind::Http2InvalidFrame))?;

        if pos + frame_total_size > buffer.len() {
            break; // Incomplete frame
        }

        // H4: validate CONTINUATION ordering
        if let Some(expected_stream) = state.expecting_continuation
            && (header.frame_type != FRAME_TYPE_CONTINUATION || header.stream_id != expected_stream)
        {
            return Err(ParseError::new(ParseErrorKind::Http2ContinuationExpected));
        }

        let frame_payload = &buffer[pos + FRAME_HEADER_SIZE..pos + frame_total_size];

        match header.frame_type {
            FRAME_TYPE_DATA => {
                handle_data_frame(state, &header, frame_payload, timestamp_ns)?;
            }
            FRAME_TYPE_HEADERS => {
                handle_headers_frame(state, &header, frame_payload, timestamp_ns)?;
            }
            FRAME_TYPE_CONTINUATION => {
                handle_continuation_frame(state, &header, frame_payload)?;
            }
            FRAME_TYPE_SETTINGS => {
                handle_settings_frame(state, &header, frame_payload)?;
            }
            FRAME_TYPE_RST_STREAM => {
                handle_rst_stream(state, &header, frame_payload);
            }
            FRAME_TYPE_GOAWAY => {
                handle_goaway(frame_payload);
            }
            FRAME_TYPE_PRIORITY
            | FRAME_TYPE_PUSH_PROMISE
            | FRAME_TYPE_PING
            | FRAME_TYPE_WINDOW_UPDATE => {}
            _ => {}
        }

        pos += frame_total_size;

        // Check only the stream that was just modified (stream_id 0 = connection-level)
        if header.stream_id != StreamId(0)
            && let Some((id, msg)) = check_stream_completion(state, header.stream_id)
        {
            completed_messages.insert(id, msg);
        }
    }

    // Evict stale streams to bound memory usage
    state.evict_stale_streams(timestamp_ns);

    Ok(completed_messages)
}

/// Parse the internal buffer incrementally, called by H2ConnectionState::feed()
///
/// Frame-level errors (missing stream for DATA, padding errors) are non-fatal:
/// the offending frame is skipped and parsing continues. HPACK errors corrupt
/// the decoder's dynamic table and are fatal — parsing stops immediately.
/// The buffer is always drained up to the last consumed position regardless
/// of errors, preventing re-processing of already-consumed frames.
pub(crate) fn parse_buffer_incremental(state: &mut H2ConnectionState) -> Result<(), ParseError> {
    let mut pos = 0;
    let timestamp_ns = state.current_timestamp_ns;
    let mut fatal_error: Option<ParseError> = None;

    // Skip connection preface if not yet seen
    if !state.preface_received && state.buffer.starts_with(CONNECTION_PREFACE) {
        pos += CONNECTION_PREFACE.len();
        state.preface_received = true;
    }

    // Parse complete frames from buffer
    while pos + FRAME_HEADER_SIZE <= state.buffer.len() {
        let header = match parse_frame_header(&state.buffer[pos..]) {
            Ok(h) => h,
            Err(_) => break,
        };

        // C4: checked arithmetic for frame total size
        let frame_total_size = match FRAME_HEADER_SIZE.checked_add(header.length as usize) {
            Some(s) => s,
            None => break,
        };

        if pos + frame_total_size > state.buffer.len() {
            break; // Incomplete frame - wait for more data
        }

        // H4: validate CONTINUATION ordering (non-fatal: skip unexpected frame)
        if let Some(expected_stream) = state.expecting_continuation
            && (header.frame_type != FRAME_TYPE_CONTINUATION || header.stream_id != expected_stream)
        {
            crate::trace_warn!(
                "expected CONTINUATION for stream {expected_stream}, got frame type {} on stream {}; \
                     abandoning incomplete header block",
                header.frame_type,
                header.stream_id
            );
            state.expecting_continuation = None;
            state.active_streams.remove(&expected_stream);
            // Fall through to process this frame normally
        }

        let frame_payload = state.buffer[pos + FRAME_HEADER_SIZE..pos + frame_total_size].to_vec();

        let result = match header.frame_type {
            FRAME_TYPE_DATA => handle_data_frame(state, &header, &frame_payload, timestamp_ns),
            FRAME_TYPE_HEADERS => {
                handle_headers_frame(state, &header, &frame_payload, timestamp_ns)
            }
            FRAME_TYPE_CONTINUATION => handle_continuation_frame(state, &header, &frame_payload),
            FRAME_TYPE_SETTINGS => handle_settings_frame(state, &header, &frame_payload),
            FRAME_TYPE_RST_STREAM => {
                handle_rst_stream(state, &header, &frame_payload);
                Ok(())
            }
            FRAME_TYPE_GOAWAY => {
                handle_goaway(&frame_payload);
                Ok(())
            }
            FRAME_TYPE_PRIORITY
            | FRAME_TYPE_PUSH_PROMISE
            | FRAME_TYPE_PING
            | FRAME_TYPE_WINDOW_UPDATE => Ok(()),
            _ => Ok(()),
        };

        // Always advance past the frame so it won't be re-processed
        pos += frame_total_size;

        let stream_id = header.stream_id;

        if let Err(ref e) = result {
            // HPACK errors corrupt the decoder's dynamic table — stop parsing
            if matches!(e.kind, ParseErrorKind::Http2HpackError(_)) {
                crate::trace_warn!("fatal HPACK error on stream {stream_id}: {e}");
                fatal_error = Some(result.unwrap_err());
                break;
            }
            // Other errors (missing stream, padding) are non-fatal: skip frame
            crate::trace_warn!("non-fatal frame error on stream {stream_id}: {e}");
            continue;
        }

        // Check only the stream that was just modified (stream_id 0 = connection-level)
        if stream_id != StreamId(0)
            && let Some(pair) = check_stream_completion(state, stream_id)
        {
            state.completed.push_back(pair);
        }
    }

    // Remove consumed bytes from buffer, keeping any partial frame data
    if pos > 0 {
        state.buffer.drain(..pos);
    }

    // Evict stale/excess streams to bound memory usage
    state.evict_stale_streams(timestamp_ns);

    match fatal_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn handle_headers_frame(
    state: &mut H2ConnectionState,
    header: &FrameHeader,
    payload: &[u8],
    timestamp_ns: TimestampNs,
) -> Result<(), ParseError> {
    let stream_id = header.stream_id;

    // Reject new streams when at capacity (non-fatal: skip the frame)
    if !state.active_streams.contains_key(&stream_id)
        && state.active_streams.len() >= state.limits.max_concurrent_streams
    {
        crate::trace_warn!("max concurrent streams reached, rejecting stream {stream_id}");
        return Err(ParseError::with_stream(
            ParseErrorKind::Http2MaxConcurrentStreams,
            stream_id,
        ));
    }

    // H2: Validate stream ID ordering for new streams (RFC 7540 §5.1.1)
    if !state.active_streams.contains_key(&stream_id) {
        if stream_id.0 != 0 && stream_id <= state.highest_stream_id {
            crate::trace_warn!(
                "stream {stream_id} not greater than highest seen ({}); RFC 7540 §5.1.1 violation",
                state.highest_stream_id
            );
        }
        if stream_id.0.is_multiple_of(2) && stream_id.0 != 0 {
            crate::trace_warn!(
                "even stream ID {stream_id} (server-initiated); unexpected for client traffic"
            );
        }
    }

    // Create stream if new, recording the timestamp of first frame
    // Also track highest stream ID for protocol validation
    let stream = state.active_streams.entry(stream_id).or_insert_with(|| {
        if stream_id > state.highest_stream_id {
            state.highest_stream_id = stream_id;
        }
        StreamState::new(stream_id, timestamp_ns)
    });

    // Handle PADDED flag
    // Padded frame format: [Pad Length (1 byte)] [Header Block] [Padding]
    let (header_block, _padding_len) = if header.flags & FLAG_PADDED != 0 {
        if payload.is_empty() {
            return Err(ParseError::with_stream(
                ParseErrorKind::Http2PaddingError,
                stream_id,
            ));
        }
        let pad_len = payload[0] as usize;
        if pad_len >= payload.len() {
            return Err(ParseError::with_stream(
                ParseErrorKind::Http2PaddingError,
                stream_id,
            ));
        }
        (&payload[1..payload.len() - pad_len], pad_len)
    } else {
        (payload, 0)
    };

    // Handle PRIORITY flag (skip 5 bytes: 4-byte dependency + 1-byte weight)
    let header_block = if header.flags & FLAG_PRIORITY != 0 {
        if header_block.len() < 5 {
            return Err(ParseError::with_stream(
                ParseErrorKind::Http2PriorityError,
                stream_id,
            ));
        }
        // M2: Check for self-dependency (RFC 7540 §5.3.1)
        let dependency = u32::from_be_bytes([
            header_block[0] & 0x7F,
            header_block[1],
            header_block[2],
            header_block[3],
        ]);
        if dependency == stream_id.0 {
            crate::trace_warn!("stream {stream_id} depends on itself (RFC 7540 §5.3.1 violation)");
        }
        &header_block[5..]
    } else {
        header_block
    };

    stream.header_size += FRAME_HEADER_SIZE + payload.len();

    let has_end_headers = header.flags & FLAG_END_HEADERS != 0;
    let has_end_stream = header.flags & FLAG_END_STREAM != 0;

    // Check END_HEADERS flag
    if has_end_headers {
        // Complete header block - decode now
        let full_block: Vec<u8> = if stream.continuation_buffer.is_empty() {
            header_block.to_vec()
        } else {
            stream.continuation_buffer.extend_from_slice(header_block);
            std::mem::take(&mut stream.continuation_buffer)
        };

        decode_headers_into_stream(&mut state.decoder, stream, &full_block, &state.limits)?;
        state.expecting_continuation = None;
    } else {
        // Incomplete header block - wait for CONTINUATION
        stream.continuation_buffer.extend_from_slice(header_block);
        state.expecting_continuation = Some(stream_id);
    }

    // Update phase based on flags
    if has_end_stream {
        stream.end_stream_timestamp_ns = timestamp_ns;
    }
    stream.phase = match (has_end_headers, has_end_stream) {
        (true, true) => StreamPhase::Complete,
        (true, false) => StreamPhase::ReceivingBody,
        (false, es) => StreamPhase::ReceivingHeaders {
            end_stream_seen: es,
        },
    };

    Ok(())
}

fn handle_continuation_frame(
    state: &mut H2ConnectionState,
    header: &FrameHeader,
    payload: &[u8],
) -> Result<(), ParseError> {
    let stream = state
        .active_streams
        .get_mut(&header.stream_id)
        .ok_or(ParseError::with_stream(
            ParseErrorKind::Http2HeadersIncomplete,
            header.stream_id,
        ))?;

    stream.continuation_buffer.extend_from_slice(payload);
    stream.header_size += FRAME_HEADER_SIZE + payload.len();

    if header.flags & FLAG_END_HEADERS != 0 {
        let buf = std::mem::take(&mut stream.continuation_buffer);
        decode_headers_into_stream(&mut state.decoder, stream, &buf, &state.limits)?;
        state.expecting_continuation = None;

        // Transition based on whether END_STREAM was pending from the HEADERS frame
        stream.phase = match stream.phase {
            StreamPhase::ReceivingHeaders {
                end_stream_seen: true,
            } => StreamPhase::Complete,
            _ => StreamPhase::ReceivingBody,
        };
    }

    Ok(())
}

fn handle_data_frame(
    state: &mut H2ConnectionState,
    header: &FrameHeader,
    payload: &[u8],
    timestamp_ns: TimestampNs,
) -> Result<(), ParseError> {
    // Handle PADDED flag before borrowing the stream
    // Padded frame format: [Pad Length (1 byte)] [Data] [Padding]
    let data = if header.flags & FLAG_PADDED != 0 {
        if payload.is_empty() {
            return Err(ParseError::with_stream(
                ParseErrorKind::Http2PaddingError,
                header.stream_id,
            ));
        }
        let pad_len = payload[0] as usize;
        // Data length = total - pad_length_byte - padding
        if pad_len >= payload.len() {
            return Err(ParseError::with_stream(
                ParseErrorKind::Http2PaddingError,
                header.stream_id,
            ));
        }
        &payload[1..payload.len() - pad_len]
    } else {
        payload
    };

    // Check body size limit and M1 (DATA before headers complete) before borrowing the stream mutably
    {
        let stream = state
            .active_streams
            .get(&header.stream_id)
            .ok_or(ParseError::with_stream(
                ParseErrorKind::Http2StreamNotFound,
                header.stream_id,
            ))?;
        // M1: DATA before headers are complete (RFC 7540 §8.1)
        if matches!(stream.phase, StreamPhase::ReceivingHeaders { .. }) {
            crate::trace_warn!(
                "DATA on stream {} before headers complete (RFC 7540 §8.1)",
                header.stream_id
            );
        }
        if stream.body.len() + data.len() > state.limits.max_body_size {
            // Drop the stream rather than accumulating unbounded data
            crate::trace_warn!(
                "body size limit exceeded on stream {}, dropping stream",
                header.stream_id
            );
            state.active_streams.remove(&header.stream_id);
            return Ok(());
        }
    }

    let stream = state
        .active_streams
        .get_mut(&header.stream_id)
        .ok_or(ParseError::with_stream(
            ParseErrorKind::Http2StreamNotFound,
            header.stream_id,
        ))?;

    stream.body.extend_from_slice(data);

    if header.flags & FLAG_END_STREAM != 0 {
        stream.end_stream_timestamp_ns = timestamp_ns;
        stream.phase = StreamPhase::Complete;
    }

    Ok(())
}

fn handle_settings_frame(
    state: &mut H2ConnectionState,
    _header: &FrameHeader,
    payload: &[u8],
) -> Result<(), ParseError> {
    // H3: SETTINGS payload must be a multiple of 6 bytes (RFC 7540 §6.5)
    if !payload.len().is_multiple_of(6) {
        return Err(ParseError::new(ParseErrorKind::Http2SettingsLengthError));
    }

    // Settings frame: 6 bytes per setting (2-byte id, 4-byte value)
    let mut pos = 0;
    while pos + 6 <= payload.len() {
        let setting_id = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let value = u32::from_be_bytes([
            payload[pos + 2],
            payload[pos + 3],
            payload[pos + 4],
            payload[pos + 5],
        ]);

        match setting_id {
            0x01 => {
                // M4: Store the capped value, not the raw peer value
                let capped = value.min(state.limits.max_table_size as u32);
                state.settings.header_table_size = capped;
                state.decoder.set_max_table_size(capped as usize);
            }
            0x02 => state.settings.enable_push = value != 0,
            0x03 => state.settings.max_concurrent_streams = value,
            0x04 => state.settings.initial_window_size = value,
            0x05 => {
                // RFC 7540 §6.5.2: valid range is [16384, 16777215]
                if (16_384..=MAX_FRAME_PAYLOAD_LENGTH).contains(&value) {
                    state.settings.max_frame_size = value;
                }
                // Ignore out-of-range values (passive monitor shouldn't disconnect)
            }
            0x06 => state.settings.max_header_list_size = value,
            _ => {} // Unknown setting
        }

        pos += 6;
    }

    Ok(())
}

/// Handle RST_STREAM: remove the stream from active tracking (L1).
fn handle_rst_stream(state: &mut H2ConnectionState, header: &FrameHeader, payload: &[u8]) {
    if payload.len() < 4 {
        crate::trace_warn!(
            "RST_STREAM on stream {} with short payload ({} bytes)",
            header.stream_id,
            payload.len()
        );
        return;
    }
    let _error_code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    crate::trace_warn!(
        "RST_STREAM on stream {} error_code={_error_code}",
        header.stream_id
    );
    state.active_streams.remove(&header.stream_id);
}

/// Handle GOAWAY: log the last stream ID and error code (L2).
/// Does not interrupt parsing — the passive monitor continues observing.
fn handle_goaway(payload: &[u8]) {
    if payload.len() < 8 {
        crate::trace_warn!("GOAWAY with short payload ({} bytes)", payload.len());
        return;
    }
    let _last_stream_id =
        u32::from_be_bytes([payload[0] & 0x7F, payload[1], payload[2], payload[3]]);
    let _error_code = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    crate::trace_warn!("GOAWAY: last_stream_id={_last_stream_id}, error_code={_error_code}");
}

/// Decode an HPACK header block into the given stream's header state.
///
/// The HPACK decoder's dynamic table is mutated during `decode_with_cb`.
/// If invalid UTF-8 is encountered, the dynamic table has already been
/// updated with the invalid entry. This is a known limitation of
/// `loona-hpack`'s callback API. For passive monitoring, this is acceptable
/// since we prioritize keeping the connection parseable over strict validation.
fn decode_headers_into_stream(
    decoder: &mut loona_hpack::Decoder<'static>,
    stream: &mut StreamState,
    header_block: &[u8],
    limits: &crate::state::H2Limits,
) -> Result<(), ParseError> {
    let mut total_size: usize = 0;
    let mut header_count: usize = 0;
    let mut limit_exceeded = false;
    let mut encoding_error = false;

    decoder
        .decode_with_cb(header_block, |name, value| {
            if limit_exceeded || encoding_error {
                return;
            }

            header_count += 1;
            if header_count > limits.max_header_count {
                limit_exceeded = true;
                return;
            }

            if value.len() > limits.max_header_value_size {
                limit_exceeded = true;
                return;
            }

            // RFC 7540 §6.5.2: header list size = sum of (name.len + value.len + 32) per entry
            total_size += name.len() + value.len() + 32;
            if total_size > limits.max_header_list_size {
                limit_exceeded = true;
                return;
            }

            let (Ok(name_str), Ok(value_str)) =
                (std::str::from_utf8(&name), std::str::from_utf8(&value))
            else {
                encoding_error = true;
                return;
            };
            let name_str = name_str.to_string();
            let value_str = value_str.to_string();

            match name_str.as_str() {
                ":method" => stream.method = Some(value_str),
                ":path" => stream.path = Some(value_str),
                ":authority" => stream.authority = Some(value_str),
                ":scheme" => stream.scheme = Some(value_str),
                ":status" => stream.status = value_str.parse().ok(),
                _ => stream.headers.push((name_str, value_str)),
            }
        })
        .map_err(|e| ParseError::new(ParseErrorKind::Http2HpackError(format!("{e:?}"))))?;

    if encoding_error {
        crate::trace_warn!(
            "HPACK decoded header with invalid UTF-8; dynamic table may contain tainted entry"
        );
        return Err(ParseError::new(ParseErrorKind::Http2InvalidHeaderEncoding));
    }

    if limit_exceeded {
        crate::trace_warn!("HPACK header list size/count limit exceeded");
        return Err(ParseError::new(ParseErrorKind::Http2HeaderListTooLarge));
    }

    Ok(())
}

/// Build a `ParsedH2Message` by taking ownership of a completed stream's data.
fn build_parsed_message_owned(stream_id: StreamId, stream: StreamState) -> ParsedH2Message {
    ParsedH2Message {
        method: stream.method,
        path: stream.path,
        authority: stream.authority,
        scheme: stream.scheme,
        status: stream.status,
        headers: stream.headers,
        stream_id,
        header_size: stream.header_size,
        body: stream.body,
        first_frame_timestamp_ns: stream.first_frame_timestamp_ns,
        end_stream_timestamp_ns: stream.end_stream_timestamp_ns,
    }
}

/// Check if the specified stream is complete and extract it if so.
/// Only checks the single stream that was just modified, avoiding a full scan.
fn check_stream_completion(
    state: &mut H2ConnectionState,
    stream_id: StreamId,
) -> Option<(StreamId, ParsedH2Message)> {
    let stream = state.active_streams.get(&stream_id)?;
    if stream.phase == StreamPhase::Complete {
        let stream = state.active_streams.remove(&stream_id)?;
        Some((stream_id, build_parsed_message_owned(stream_id, stream)))
    } else {
        None
    }
}
