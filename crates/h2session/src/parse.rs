use std::collections::HashMap;

use crate::frame::*;
use crate::state::{H2ConnectionState, ParseError, ParsedH2Message, StreamState};

/// Parse HTTP/2 frames with connection-level state
///
/// Processes the buffer for HTTP/2 frames and returns completed messages
/// indexed by stream_id. State is accumulated across calls for HPACK decoding
/// and stream tracking.
/// Returns `Ok(HashMap)` which may be empty if no streams completed yet.
///
/// NOTE: This function re-parses the entire buffer from the beginning each call.
/// For incremental parsing, use `H2ConnectionState::feed()` instead.
pub fn parse_frames_stateful(
    buffer: &[u8],
    state: &mut H2ConnectionState,
) -> Result<HashMap<u32, ParsedH2Message>, ParseError> {
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
        let frame_total_size = FRAME_HEADER_SIZE + header.length as usize;

        if pos + frame_total_size > buffer.len() {
            break; // Incomplete frame
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
            _ => {
                // Skip other frame types
            }
        }

        pos += frame_total_size;

        // Check only the stream that was just modified (stream_id 0 = connection-level)
        if header.stream_id != 0
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
        let frame_total_size = FRAME_HEADER_SIZE + header.length as usize;

        if pos + frame_total_size > state.buffer.len() {
            break; // Incomplete frame - wait for more data
        }

        let frame_payload = state.buffer[pos + FRAME_HEADER_SIZE..pos + frame_total_size].to_vec();

        let result = match header.frame_type {
            FRAME_TYPE_DATA => handle_data_frame(state, &header, &frame_payload, timestamp_ns),
            FRAME_TYPE_HEADERS => {
                handle_headers_frame(state, &header, &frame_payload, timestamp_ns)
            }
            FRAME_TYPE_CONTINUATION => handle_continuation_frame(state, &header, &frame_payload),
            FRAME_TYPE_SETTINGS => handle_settings_frame(state, &header, &frame_payload),
            _ => Ok(()),
        };

        // Always advance past the frame so it won't be re-processed
        pos += frame_total_size;

        let stream_id = header.stream_id;

        if let Err(e) = result {
            // HPACK errors corrupt the decoder's dynamic table — stop parsing
            if matches!(e, ParseError::Http2HpackError(_)) {
                fatal_error = Some(e);
                break;
            }
            // Other errors (missing stream, padding) are non-fatal: skip frame
            continue;
        }

        // Check only the stream that was just modified (stream_id 0 = connection-level)
        if stream_id != 0
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
    timestamp_ns: u64,
) -> Result<(), ParseError> {
    let stream_id = header.stream_id;

    // Reject new streams when at capacity (non-fatal: skip the frame)
    if !state.active_streams.contains_key(&stream_id)
        && state.active_streams.len() >= state.limits.max_concurrent_streams
    {
        return Err(ParseError::Http2MaxConcurrentStreams);
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
            return Err(ParseError::Http2PaddingError);
        }
        let pad_len = payload[0] as usize;
        if pad_len >= payload.len() {
            return Err(ParseError::Http2PaddingError);
        }
        (&payload[1..payload.len() - pad_len], pad_len)
    } else {
        (payload, 0)
    };

    // Handle PRIORITY flag (skip 5 bytes)
    let header_block = if header.flags & FLAG_PRIORITY != 0 {
        if header_block.len() < 5 {
            return Err(ParseError::Http2PriorityError);
        }
        &header_block[5..]
    } else {
        header_block
    };

    stream.header_size += FRAME_HEADER_SIZE + payload.len();

    // Check END_HEADERS flag
    if header.flags & FLAG_END_HEADERS != 0 {
        // Complete header block - decode now
        let full_block: Vec<u8> = if stream.continuation_buffer.is_empty() {
            header_block.to_vec()
        } else {
            stream.continuation_buffer.extend_from_slice(header_block);
            std::mem::take(&mut stream.continuation_buffer)
        };

        decode_headers_into_stream(&mut state.decoder, stream, &full_block, &state.limits)?;
        stream.end_headers_seen = true;
    } else {
        // Incomplete header block - wait for CONTINUATION
        stream.continuation_buffer.extend_from_slice(header_block);
    }

    // Check END_STREAM flag
    if header.flags & FLAG_END_STREAM != 0 {
        stream.end_stream_seen = true;
        stream.end_stream_timestamp_ns = timestamp_ns;
    }

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
        .ok_or(ParseError::Http2HeadersIncomplete)?;

    stream.continuation_buffer.extend_from_slice(payload);
    stream.header_size += FRAME_HEADER_SIZE + payload.len();

    if header.flags & FLAG_END_HEADERS != 0 {
        let buf = std::mem::take(&mut stream.continuation_buffer);
        decode_headers_into_stream(&mut state.decoder, stream, &buf, &state.limits)?;
        stream.end_headers_seen = true;
    }

    Ok(())
}

fn handle_data_frame(
    state: &mut H2ConnectionState,
    header: &FrameHeader,
    payload: &[u8],
    timestamp_ns: u64,
) -> Result<(), ParseError> {
    // Handle PADDED flag before borrowing the stream
    // Padded frame format: [Pad Length (1 byte)] [Data] [Padding]
    let data = if header.flags & FLAG_PADDED != 0 {
        if payload.is_empty() {
            return Err(ParseError::Http2PaddingError);
        }
        let pad_len = payload[0] as usize;
        // Data length = total - pad_length_byte - padding
        if pad_len >= payload.len() {
            return Err(ParseError::Http2PaddingError);
        }
        &payload[1..payload.len() - pad_len]
    } else {
        payload
    };

    // Check body size limit before borrowing the stream mutably
    {
        let stream = state
            .active_streams
            .get(&header.stream_id)
            .ok_or(ParseError::Http2StreamNotFound)?;
        if stream.body.len() + data.len() > state.limits.max_body_size {
            // Drop the stream rather than accumulating unbounded data
            state.active_streams.remove(&header.stream_id);
            return Ok(());
        }
    }

    let stream = state
        .active_streams
        .get_mut(&header.stream_id)
        .ok_or(ParseError::Http2StreamNotFound)?;

    stream.body.extend_from_slice(data);

    if header.flags & FLAG_END_STREAM != 0 {
        stream.end_stream_seen = true;
        stream.end_stream_timestamp_ns = timestamp_ns;
    }

    Ok(())
}

fn handle_settings_frame(
    state: &mut H2ConnectionState,
    _header: &FrameHeader,
    payload: &[u8],
) -> Result<(), ParseError> {
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
                state.settings.header_table_size = value;
                let capped = (value as usize).min(state.limits.max_table_size);
                state.decoder.set_max_table_size(capped);
            }
            0x02 => state.settings.enable_push = value != 0,
            0x03 => state.settings.max_concurrent_streams = value,
            0x04 => state.settings.initial_window_size = value,
            0x05 => state.settings.max_frame_size = value,
            0x06 => state.settings.max_header_list_size = value,
            _ => {} // Unknown setting
        }

        pos += 6;
    }

    Ok(())
}

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
        .map_err(|e| ParseError::Http2HpackError(format!("{e:?}")))?;

    if encoding_error {
        return Err(ParseError::Http2InvalidHeaderEncoding);
    }

    if limit_exceeded {
        return Err(ParseError::Http2HeaderListTooLarge);
    }

    Ok(())
}

/// Build a `ParsedH2Message` by taking ownership of a completed stream's data.
fn build_parsed_message_owned(stream_id: u32, stream: StreamState) -> ParsedH2Message {
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
    stream_id: u32,
) -> Option<(u32, ParsedH2Message)> {
    let stream = state.active_streams.get(&stream_id)?;
    if stream.end_headers_seen && stream.end_stream_seen {
        let stream = state.active_streams.remove(&stream_id)?;
        Some((stream_id, build_parsed_message_owned(stream_id, stream)))
    } else {
        None
    }
}
