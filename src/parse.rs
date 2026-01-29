use std::collections::HashMap;

use crate::frame::*;
use crate::state::{H2ConnectionState, ParseError, ParsedH2Message, StreamState};

/// Parse HTTP/2 frames with connection-level state
///
/// Processes the buffer for HTTP/2 frames and returns completed messages
/// indexed by stream_id. State is accumulated across calls for HPACK decoding
/// and stream tracking.
/// Returns `Err(ParseError::Http2BufferTooSmall)` if no complete messages yet.
pub fn parse_frames_stateful(
    buffer: &[u8],
    state: &mut H2ConnectionState,
) -> Result<HashMap<u32, ParsedH2Message>, ParseError> {
    let mut pos = 0;
    let mut completed_messages = HashMap::new();

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
                handle_data_frame(state, &header, frame_payload)?;
            }
            FRAME_TYPE_HEADERS => {
                handle_headers_frame(state, &header, frame_payload)?;
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

        // Check for completed streams
        extract_completed_streams(state, &mut completed_messages);
    }

    if completed_messages.is_empty() {
        Err(ParseError::Http2BufferTooSmall)
    } else {
        Ok(completed_messages)
    }
}

fn handle_headers_frame(
    state: &mut H2ConnectionState,
    header: &FrameHeader,
    payload: &[u8],
) -> Result<(), ParseError> {
    let stream_id = header.stream_id;

    // Create stream if new
    let stream = state
        .active_streams
        .entry(stream_id)
        .or_insert_with(|| StreamState::new(stream_id));

    // Handle PADDED flag
    // Padded frame format: [Pad Length (1 byte)] [Header Block] [Padding]
    let (header_block, _padding_len) = if header.flags & FLAG_PADDED != 0 {
        if payload.is_empty() {
            return Err(ParseError::Http2BufferTooSmall);
        }
        let pad_len = payload[0] as usize;
        if pad_len >= payload.len() {
            return Err(ParseError::Http2BufferTooSmall);
        }
        (&payload[1..payload.len() - pad_len], pad_len)
    } else {
        (payload, 0)
    };

    // Handle PRIORITY flag (skip 5 bytes)
    let header_block = if header.flags & FLAG_PRIORITY != 0 {
        if header_block.len() < 5 {
            return Err(ParseError::Http2BufferTooSmall);
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

        decode_headers_into_stream(&mut state.decoder, stream, &full_block)?;
        stream.end_headers_seen = true;
    } else {
        // Incomplete header block - wait for CONTINUATION
        stream.continuation_buffer.extend_from_slice(header_block);
    }

    // Check END_STREAM flag
    if header.flags & FLAG_END_STREAM != 0 {
        stream.end_stream_seen = true;
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
        decode_headers_into_stream(
            &mut state.decoder,
            stream,
            &stream.continuation_buffer.clone(),
        )?;
        stream.continuation_buffer.clear();
        stream.end_headers_seen = true;
    }

    Ok(())
}

fn handle_data_frame(
    state: &mut H2ConnectionState,
    header: &FrameHeader,
    payload: &[u8],
) -> Result<(), ParseError> {
    let stream = state
        .active_streams
        .get_mut(&header.stream_id)
        .ok_or(ParseError::Http2BufferTooSmall)?;

    // Handle PADDED flag
    // Padded frame format: [Pad Length (1 byte)] [Data] [Padding]
    let data = if header.flags & FLAG_PADDED != 0 {
        if payload.is_empty() {
            return Err(ParseError::Http2BufferTooSmall);
        }
        let pad_len = payload[0] as usize;
        // Data length = total - pad_length_byte - padding
        if pad_len >= payload.len() {
            return Err(ParseError::Http2BufferTooSmall);
        }
        &payload[1..payload.len() - pad_len]
    } else {
        payload
    };

    stream.body.extend_from_slice(data);

    if header.flags & FLAG_END_STREAM != 0 {
        stream.end_stream_seen = true;
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
            0x01 => state.settings.header_table_size = value,
            0x02 => state.settings.enable_push = value != 0,
            0x03 => state.settings.max_concurrent_streams = value,
            0x04 => state.settings.initial_window_size = value,
            0x05 => state.settings.max_frame_size = value,
            0x06 => state.settings.max_header_list_size = value,
            _ => {} // Unknown setting
        }

        pos += 6;
    }

    // Note: hpack crate's Decoder doesn't expose set_max_table_size in current API
    // This would be needed for proper HEADER_TABLE_SIZE handling

    Ok(())
}

fn decode_headers_into_stream(
    decoder: &mut loona_hpack::Decoder<'static>,
    stream: &mut StreamState,
    header_block: &[u8],
) -> Result<(), ParseError> {
    let decoded = decoder
        .decode(header_block)
        .map_err(|e| ParseError::Http2HpackError(format!("{:?}", e)))?;

    for (name, value) in decoded {
        let name_str = String::from_utf8_lossy(&name).to_string();
        let value_str = String::from_utf8_lossy(&value).to_string();

        // Handle pseudo-headers
        match name_str.as_str() {
            ":method" => stream.method = Some(value_str),
            ":path" => stream.path = Some(value_str),
            ":authority" => stream.authority = Some(value_str),
            ":scheme" => stream.scheme = Some(value_str),
            ":status" => stream.status = value_str.parse().ok(),
            _ => stream.headers.push((name_str, value_str)),
        }
    }

    Ok(())
}

fn extract_completed_streams(
    state: &mut H2ConnectionState,
    completed: &mut HashMap<u32, ParsedH2Message>,
) {
    let mut to_remove = Vec::new();

    for (stream_id, stream) in &state.active_streams {
        // Stream is complete if: headers decoded AND END_STREAM seen
        if stream.end_headers_seen && stream.end_stream_seen {
            completed.insert(
                *stream_id,
                ParsedH2Message {
                    method: stream.method.clone(),
                    path: stream.path.clone(),
                    authority: stream.authority.clone(),
                    scheme: stream.scheme.clone(),
                    status: stream.status,
                    headers: stream.headers.clone(),
                    stream_id: *stream_id,
                    header_size: stream.header_size,
                    body: stream.body.clone(),
                },
            );
            to_remove.push(*stream_id);
        }
    }

    for stream_id in to_remove {
        state.active_streams.remove(&stream_id);
    }
}
