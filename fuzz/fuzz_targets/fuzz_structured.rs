//! Fuzz target: Structured frame generation
//!
//! This fuzz target generates semi-valid HTTP/2 frames using the Arbitrary
//! trait. This is more effective at finding bugs in frame handling logic since
//! the inputs are structurally valid but have random field values.

#![no_main]

use arbitrary::Arbitrary;
use h2session::H2SessionCache;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 connection preface
const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Frame types
const FRAME_TYPE_DATA: u8 = 0x00;
const FRAME_TYPE_HEADERS: u8 = 0x01;
const FRAME_TYPE_SETTINGS: u8 = 0x04;

/// Frame flags
const FLAG_PADDED: u8 = 0x08;
const FLAG_PRIORITY: u8 = 0x20;

/// A structured HTTP/2 frame for fuzzing
#[derive(Debug, Arbitrary)]
struct FuzzFrame {
    frame_type:   u8,
    flags:        u8,
    stream_id:    u32,
    payload:      Vec<u8>,
    /// Extra flags to control frame generation
    add_padding:  bool,
    add_priority: bool,
    padding_len:  u8,
}

impl FuzzFrame {
    fn to_bytes(&self) -> Vec<u8> {
        let frame_type = self.frame_type % 10; // Valid frame types 0-9
        let stream_id = self.stream_id & 0x7FFFFFFF; // Clear reserved bit

        let mut payload = self.payload.clone();
        let mut flags = self.flags;

        // Handle PADDED flag for DATA and HEADERS
        if self.add_padding && (frame_type == FRAME_TYPE_DATA || frame_type == FRAME_TYPE_HEADERS) {
            let pad_len = self.padding_len.min(200); // Reasonable padding
            if payload.len() + 1 + pad_len as usize <= 16384 {
                flags |= FLAG_PADDED;
                let mut new_payload = vec![pad_len];
                new_payload.extend(&payload);
                new_payload.extend(std::iter::repeat(0u8).take(pad_len as usize));
                payload = new_payload;
            }
        }

        // Handle PRIORITY flag for HEADERS
        if self.add_priority && frame_type == FRAME_TYPE_HEADERS {
            if payload.len() + 5 <= 16384 {
                flags |= FLAG_PRIORITY;
                let mut new_payload = Vec::new();
                // If already padded, insert priority after pad length
                if flags & FLAG_PADDED != 0 && !payload.is_empty() {
                    new_payload.push(payload[0]); // Pad length
                    new_payload.extend(&[0, 0, 0, 0, 16]); // Priority: dep=0, weight=16
                    new_payload.extend(&payload[1..]);
                } else {
                    new_payload.extend(&[0, 0, 0, 0, 16]); // Priority
                    new_payload.extend(&payload);
                }
                payload = new_payload;
            }
        }

        // Limit payload size
        if payload.len() > 16384 {
            payload.truncate(16384);
        }

        let length = payload.len() as u32;

        let mut frame = Vec::with_capacity(9 + payload.len());
        // Length (24-bit)
        frame.push((length >> 16) as u8);
        frame.push((length >> 8) as u8);
        frame.push(length as u8);
        // Type
        frame.push(frame_type);
        // Flags
        frame.push(flags);
        // Stream ID (31-bit)
        frame.push((stream_id >> 24) as u8 & 0x7F);
        frame.push((stream_id >> 16) as u8);
        frame.push((stream_id >> 8) as u8);
        frame.push(stream_id as u8);
        // Payload
        frame.extend(&payload);

        frame
    }
}

/// A sequence of frames for fuzzing
#[derive(Debug, Arbitrary)]
struct FuzzConnection {
    include_preface:  bool,
    include_settings: bool,
    frames:           Vec<FuzzFrame>,
}

impl FuzzConnection {
    fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();

        if self.include_preface {
            data.extend_from_slice(CONNECTION_PREFACE);
        }

        if self.include_settings {
            // Empty SETTINGS frame
            data.extend(&[0, 0, 0, FRAME_TYPE_SETTINGS, 0, 0, 0, 0, 0]);
        }

        for frame in &self.frames {
            data.extend(frame.to_bytes());
        }

        data
    }
}

fuzz_target!(|conn: FuzzConnection| {
    let data = conn.to_bytes();
    let cache: H2SessionCache<u32> = H2SessionCache::new();

    // Parse the structured input
    let _ = cache.parse(1, &data);

    // Test incremental parsing with same structured input
    if data.len() > 20 {
        let cache2: H2SessionCache<u32> = H2SessionCache::new();
        for chunk in data.chunks(33) {
            // Odd chunk size to hit boundaries
            let _ = cache2.parse(2, chunk);
        }
    }
});
