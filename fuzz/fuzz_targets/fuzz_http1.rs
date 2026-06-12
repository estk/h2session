//! Fuzz target: HTTP/1.x parsing
//!
//! Feeds random bytes to the HTTP/1 request and response parsers.
//! The goal is to ensure the parsers never panic on arbitrary input.

#![no_main]

use h2session::TimestampNs;
use http_collator::{h1, h1::MessageTimestamps};
use libfuzzer_sys::fuzz_target;

/// Zeroed lifecycle timestamps; the parsers under fuzz only thread these
/// through, so the values are irrelevant to the code paths being exercised.
const TS: MessageTimestamps = MessageTimestamps {
    start: TimestampNs(0),
    userspace_start: TimestampNs(0),
    complete: TimestampNs(0),
    userspace_complete: TimestampNs(0),
};

fuzz_target!(|data: &[u8]| {
    // Try parsing as request
    let _ = h1::try_parse_http1_request(data, TS);

    // Try parsing as response
    let _ = h1::try_parse_http1_response(data, TS);

    // Also test protocol detection helpers
    let _ = h1::is_http1_request(data);
    let _ = h1::is_http1_response(data);

    // Test incremental: prefix of data
    if data.len() > 10 {
        let _ = h1::try_parse_http1_request(&data[..data.len() / 2], TS);
        let _ = h1::try_parse_http1_response(&data[..data.len() / 2], TS);
    }
});
