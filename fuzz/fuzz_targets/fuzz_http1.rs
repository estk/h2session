//! Fuzz target: HTTP/1.x parsing
//!
//! Feeds random bytes to the HTTP/1 request and response parsers.
//! The goal is to ensure the parsers never panic on arbitrary input.

#![no_main]

use http_collator::h1;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try parsing as request
    let _ = h1::try_parse_http1_request(data, 0);

    // Try parsing as response
    let _ = h1::try_parse_http1_response(data, 0);

    // Also test protocol detection helpers
    let _ = h1::is_http1_request(data);
    let _ = h1::is_http1_response(data);

    // Test incremental: prefix of data
    if data.len() > 10 {
        let _ = h1::try_parse_http1_request(&data[..data.len() / 2], 0);
        let _ = h1::try_parse_http1_response(&data[..data.len() / 2], 0);
    }
});
