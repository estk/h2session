//! Fuzz target: Raw byte parsing
//!
//! This fuzz target feeds completely random bytes to the parser.
//! The goal is to ensure the parser never panics on arbitrary input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use h2session::H2SessionCache;

fuzz_target!(|data: &[u8]| {
    // Create a fresh cache for each input
    let cache: H2SessionCache<u32> = H2SessionCache::new();

    // Try to parse the random data
    // We don't care about the result, only that it doesn't panic
    let _ = cache.parse(1, data);

    // Also try parsing in chunks to test incremental parsing
    if data.len() > 10 {
        let cache2: H2SessionCache<u32> = H2SessionCache::new();
        let mid = data.len() / 2;
        let _ = cache2.parse(2, &data[..mid]);
        let _ = cache2.parse(2, &data[mid..]);
    }

    // Try multiple "connections" with the same data
    let cache3: H2SessionCache<u32> = H2SessionCache::new();
    let _ = cache3.parse(1, data);
    let _ = cache3.parse(2, data);
    let _ = cache3.parse(3, data);
});
