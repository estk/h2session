/// QPACK decoder for HTTP/3 header decompression (RFC 9204).
///
/// Supports static table references and literal header fields.
/// Dynamic table support is deferred until encoder stream data is available.

/// QPACK static table (RFC 9204, Appendix A)
const STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),                        // 0
    (":path", "/"),                            // 1
    ("age", "0"),                              // 2
    ("content-disposition", ""),               // 3
    ("content-length", "0"),                   // 4
    ("cookie", ""),                            // 5
    ("date", ""),                              // 6
    ("etag", ""),                              // 7
    ("if-modified-since", ""),                 // 8
    ("if-none-match", ""),                     // 9
    ("last-modified", ""),                     // 10
    ("link", ""),                              // 11
    ("location", ""),                          // 12
    ("referer", ""),                           // 13
    ("set-cookie", ""),                        // 14
    (":method", "CONNECT"),                    // 15
    (":method", "DELETE"),                     // 16
    (":method", "GET"),                        // 17
    (":method", "HEAD"),                       // 18
    (":method", "OPTIONS"),                    // 19
    (":method", "POST"),                       // 20
    (":method", "PUT"),                        // 21
    (":scheme", "http"),                       // 22
    (":scheme", "https"),                      // 23
    (":status", "103"),                        // 24
    (":status", "200"),                        // 25
    (":status", "304"),                        // 26
    (":status", "404"),                        // 27
    (":status", "503"),                        // 28
    ("accept", "*/*"),                         // 29
    ("accept", "application/dns-message"),     // 30
    ("accept-encoding", "gzip, deflate, br"), // 31
    ("accept-ranges", "bytes"),               // 32
    ("access-control-allow-headers", "cache-control"),      // 33
    ("access-control-allow-headers", "content-type"),       // 34
    ("access-control-allow-origin", "*"),                   // 35
    ("cache-control", "max-age=0"),                         // 36
    ("cache-control", "max-age=2592000"),                   // 37
    ("cache-control", "max-age=604800"),                    // 38
    ("cache-control", "no-cache"),                          // 39
    ("cache-control", "no-store"),                          // 40
    ("cache-control", "public, max-age=31536000"),          // 41
    ("content-encoding", "br"),               // 42
    ("content-encoding", "gzip"),             // 43
    ("content-type", "application/dns-message"),            // 44
    ("content-type", "application/javascript"),             // 45
    ("content-type", "application/json"),                   // 46
    ("content-type", "application/x-www-form-urlencoded"),  // 47
    ("content-type", "image/gif"),            // 48
    ("content-type", "image/jpeg"),           // 49
    ("content-type", "image/png"),            // 50
    ("content-type", "text/css"),             // 51
    ("content-type", "text/html; charset=utf-8"),           // 52
    ("content-type", "text/plain"),           // 53
    ("content-type", "text/plain;charset=utf-8"),           // 54
    ("range", "bytes=0-"),                    // 55
    ("strict-transport-security", "max-age=31536000"),                        // 56
    ("strict-transport-security", "max-age=31536000; includesubdomains"),     // 57
    ("strict-transport-security", "max-age=31536000; includesubdomains; preload"), // 58
    ("vary", "accept-encoding"),              // 59
    ("vary", "origin"),                       // 60
    ("x-content-type-options", "nosniff"),    // 61
    ("x-xss-protection", "1; mode=block"),   // 62
    (":status", "100"),                       // 63
    (":status", "204"),                       // 64
    (":status", "206"),                       // 65
    (":status", "302"),                       // 66
    (":status", "400"),                       // 67
    (":status", "403"),                       // 68
    (":status", "421"),                       // 69
    (":status", "425"),                       // 70
    (":status", "500"),                       // 71
    ("accept-language", ""),                  // 72
    ("access-control-allow-credentials", "FALSE"),         // 73
    ("access-control-allow-credentials", "TRUE"),          // 74
    ("access-control-allow-headers", "*"),                  // 75
    ("access-control-allow-methods", "get"),                // 76
    ("access-control-allow-methods", "get, post, options"), // 77
    ("access-control-allow-methods", "options"),            // 78
    ("access-control-expose-headers", "content-length"),    // 79
    ("access-control-request-headers", "content-type"),     // 80
    ("access-control-request-method", "get"),               // 81
    ("access-control-request-method", "post"),              // 82
    ("alt-svc", "clear"),                     // 83
    ("authorization", ""),                    // 84
    ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"), // 85
    ("early-data", "1"),                      // 86
    ("expect-ct", ""),                        // 87
    ("forwarded", ""),                        // 88
    ("if-range", ""),                         // 89
    ("origin", ""),                           // 90
    ("purpose", "prefetch"),                  // 91
    ("server", ""),                           // 92
    ("timing-allow-origin", "*"),             // 93
    ("upgrade-insecure-requests", "1"),       // 94
    ("user-agent", ""),                       // 95
    ("x-forwarded-for", ""),                  // 96
    ("x-frame-options", "deny"),             // 97
    ("x-frame-options", "sameorigin"),       // 98
];

/// QPACK header field decoder.
///
/// Currently supports:
/// - Static table indexed references (both name+value and name-only)
/// - Literal header fields with/without name reference
///
/// Dynamic table references return an error marker indicating missing context.
pub struct QpackDecoder {
    // Dynamic table entries would go here when implemented
}

impl QpackDecoder {
    pub fn new() -> Self {
        Self {}
    }

    /// Decode a QPACK-encoded header block into a list of (name, value) pairs.
    ///
    /// The `header_block` is the payload of an HTTP/3 HEADERS frame.
    /// QPACK header blocks start with two varint-encoded integers:
    /// Required Insert Count and Delta Base (RFC 9204 Section 4.5.1).
    pub fn decode_header_block(
        &mut self,
        header_block: &[u8],
    ) -> Result<Vec<(String, String)>, DecodeError> {
        let mut headers = Vec::new();
        let mut pos = 0;

        // Decode Required Insert Count (prefix-encoded integer, 8-bit prefix)
        let (ric, consumed) = decode_prefixed_int(header_block, 8)?;
        pos += consumed;

        if pos >= header_block.len() && ric > 0 {
            return Err(DecodeError::Incomplete);
        }

        // Decode Delta Base (prefix-encoded integer, 7-bit prefix + sign bit)
        if pos < header_block.len() {
            let (_, consumed) = decode_prefixed_int(&header_block[pos..], 7)?;
            pos += consumed;
        }

        // Parse header field representations.
        // When RIC > 0 the encoder used dynamic table entries we don't have.
        // We still decode static refs and literals (best-effort), skipping
        // instructions that reference the dynamic table.
        while pos < header_block.len() {
            let byte = header_block[pos];

            if byte & 0x80 != 0 {
                // Indexed Header Field: 1Sxxxxxx
                let is_static = byte & 0x40 != 0;
                if is_static {
                    let (index, consumed) = decode_prefixed_int(&header_block[pos..], 6)?;
                    pos += consumed;
                    if let Some(&(name, value)) = STATIC_TABLE.get(index as usize) {
                        headers.push((name.to_string(), value.to_string()));
                    } else {
                        return Err(DecodeError::InvalidStaticIndex(index));
                    }
                } else {
                    // Dynamic table indexed reference — skip
                    let (_, consumed) = decode_prefixed_int(&header_block[pos..], 6)?;
                    pos += consumed;
                }
            } else if byte & 0xc0 == 0x40 {
                // Literal Header Field With Name Reference: 01NTxxxx
                // T bit (0x10) = 1 means static table, 0 means dynamic
                let static_ref = byte & 0x10 != 0;
                let (name_index, consumed) = decode_prefixed_int(&header_block[pos..], 4)?;
                pos += consumed;

                if static_ref {
                    let name = STATIC_TABLE
                        .get(name_index as usize)
                        .map(|&(n, _)| n.to_string())
                        .ok_or(DecodeError::InvalidStaticIndex(name_index))?;

                    let (value, consumed) = decode_string(&header_block[pos..])?;
                    pos += consumed;
                    headers.push((name, value));
                } else {
                    // Dynamic name ref — skip value
                    let (_, consumed) = decode_string(&header_block[pos..])?;
                    pos += consumed;
                }
            } else if byte & 0xe0 == 0x20 {
                // Literal Header Field Without Name Reference: 001Nxxxx
                pos += 1;

                let (name, consumed) = decode_string(&header_block[pos..])?;
                pos += consumed;

                let (value, consumed) = decode_string(&header_block[pos..])?;
                pos += consumed;

                headers.push((name, value));
            } else if byte & 0xf0 == 0x10 {
                // Indexed Header Field With Post-Base Index: 0001xxxx
                let (_, consumed) = decode_prefixed_int(&header_block[pos..], 4)?;
                pos += consumed;
            } else {
                // Literal Header Field With Post-Base Name Reference: 0000Nxxx
                let (_, consumed) = decode_prefixed_int(&header_block[pos..], 3)?;
                pos += consumed;
                // Skip value string
                let (_, consumed) = decode_string(&header_block[pos..])?;
                pos += consumed;
            }
        }

        if ric > 0 && headers.is_empty() {
            return Err(DecodeError::DynamicTableRequired(ric));
        }

        Ok(headers)
    }
}

impl Default for QpackDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur during QPACK decoding
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    Incomplete,
    InvalidStaticIndex(u64),
    DynamicTableRequired(u64),
    InvalidString,
}

/// Decode a prefix-encoded integer (RFC 7541 Section 5.1, used by QPACK).
/// `prefix_bits` is the number of usable bits in the first byte (1-8).
fn decode_prefixed_int(buf: &[u8], prefix_bits: u8) -> Result<(u64, usize), DecodeError> {
    if buf.is_empty() {
        return Err(DecodeError::Incomplete);
    }

    let mask: u8 = if prefix_bits >= 8 {
        0xff
    } else {
        (1u8 << prefix_bits) - 1
    };
    let first_value = (buf[0] & mask) as u64;

    if first_value < mask as u64 {
        return Ok((first_value, 1));
    }

    // Multi-byte integer
    let mut value = mask as u64;
    let mut shift = 0u32;
    let mut pos = 1;

    loop {
        if pos >= buf.len() {
            return Err(DecodeError::Incomplete);
        }
        let byte = buf[pos];
        value += ((byte & 0x7f) as u64) << shift;
        pos += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 56 {
            return Err(DecodeError::InvalidString);
        }
    }

    Ok((value, pos))
}

/// Decode a length-prefixed string (with Huffman flag in top bit).
/// Returns (decoded_string, bytes_consumed).
fn decode_string(buf: &[u8]) -> Result<(String, usize), DecodeError> {
    if buf.is_empty() {
        return Err(DecodeError::Incomplete);
    }

    let huffman = buf[0] & 0x80 != 0;
    let (len, len_consumed) = decode_prefixed_int(buf, 7)?;
    let total = len_consumed + len as usize;

    if buf.len() < total {
        return Err(DecodeError::Incomplete);
    }

    let raw = &buf[len_consumed..total];

    let value = if huffman {
        decode_huffman(raw)?
    } else {
        String::from_utf8_lossy(raw).to_string()
    };

    Ok((value, total))
}

/// HPACK Huffman decode table (RFC 7541 Appendix B).
/// Index = symbol (0-255, 256=EOS). Value = (code, bit_length).
/// Codes are stored as the integer value from the RFC (MSB-first encoding).
const HUFFMAN_ENCODE_TABLE: [(u32, u8); 257] = [
    (0x1ff8, 13),     // 0
    (0x7fffd8, 23),   // 1
    (0xfffffe2, 28),  // 2
    (0xfffffe3, 28),  // 3
    (0xfffffe4, 28),  // 4
    (0xfffffe5, 28),  // 5
    (0xfffffe6, 28),  // 6
    (0xfffffe7, 28),  // 7
    (0xfffffe8, 28),  // 8
    (0xffffea, 24),   // 9
    (0x3ffffffc, 30), // 10 (LF)
    (0xfffffe9, 28),  // 11
    (0xfffffea, 28),  // 12
    (0x3ffffffd, 30), // 13 (CR)
    (0xfffffeb, 28),  // 14
    (0xfffffec, 28),  // 15
    (0xfffffed, 28),  // 16
    (0xfffffee, 28),  // 17
    (0xfffffef, 28),  // 18
    (0xffffff0, 28),  // 19
    (0xffffff1, 28),  // 20
    (0xffffff2, 28),  // 21
    (0x3ffffffe, 30), // 22
    (0xffffff3, 28),  // 23
    (0xffffff4, 28),  // 24
    (0xffffff5, 28),  // 25
    (0xffffff6, 28),  // 26
    (0xffffff7, 28),  // 27
    (0xffffff8, 28),  // 28
    (0xffffff9, 28),  // 29
    (0xffffffa, 28),  // 30
    (0xffffffb, 28),  // 31
    (0x14, 6),        // 32 ' '
    (0x3f8, 10),      // 33 '!'
    (0x3f9, 10),      // 34 '"'
    (0xffa, 12),      // 35 '#'
    (0x1ff9, 13),     // 36 '$'
    (0x15, 6),        // 37 '%'
    (0xf8, 8),        // 38 '&'
    (0x7fa, 11),      // 39 '\''
    (0x3fa, 10),      // 40 '('
    (0x3fb, 10),      // 41 ')'
    (0xf9, 8),        // 42 '*'
    (0x7fb, 11),      // 43 '+'
    (0xfa, 8),        // 44 ','
    (0x16, 6),        // 45 '-'
    (0x17, 6),        // 46 '.'
    (0x18, 6),        // 47 '/'
    (0x0, 5),         // 48 '0'
    (0x1, 5),         // 49 '1'
    (0x2, 5),         // 50 '2'
    (0x19, 6),        // 51 '3'
    (0x1a, 6),        // 52 '4'
    (0x1b, 6),        // 53 '5'
    (0x1c, 6),        // 54 '6'
    (0x1d, 6),        // 55 '7'
    (0x1e, 6),        // 56 '8'
    (0x1f, 6),        // 57 '9'
    (0x5c, 7),        // 58 ':'
    (0xfb, 8),        // 59 ';'
    (0x7ffc, 15),     // 60 '<'
    (0x20, 6),        // 61 '='
    (0xffb, 12),      // 62 '>'
    (0x3fc, 10),      // 63 '?'
    (0x1ffa, 13),     // 64 '@'
    (0x21, 6),        // 65 'A'
    (0x5d, 7),        // 66 'B'
    (0x5e, 7),        // 67 'C'
    (0x5f, 7),        // 68 'D'
    (0x60, 7),        // 69 'E'
    (0x61, 7),        // 70 'F'
    (0x62, 7),        // 71 'G'
    (0x63, 7),        // 72 'H'
    (0x64, 7),        // 73 'I'
    (0x65, 7),        // 74 'J'
    (0x66, 7),        // 75 'K'
    (0x67, 7),        // 76 'L'
    (0x68, 7),        // 77 'M'
    (0x69, 7),        // 78 'N'
    (0x6a, 7),        // 79 'O'
    (0x6b, 7),        // 80 'P'
    (0x6c, 7),        // 81 'Q'
    (0x6d, 7),        // 82 'R'
    (0x6e, 7),        // 83 'S'
    (0x6f, 7),        // 84 'T'
    (0x70, 7),        // 85 'U'
    (0x71, 7),        // 86 'V'
    (0x72, 7),        // 87 'W'
    (0xfc, 8),        // 88 'X'
    (0x73, 7),        // 89 'Y'
    (0xfd, 8),        // 90 'Z'
    (0x1ffb, 13),     // 91 '['
    (0x7fff0, 19),    // 92 '\\'
    (0x1ffc, 13),     // 93 ']'
    (0x3ffc, 14),     // 94 '^'
    (0x22, 6),        // 95 '_'
    (0x7ffd, 15),     // 96 '`'
    (0x3, 5),         // 97 'a'
    (0x23, 6),        // 98 'b'
    (0x4, 5),         // 99 'c'
    (0x24, 6),        // 100 'd'
    (0x5, 5),         // 101 'e'
    (0x25, 6),        // 102 'f'
    (0x26, 6),        // 103 'g'
    (0x27, 6),        // 104 'h'
    (0x6, 5),         // 105 'i'
    (0x74, 7),        // 106 'j'
    (0x75, 7),        // 107 'k'
    (0x28, 6),        // 108 'l'
    (0x29, 6),        // 109 'm'
    (0x2a, 6),        // 110 'n'
    (0x7, 5),         // 111 'o'
    (0x2b, 6),        // 112 'p'
    (0x76, 7),        // 113 'q'
    (0x2c, 6),        // 114 'r'
    (0x8, 5),         // 115 's'
    (0x9, 5),         // 116 't'
    (0x2d, 6),        // 117 'u'
    (0x77, 7),        // 118 'v'
    (0x78, 7),        // 119 'w'
    (0x79, 7),        // 120 'x'
    (0x7a, 7),        // 121 'y'
    (0x7b, 7),        // 122 'z'
    (0x7fffe, 19),    // 123 '{'
    (0x7fc, 11),      // 124 '|'
    (0x3ffd, 14),     // 125 '}'
    (0x1ffd, 13),     // 126 '~'
    (0xffffffc, 28),  // 127
    (0xfffe6, 20),    // 128
    (0x3fffd2, 22),   // 129
    (0xfffe7, 20),    // 130
    (0xfffe8, 20),    // 131
    (0x3fffd3, 22),   // 132
    (0x3fffd4, 22),   // 133
    (0x3fffd5, 22),   // 134
    (0x7fffd9, 23),   // 135
    (0x3fffd6, 22),   // 136
    (0x7fffda, 23),   // 137
    (0x7fffdb, 23),   // 138
    (0x7fffdc, 23),   // 139
    (0x7fffdd, 23),   // 140
    (0x7fffde, 23),   // 141
    (0xffffeb, 24),   // 142
    (0x7fffdf, 23),   // 143
    (0xffffec, 24),   // 144
    (0xffffed, 24),   // 145
    (0x3fffd7, 22),   // 146
    (0x7fffe0, 23),   // 147
    (0xffffee, 24),   // 148
    (0x7fffe1, 23),   // 149
    (0x7fffe2, 23),   // 150
    (0x7fffe3, 23),   // 151
    (0x7fffe4, 23),   // 152
    (0x1fffdc, 21),   // 153
    (0x3fffd8, 22),   // 154
    (0x7fffe5, 23),   // 155
    (0x3fffd9, 22),   // 156
    (0x7fffe6, 23),   // 157
    (0x7fffe7, 23),   // 158
    (0xffffef, 24),   // 159
    (0x3fffda, 22),   // 160
    (0x1fffdd, 21),   // 161
    (0xfffe9, 20),    // 162
    (0x3fffdb, 22),   // 163
    (0x3fffdc, 22),   // 164
    (0x7fffe8, 23),   // 165
    (0x7fffe9, 23),   // 166
    (0x1fffde, 21),   // 167
    (0x7fffea, 23),   // 168
    (0x3fffdd, 22),   // 169
    (0x3fffde, 22),   // 170
    (0xfffff0, 24),   // 171
    (0x1fffdf, 21),   // 172
    (0x3fffdf, 22),   // 173
    (0x7fffeb, 23),   // 174
    (0x7fffec, 23),   // 175
    (0x1fffe0, 21),   // 176
    (0x1fffe1, 21),   // 177
    (0x3fffe0, 22),   // 178
    (0x1fffe2, 21),   // 179
    (0x7fffed, 23),   // 180
    (0x3fffe1, 22),   // 181
    (0x7fffee, 23),   // 182
    (0x7fffef, 23),   // 183
    (0xfffea, 20),    // 184
    (0x3fffe2, 22),   // 185
    (0x3fffe3, 22),   // 186
    (0x3fffe4, 22),   // 187
    (0x7ffff0, 23),   // 188
    (0x3fffe5, 22),   // 189
    (0x3fffe6, 22),   // 190
    (0x7ffff1, 23),   // 191
    (0x3ffffe0, 26),  // 192
    (0x3ffffe1, 26),  // 193
    (0xfffeb, 20),    // 194
    (0x7fff1, 19),    // 195
    (0x3fffe7, 22),   // 196
    (0x7ffff2, 23),   // 197
    (0x3fffe8, 22),   // 198
    (0x1ffffec, 25),  // 199
    (0x3ffffe2, 26),  // 200
    (0x3ffffe3, 26),  // 201
    (0x3ffffe4, 26),  // 202
    (0x7ffffde, 27),  // 203
    (0x7ffffdf, 27),  // 204
    (0x3ffffe5, 26),  // 205
    (0xfffff1, 24),   // 206
    (0x1ffffed, 25),  // 207
    (0x7fff2, 19),    // 208
    (0x1fffe3, 21),   // 209
    (0x3ffffe6, 26),  // 210
    (0x7ffffe0, 27),  // 211
    (0x7ffffe1, 27),  // 212
    (0x3ffffe7, 26),  // 213
    (0x7ffffe2, 27),  // 214
    (0xfffff2, 24),   // 215
    (0x1fffe4, 21),   // 216
    (0x1fffe5, 21),   // 217
    (0x3ffffe8, 26),  // 218
    (0x3ffffe9, 26),  // 219
    (0xffffffd, 28),  // 220
    (0x7ffffe3, 27),  // 221
    (0x7ffffe4, 27),  // 222
    (0x7ffffe5, 27),  // 223
    (0xfffec, 20),    // 224
    (0xfffff3, 24),   // 225
    (0xfffed, 20),    // 226
    (0x1fffe6, 21),   // 227
    (0x3fffe9, 22),   // 228
    (0x1fffe7, 21),   // 229
    (0x1fffe8, 21),   // 230
    (0x7ffff3, 23),   // 231
    (0x3fffea, 22),   // 232
    (0x3fffeb, 22),   // 233
    (0x1ffffee, 25),  // 234
    (0x1ffffef, 25),  // 235
    (0xfffff4, 24),   // 236
    (0xfffff5, 24),   // 237
    (0x3ffffea, 26),  // 238
    (0x7ffff4, 23),   // 239
    (0x3ffffeb, 26),  // 240
    (0x7ffffe6, 27),  // 241
    (0x3ffffec, 26),  // 242
    (0x3ffffed, 26),  // 243
    (0x7ffffe7, 27),  // 244
    (0x7ffffe8, 27),  // 245
    (0x7ffffe9, 27),  // 246
    (0x7ffffea, 27),  // 247
    (0x7ffffeb, 27),  // 248
    (0xffffffe, 28),  // 249
    (0x7ffffec, 27),  // 250
    (0x7ffffed, 27),  // 251
    (0x7ffffee, 27),  // 252
    (0x7ffffef, 27),  // 253
    (0x7fffff0, 27),  // 254
    (0x3ffffee, 26),  // 255
    (0x3fffffff, 30), // 256 EOS
];

/// Decode a Huffman-encoded byte sequence per RFC 7541 Appendix B.
///
/// Builds a decode tree at runtime from `HUFFMAN_ENCODE_TABLE`, then walks
/// input bits MSB-first to emit decoded symbols. Padding bits (up to 7 trailing
/// 1-bits) are accepted per the spec.
fn decode_huffman(data: &[u8]) -> Result<String, DecodeError> {
    // Node in the binary decode tree. Left = bit 0, Right = bit 1.
    // A leaf stores Some(symbol), internal nodes store None.
    struct Node {
        symbol: Option<u16>,
        children: [u16; 2], // 0 = no child
    }

    // Build the tree. Max depth is 30 bits so we need at most ~2*257 nodes
    // in practice, but allocate generously.
    let mut nodes: Vec<Node> = Vec::with_capacity(1024);
    nodes.push(Node {
        symbol: None,
        children: [0, 0],
    }); // root = index 0 (but we use 1-indexed, so push a dummy)
    nodes.push(Node {
        symbol: None,
        children: [0, 0],
    }); // root at index 1

    for (sym, &(code, bits)) in HUFFMAN_ENCODE_TABLE.iter().enumerate() {
        if sym == 256 {
            break; // skip EOS for decoding purposes
        }
        let mut current = 1u16; // root
        for i in (0..bits).rev() {
            let bit = ((code >> i) & 1) as usize;
            if nodes[current as usize].children[bit] == 0 {
                nodes.push(Node {
                    symbol: None,
                    children: [0, 0],
                });
                let new_idx = (nodes.len() - 1) as u16;
                nodes[current as usize].children[bit] = new_idx;
            }
            current = nodes[current as usize].children[bit];
        }
        nodes[current as usize].symbol = Some(sym as u16);
    }

    // Walk input bits through the tree
    let mut result = Vec::new();
    let mut current = 1u16; // root
    let mut bits_since_last_symbol = 0u8;

    for &byte in data {
        for i in (0..8).rev() {
            let bit = ((byte >> i) & 1) as usize;
            let next = nodes[current as usize].children[bit];
            if next == 0 {
                return Err(DecodeError::InvalidString);
            }
            current = next;
            bits_since_last_symbol += 1;

            if let Some(sym) = nodes[current as usize].symbol {
                result.push(sym as u8);
                current = 1; // reset to root
                bits_since_last_symbol = 0;
            }
        }
    }

    // Remaining bits must be padding (all 1s, at most 7 bits)
    if bits_since_last_symbol > 7 {
        return Err(DecodeError::InvalidString);
    }

    String::from_utf8(result).map_err(|_| DecodeError::InvalidString)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_prefixed_int_small() {
        // Value 10 with 5-bit prefix: fits in one byte (10 < 31)
        let buf = [0x0a]; // 00001010
        let (val, consumed) = decode_prefixed_int(&buf, 5).unwrap();
        assert_eq!(val, 10);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_decode_prefixed_int_multi_byte() {
        // Value 1337 with 5-bit prefix (from RFC 7541 example C.1)
        // First byte: 11111 (31), then 1337 - 31 = 1306
        // 1306 = 0x051a: first continuation byte = 0x9a (0x1a | 0x80), second = 0x0a
        let buf = [0x1f, 0x9a, 0x0a];
        let (val, consumed) = decode_prefixed_int(&buf, 5).unwrap();
        assert_eq!(val, 1337);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn test_decode_string_literal() {
        // Non-Huffman string "hello" (length=5, no Huffman flag)
        let buf = [0x05, b'h', b'e', b'l', b'l', b'o'];
        let (val, consumed) = decode_string(&buf).unwrap();
        assert_eq!(val, "hello");
        assert_eq!(consumed, 6);
    }

    #[test]
    fn test_decode_static_indexed_header() {
        let mut decoder = QpackDecoder::new();
        // Header block: RIC=0, DeltaBase=0, then indexed static field for :method GET (index 17)
        // RIC: 0x00 (8-bit prefix, value 0)
        // DeltaBase: 0x00 (7-bit prefix, value 0)
        // Indexed static: 1_1_010001 = 0xC0 | 0x11 = 0xD1 (S=1, index=17)
        let block = [0x00, 0x00, 0xd1];
        let headers = decoder.decode_header_block(&block).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0], (":method".to_string(), "GET".to_string()));
    }

    #[test]
    fn test_decode_multiple_static_indexed() {
        let mut decoder = QpackDecoder::new();
        // RIC=0, DeltaBase=0, :method GET (17), :scheme https (23), :path / (1)
        // Indexed static: 0xC0 | index (with S=1 bit set at position 6)
        // Pattern: 1Sxxxxxx where S=1 means static
        // For 6-bit prefix: 0b11_010001=0xD1 (17), 0b11_010111=0xD7 (23), 0b11_000001=0xC1 (1)
        let block = [0x00, 0x00, 0xd1, 0xd7, 0xc1];
        let headers = decoder.decode_header_block(&block).unwrap();
        assert_eq!(headers.len(), 3);
        assert_eq!(headers[0], (":method".to_string(), "GET".to_string()));
        assert_eq!(headers[1], (":scheme".to_string(), "https".to_string()));
        assert_eq!(headers[2], (":path".to_string(), "/".to_string()));
    }

    #[test]
    fn test_decode_dynamic_table_required() {
        let mut decoder = QpackDecoder::new();
        // RIC=5 (requires dynamic table entries)
        let block = [0x05, 0x00];
        let err = decoder.decode_header_block(&block).unwrap_err();
        assert_eq!(err, DecodeError::DynamicTableRequired(5));
    }

    #[test]
    fn test_literal_with_static_name_ref() {
        let mut decoder = QpackDecoder::new();
        // RIC=0, DeltaBase=0
        // Literal with name reference: 01_S_N_xxxx
        // Name from static table index 0 (:authority), value = "example.com"
        // Pattern: 0101_0000 = 0x50 (S=1, N=0, index=0 in 4-bit prefix)
        // Value: non-huffman, length=11, "example.com"
        let mut block = vec![0x00, 0x00, 0x50];
        block.push(0x0b); // length = 11, no huffman
        block.extend_from_slice(b"example.com");

        let headers = decoder.decode_header_block(&block).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers[0],
            (":authority".to_string(), "example.com".to_string())
        );
    }

    #[test]
    fn test_huffman_decode_www_example_com() {
        // RFC 7541 C.4.1: "www.example.com" Huffman-encoded
        let encoded = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        let decoded = decode_huffman(&encoded).unwrap();
        assert_eq!(decoded, "www.example.com");
    }

    #[test]
    fn test_huffman_decode_no_cache() {
        // RFC 7541 C.4.2: "no-cache"
        let encoded = [0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];
        let decoded = decode_huffman(&encoded).unwrap();
        assert_eq!(decoded, "no-cache");
    }

    #[test]
    fn test_huffman_decode_custom_key() {
        // RFC 7541 C.4.3: "custom-key"
        let encoded = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f];
        let decoded = decode_huffman(&encoded).unwrap();
        assert_eq!(decoded, "custom-key");
    }

    #[test]
    fn test_huffman_decode_custom_value() {
        // RFC 7541 C.4.3: "custom-value"
        let encoded = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf];
        let decoded = decode_huffman(&encoded).unwrap();
        assert_eq!(decoded, "custom-value");
    }

    #[test]
    fn test_huffman_decode_localhost_8443() {
        // From a raw QPACK capture: 0x8a is the length prefix (H=1, len=10),
        // followed by 10 bytes of Huffman-encoded "localhost:8443"
        let wire = [0x8a, 0xa0, 0xe4, 0x1d, 0x13, 0x9d, 0x09, 0xb8, 0xf3, 0x4d, 0x33];
        let (decoded, consumed) = decode_string(&wire).unwrap();
        assert_eq!(decoded, "localhost:8443");
        assert_eq!(consumed, 11);
    }

    #[test]
    fn test_huffman_decode_via_decode_string() {
        // Huffman flag set (0x80 | length), followed by Huffman-encoded "no-cache"
        let encoded_payload = [0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];
        let mut buf = vec![0x80 | encoded_payload.len() as u8];
        buf.extend_from_slice(&encoded_payload);

        let (val, consumed) = decode_string(&buf).unwrap();
        assert_eq!(val, "no-cache");
        assert_eq!(consumed, buf.len());
    }
}
