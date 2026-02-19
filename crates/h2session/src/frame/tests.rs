use super::*;

#[test]
fn test_is_http2_preface() {
    assert!(is_http2_preface(CONNECTION_PREFACE));
    assert!(is_http2_preface(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nextra"));
    assert!(!is_http2_preface(b"GET / HTTP/1.1\r\n"));
    assert!(!is_http2_preface(b"PRI"));
}

#[test]
fn test_looks_like_http2_frame() {
    // Valid SETTINGS frame header (type 4, length 0, stream 0)
    let settings_frame = [0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert!(looks_like_http2_frame(&settings_frame));

    // Invalid: too short
    assert!(!looks_like_http2_frame(&[0x00, 0x00]));

    // Invalid: unknown frame type (> 9)
    let bad_type = [0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert!(!looks_like_http2_frame(&bad_type));
}

#[test]
fn test_parse_frame_header() {
    // HEADERS frame, length 10, flags 0x04, stream 1
    let data = [0x00, 0x00, 0x0A, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01];
    let header = parse_frame_header(&data).unwrap();
    assert_eq!(header.length, 10);
    assert_eq!(header.frame_type, FRAME_TYPE_HEADERS);
    assert_eq!(header.flags, 0x04);
    assert_eq!(header.stream_id, StreamId(1));
}

#[test]
fn test_parse_frame_header_too_small() {
    let data = [0x00, 0x00, 0x0A];
    assert!(matches!(
        parse_frame_header(&data),
        Err(ref e) if matches!(e.kind, ParseErrorKind::Http2BufferTooSmall)
    ));
}
