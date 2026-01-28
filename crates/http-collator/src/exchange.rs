//! HTTP exchange (request/response pair)

use crate::connection::Protocol;
use crate::h1::{HttpRequest, HttpResponse};

/// A complete request/response exchange
#[derive(Debug)]
pub struct Exchange {
    pub request: HttpRequest,
    pub response: HttpResponse,
    pub latency_ns: u64,
    pub protocol: Protocol,
    pub process_id: u32,
    /// Remote port, None if unavailable (e.g., SSL without socket fd)
    pub remote_port: Option<u16>,
    /// Stream ID for HTTP/2 (None for HTTP/1)
    pub stream_id: Option<u32>,
}

impl std::fmt::Display for Exchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let proto_str = match self.protocol {
            Protocol::Http1 => "HTTP/1.1",
            Protocol::Http2 => "HTTP/2",
            Protocol::Unknown => "Unknown",
        };
        let latency_ms = self.latency_ns as f64 / 1_000_000.0;
        let port_str = self
            .remote_port
            .map_or("unavailable".to_string(), |p| p.to_string());

        writeln!(
            f,
            "=== {} Exchange (PID: {}, Port: {}) ===",
            proto_str, self.process_id, port_str
        )?;
        writeln!(f, "Latency: {:.2}ms", latency_ms)?;
        writeln!(f)?;
        writeln!(f, "--- Request ---")?;
        writeln!(f, "{} {}", self.request.method, self.request.uri)?;
        for (key, value) in &self.request.headers {
            writeln!(f, "{}: {}", key, value.to_str().unwrap_or("<binary>"))?;
        }
        if !self.request.body.is_empty() {
            writeln!(f)?;
            writeln!(f, "{}", String::from_utf8_lossy(&self.request.body))?;
        }
        writeln!(f)?;
        writeln!(f, "--- Response ---")?;
        let reason = self.response.status.canonical_reason().unwrap_or("");
        writeln!(f, "{} {}", self.response.status.as_u16(), reason)?;
        for (key, value) in &self.response.headers {
            writeln!(f, "{}: {}", key, value.to_str().unwrap_or("<binary>"))?;
        }
        if !self.response.body.is_empty() {
            writeln!(f)?;
            writeln!(f, "{}", String::from_utf8_lossy(&self.response.body))?;
        }
        Ok(())
    }
}
