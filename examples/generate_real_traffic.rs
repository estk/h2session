//! Real HTTP/2 Traffic Generator
//!
//! This binary captures actual HTTP/2 traffic from a real h2 client/server
//! interaction and saves it as a test fixture.
//!
//! Run with: cargo run --bin generate_real_traffic

use bytes::Bytes;
use h2::client;
use h2::server;
use http::{Request, Response, StatusCode};
use serde::Serialize;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Captured traffic data
#[derive(Serialize)]
struct CapturedTraffic {
    message_count: usize,
    streams: Vec<StreamInfo>,
}

#[derive(Serialize)]
struct StreamInfo {
    stream_id: u32,
    method: Option<String>,
    path: Option<String>,
    status: Option<u16>,
    body_size: usize,
}

/// Wrapper around TcpStream that captures all bytes
struct CapturingStream {
    inner: TcpStream,
    captured: Arc<Mutex<Vec<u8>>>,
}

impl CapturingStream {
    fn new(inner: TcpStream, captured: Arc<Mutex<Vec<u8>>>) -> Self {
        Self { inner, captured }
    }
}

impl tokio::io::AsyncRead for CapturingStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);

        if let std::task::Poll::Ready(Ok(())) = &result {
            let after = buf.filled().len();
            if after > before {
                let new_data = &buf.filled()[before..after];
                // Can't block here, so we spawn a task
                let captured = self.captured.clone();
                let data = new_data.to_vec();
                tokio::spawn(async move {
                    captured.lock().await.extend(data);
                });
            }
        }

        result
    }
}

impl tokio::io::AsyncWrite for CapturingStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // Capture outgoing data too
        let captured = self.captured.clone();
        let data = buf.to_vec();
        tokio::spawn(async move {
            captured.lock().await.extend(data);
        });

        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Start an HTTP/2 server that responds with chunked bodies
async fn run_server(listener: TcpListener) -> Result<(), Box<dyn Error + Send + Sync>> {
    loop {
        let (socket, _) = listener.accept().await?;

        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket).await {
                eprintln!("Server error: {}", e);
            }
        });
    }
}

async fn handle_connection(socket: TcpStream) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut connection = server::handshake(socket).await?;

    while let Some(result) = connection.accept().await {
        let (request, mut respond) = result?;
        let path = request.uri().path().to_string();

        tokio::spawn(async move {
            // Create response based on path
            let body_size = match path.as_str() {
                "/small" => 100,
                "/medium" => 1000,
                "/large" => 10000,
                _ => 500,
            };

            let response = Response::builder()
                .status(StatusCode::OK)
                .body(())
                .unwrap();

            let mut send = respond.send_response(response, false).unwrap();

            // Send body in chunks
            let chunk_size = 100;
            let mut remaining = body_size;

            while remaining > 0 {
                let size = std::cmp::min(chunk_size, remaining);
                let chunk = vec![b'X'; size];
                send.send_data(Bytes::from(chunk), remaining <= chunk_size)
                    .unwrap();
                remaining = remaining.saturating_sub(chunk_size);
            }
        });
    }

    Ok(())
}

/// Run HTTP/2 client sending concurrent requests
async fn run_client(
    addr: SocketAddr,
    captured: Arc<Mutex<Vec<u8>>>,
) -> Result<Vec<StreamInfo>, Box<dyn Error + Send + Sync>> {
    let tcp = TcpStream::connect(addr).await?;
    let stream = CapturingStream::new(tcp, captured);

    let (client, h2) = client::handshake(stream).await?;

    // Spawn connection driver
    tokio::spawn(async move {
        if let Err(e) = h2.await {
            eprintln!("Connection error: {}", e);
        }
    });

    let mut client = client.ready().await?;

    // Send 5 concurrent requests
    let paths = vec!["/small", "/medium", "/large", "/path1", "/path2"];
    let mut handles = Vec::new();

    for path in &paths {
        let request = Request::builder()
            .method("GET")
            .uri(format!("http://localhost{}", path))
            .body(())
            .unwrap();

        let (response, _) = client.send_request(request, true)?;
        handles.push((path.to_string(), response));
        client = client.ready().await?;
    }

    // Collect responses
    let mut streams = Vec::new();
    for (path, response_future) in handles {
        let response = response_future.await?;
        let status = response.status().as_u16();
        let mut body = response.into_body();

        let mut body_data = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk?;
            body_data.extend_from_slice(&chunk);
            let _ = body.flow_control().release_capacity(chunk.len());
        }

        streams.push(StreamInfo {
            stream_id: 0, // Will be determined by the library
            method: Some("GET".to_string()),
            path: Some(path),
            status: Some(status),
            body_size: body_data.len(),
        });
    }

    Ok(streams)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    println!("HTTP/2 Real Traffic Generator");
    println!("==============================");

    // Bind server to random port
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    println!("Server listening on {}", addr);

    // Start server in background
    tokio::spawn(run_server(listener));

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Capture traffic
    let captured = Arc::new(Mutex::new(Vec::new()));

    println!("Sending {} concurrent requests...", 5);
    let streams = run_client(addr, captured.clone()).await?;

    // Give time for all data to be captured
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Get captured data
    let traffic_data = captured.lock().await.clone();
    println!("Captured {} bytes of HTTP/2 traffic", traffic_data.len());

    // Save raw traffic
    let fixture_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    std::fs::create_dir_all(fixture_dir)?;

    let bin_path = format!("{}/real_traffic.bin", fixture_dir);
    let mut bin_file = File::create(&bin_path)?;
    bin_file.write_all(&traffic_data)?;
    println!("Saved raw traffic to {}", bin_path);

    // Save expected results
    let expected = CapturedTraffic {
        message_count: streams.len(),
        streams,
    };

    let json_path = format!("{}/real_traffic_expected.json", fixture_dir);
    let json = serde_json::to_string_pretty(&expected)?;
    let mut json_file = File::create(&json_path)?;
    json_file.write_all(json.as_bytes())?;
    println!("Saved expected results to {}", json_path);

    println!("\nDone! Run tests with: cargo test --test integration_test");

    Ok(())
}
