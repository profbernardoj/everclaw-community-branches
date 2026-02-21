//! morpheus-status — WASI component that checks EverClaw proxy health.
//!
//! This is a WASI Preview 2 component that uses wasi:http/outgoing-handler
//! to make an HTTP request to the local EverClaw proxy health endpoint.
//!
//! Build: cargo component build --release
//! Output: target/wasm32-wasip2/release/morpheus_status.wasm

// Generated bindings from the WIT world
mod bindings {
    wit_bindgen_rt::generate!({
        world: "morpheus-status",
        path: "wit",
    });
}

use bindings::exports::component::morpheus_status::check::Guest;

/// The proxy health endpoint
const PROXY_URL: &str = "http://127.0.0.1:8083/health";

struct Component;

impl Guest for Component {
    /// Check the EverClaw proxy health and return a human-readable status string.
    fn status() -> String {
        match fetch_health() {
            Ok(body) => format!("✅ Morpheus proxy healthy\n{}", body),
            Err(e) => format!("❌ Morpheus proxy unreachable: {}", e),
        }
    }
}

/// Make an outbound HTTP GET to the proxy health endpoint using wasi:http.
fn fetch_health() -> Result<String, String> {
    use bindings::wasi::http::outgoing_handler;
    use bindings::wasi::http::types::*;

    // Create the outgoing request
    let headers = Fields::new();
    let request = OutgoingRequest::new(headers);
    request.set_method(&Method::Get).map_err(|_| "failed to set method")?;
    request.set_scheme(Some(&Scheme::Http)).map_err(|_| "failed to set scheme")?;
    request.set_authority(Some("127.0.0.1:8083")).map_err(|_| "failed to set authority")?;
    request.set_path_with_query(Some("/health")).map_err(|_| "failed to set path")?;

    // Send the request (no request body needed for GET)
    let future_response = outgoing_handler::handle(request, None)
        .map_err(|e| format!("outgoing request failed: {:?}", e))?;

    // Block on the response (WASI pollable)
    let response_option = future_response.get();
    let response = match response_option {
        Some(Ok(Ok(resp))) => resp,
        Some(Ok(Err(e))) => return Err(format!("HTTP error: {:?}", e)),
        Some(Err(_)) => return Err("response already consumed".to_string()),
        None => {
            // Poll until ready
            let pollable = future_response.subscribe();
            pollable.block();
            match future_response.get() {
                Some(Ok(Ok(resp))) => resp,
                Some(Ok(Err(e))) => return Err(format!("HTTP error: {:?}", e)),
                _ => return Err("unexpected poll result".to_string()),
            }
        }
    };

    let status = response.status();
    if status != 200 {
        return Err(format!("HTTP {}", status));
    }

    // Read the response body
    let body = response.consume().map_err(|_| "failed to consume body")?;
    let stream = body.stream().map_err(|_| "failed to get body stream")?;

    let mut buf = Vec::new();
    loop {
        match stream.read(4096) {
            Ok(chunk) => {
                if chunk.is_empty() {
                    break;
                }
                buf.extend_from_slice(&chunk);
            }
            Err(_) => break,
        }
    }

    // Cleanup
    drop(stream);
    IncomingBody::finish(body);

    String::from_utf8(buf).map_err(|_| "response not valid UTF-8".to_string())
}

bindings::export!(Component with_types_in bindings);
