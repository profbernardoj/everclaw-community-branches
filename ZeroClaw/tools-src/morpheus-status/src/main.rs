//! morpheus-status — Native Rust tool for ZeroClaw
//!
//! Checks EverClaw proxy health. Uses `ureq` (blocking HTTP, no async runtime).
//! Produces a small binary (~1.5 MB release, ~2 MB with musl).
//!
//! Build: cargo build --release
//! Run:   ./target/release/morpheus-status

const PROXY_HEALTH_URL: &str = "http://127.0.0.1:8083/health";

fn main() {
    match check_health() {
        Ok(body) => {
            println!("✅ Morpheus proxy healthy");
            println!("{}", body);
        }
        Err(e) => {
            eprintln!("❌ Morpheus proxy: {}", e);
            eprintln!("   Start it: cd ~/.everclaw && bash scripts/start.sh");
            std::process::exit(1);
        }
    }
}

fn check_health() -> Result<String, String> {
    let response = ureq::get(PROXY_HEALTH_URL)
        .timeout(std::time::Duration::from_secs(5))
        .call()
        .map_err(|e| match e {
            ureq::Error::Transport(t) => format!("connection failed: {}", t),
            ureq::Error::Status(code, _) => format!("HTTP {}", code),
        })?;

    let status = response.status();
    if status != 200 {
        return Err(format!("HTTP {}", status));
    }

    response
        .into_string()
        .map_err(|e| format!("failed to read response: {}", e))
}
