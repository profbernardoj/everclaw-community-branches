//! Basic IronClaw agent using EverClaw Morpheus inference.
//!
//! This example shows how to connect a Rig-based agent to the local
//! EverClaw proxy for decentralized inference.
//!
//! Add to your Cargo.toml:
//!   rig-core = "0.6"
//!   tokio = { version = "1", features = ["full"] }

use rig::providers::openai;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to the local EverClaw proxy (OpenAI-compatible API)
    let client = openai::Client::from_url(
        "http://127.0.0.1:8083/v1",
        "morpheus-local", // auth token (proxy validates this)
    );

    // Build an agent using GLM-5 (default heavy model via Morpheus)
    let agent = client
        .agent("glm-5")
        .preamble("You are a helpful assistant powered by decentralized inference.")
        .build();

    // Chat with the agent
    let response = agent.prompt("What is the Morpheus AI network?").await?;
    println!("Agent: {}", response);

    Ok(())
}
