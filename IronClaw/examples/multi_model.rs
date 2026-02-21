//! Multi-model agent: routes different tasks to different Morpheus models.
//!
//! Uses GLM-5 for complex reasoning and GLM-4.7-flash for quick lookups.

use rig::providers::openai;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = openai::Client::from_url(
        "http://127.0.0.1:8083/v1",
        "morpheus-local",
    );

    // Heavy model for complex tasks
    let analyst = client
        .agent("glm-5")
        .preamble("You are an expert analyst. Provide thorough, detailed analysis.")
        .build();

    // Fast model for simple tasks
    let assistant = client
        .agent("glm-4.7-flash")
        .preamble("You are a quick assistant. Be concise.")
        .build();

    // Route based on task complexity
    println!("=== Quick question (GLM-4.7-flash) ===");
    let quick = assistant.prompt("What day is it?").await?;
    println!("{}\n", quick);

    println!("=== Deep analysis (GLM-5) ===");
    let deep = analyst
        .prompt("Analyze the trade-offs between proof-of-work and proof-of-stake consensus mechanisms.")
        .await?;
    println!("{}", deep);

    Ok(())
}
