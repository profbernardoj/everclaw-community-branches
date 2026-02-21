# morpheus-status — WASI Component for IronClaw

A WASI Preview 2 component that checks EverClaw proxy health from inside IronClaw's sandbox.

## Prerequisites

```bash
# Install Rust + WASI target
rustup target add wasm32-wasip2

# Install cargo-component (builds WASI components)
cargo install cargo-component
```

## Build

```bash
cargo component build --release
```

Output: `target/wasm32-wasip2/release/morpheus_status.wasm`

## Install in IronClaw

Copy the `.wasm` file to your IronClaw tools directory:

```bash
cp target/wasm32-wasip2/release/morpheus_status.wasm ~/.ironclaw/tools/
```

Or register via IronClaw CLI (if supported):

```bash
ironclaw tool add morpheus-status --wasm ./target/wasm32-wasip2/release/morpheus_status.wasm
```

## How It Works

The component uses `wasi:http/outgoing-handler` to make an HTTP GET request to `http://127.0.0.1:8083/health`. This is the standard WASI HTTP interface — no `reqwest`, no `tokio`, no OS threads.

The IronClaw runtime must grant the component network access to `127.0.0.1:8083` for it to work. Most WASI runtimes support this via capability flags.

## Alternative: Shell Script

If you don't need WASI sandboxing, a simpler approach:

```bash
#!/bin/bash
curl -sf http://127.0.0.1:8083/health && echo "✅ Proxy healthy" || echo "❌ Proxy down"
```

## License

MIT
