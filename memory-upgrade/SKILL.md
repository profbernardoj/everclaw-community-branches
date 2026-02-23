---
name: memory-upgrade
description: "Diagnose and fix broken memory search in OpenClaw. Enables local embeddings, hybrid search (BM25+vector), session transcript indexing, MMR diversity, and temporal decay — all running locally with zero API keys. Use when: memory_search returns empty results, agent has poor cross-session recall, user wants to upgrade their memory system, or after a fresh OpenClaw install."
---

# Memory Upgrade

Most OpenClaw installs have **broken memory search** — the `memory_search` tool returns empty results because no embedding provider is configured. OpenClaw auto-detects OpenAI → Google → Voyage keys; if none exist, embeddings stay disabled silently.

This skill fixes it with fully local inference. No API keys. No data leaves the machine.

## Quick Start

```bash
# 1. Diagnose
bash scripts/diagnose.sh

# 2. Fix (patches openclaw.json, restart gateway after)
bash scripts/configure.sh

# 3. Restart gateway
openclaw gateway restart

# 4. Verify (waits for indexing, runs test query)
bash scripts/verify.sh
```

## Optional Enhancements

```bash
# Organize memory files into clean directory structure
bash scripts/organize.sh

# Add YAML frontmatter tags to untagged files
bash scripts/tag.sh
```

## What Gets Enabled

| Feature | Details |
|---------|---------|
| **Local embeddings** | embeddinggemma-300m (~328MB GGUF, auto-downloads) |
| **Hybrid search** | BM25 keyword + vector semantic (70/30 weight) |
| **Session transcripts** | Past conversations become searchable |
| **MMR diversity** | Reduces duplicate/overlapping results (λ=0.7) |
| **Temporal decay** | Recent memories rank higher (30-day half-life) |
| **Embedding cache** | 50k entries, avoids re-embedding unchanged text |
| **File watcher** | Auto-reindexes when memory files change |

## How It Works

- Patches `agents.defaults.memorySearch` in `openclaw.json`
- Uses `node-llama-cpp` (ships with OpenClaw) for local embeddings
- Vector search via `sqlite-vec` (ships with OpenClaw)
- No external dependencies required

## Notes

- First search after restart may be slow (model loads into memory)
- Initial indexing takes 30-120s depending on file count
- Embedding model runs on CPU (ARM/x86), ~768-dim vectors
- Compatible with existing memory files — no migration needed
