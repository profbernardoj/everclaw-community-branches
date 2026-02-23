---
tags: [draft, announcement, twitter, memory-upgrade]
created: 2026-02-22
status: draft
---
# Memory Upgrade — X Thread Draft

## Thread

**Tweet 1 (Hook):**
Your AI agent has amnesia.

Every session it wakes up fresh. It writes notes to disk. Then it can't find them.

We just discovered why — and fixed it for everyone.

🧵👇

**Tweet 2 (The Problem):**
OpenClaw's memory_search tool silently returns empty results if you don't have an OpenAI, Google, or Voyage API key.

Since EverClaw users run on Morpheus + Venice (open-source first), we have none of those keys.

Result: 0 files indexed. 0 chunks. Zero recall.

**Tweet 3 (The Discovery):**
We found this while investigating ChromaDB setups with @ThomasBorrel.

Turns out OpenClaw already has everything built in — local embeddings, hybrid search, vector DB.

It just wasn't enabled by default.

**Tweet 4 (The Fix):**
New skill: memory-upgrade

```
bash scripts/diagnose.sh   # Are you broken?
bash scripts/configure.sh  # Fix it
openclaw gateway restart   # Restart
bash scripts/verify.sh     # Confirm
```

60 seconds. Zero API keys. Everything runs locally.

**Tweet 5 (The Numbers):**
Before: 0 files indexed, 0 chunks, empty results

After: 186 files, 968 searchable chunks

Including session transcripts — your past conversations are now searchable.

Hybrid search (BM25 + vector), temporal decay, MMR diversity. All local.

**Tweet 6 (Own Your Memory):**
This is what "own your inference" means in practice.

Your memories. Your hardware. Your embeddings. No data leaves your machine.

The embedding model is 328MB. Runs on your CPU. Zero cost per query.

**Tweet 7 (CTA):**
EverClaw v2026.2.22 — available now.

github.com/EverClaw/everclaw

If you're running OpenClaw without EverClaw: check if your memory_search actually works. We bet it doesn't.

Fix it: github.com/EverClaw/everclaw/tree/main/memory-upgrade
