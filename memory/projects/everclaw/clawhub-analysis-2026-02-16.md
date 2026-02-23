---
tags: [project, everclaw]
status: active
---
# ClawHub Skills Analysis - Revealed Preferences
**Date:** 2026-02-16
**Purpose:** Prep for conversation with Kyle (Morpheus API Gateway developer)

---

## Overview

- **Total Skills:** 3,286
- **Total Downloads:** 1.5M+
- **Community Stars:** 2,999

---

## Top Skills by Downloads (Ranked)

| Rank | Skill | Category | Downloads | Stars |
|------|-------|----------|-----------|-------|
| 1 | Capability Evolver | AI/ML | 35,581 | 33 |
| 2 | Wacli | Dev/Utility | 16,415 | 37 |
| 3 | ByteRover | Utility/Dev | 16,004 | 36 |
| 4 | self-improving-agent | AI/ML | 15,962 | 132 ⭐ |
| 5 | ATXP | Utility | 14,453 | 4 |
| 6 | Gog | Development | 14,313 | 48 |
| 7 | Agent Browser | Web | 11,836 | 43 |
| 8 | Summarize | Productivity | 10,956 | 28 |
| 9 | Github | Development | 10,611 | 15 |
| 10 | Sonoscli | Media | 10,304 | 6 |
| 11 | Weather | Location | 9,002 | 13 |
| 12 | Humanize AI text | Productivity | 8,771 | 20 |
| 13 | Tavily Web Search | Web/Dev | 8,142 | 10 |
| 14 | Free Ride - Unlimited AI | AI/ML | 7,927 | 1 |
| 15 | Bird | Utility | 7,767 | 27 |
| 16 | Find Skills | Utility | 7,077 | 15 |
| 17 | Proactive Agent | AI/ML | 7,010 | 49 ⭐ |
| 18 | Auto-Updater Skill | AI/ML | 6,601 | 31 |
| 19 | Obsidian | Productivity | 5,791 | 12 |
| 20 | Nano Banana Pro | Productivity | 5,704 | 20 |

---

## Category Distribution (% of Skills)

| Category | Skills | % Share |
|----------|--------|---------|
| AI/ML | 1,588 | 48.3% |
| Utility | 1,520 | 46.3% |
| Development | 976 | 29.7% |
| Productivity | 822 | 25.0% |
| Web | 637 | 19.4% |
| Science | 598 | 18.2% |
| Media | 365 | 11.1% |
| Social | 364 | 11.1% |
| Finance | 311 | 9.5% |
| Location | 153 | 4.7% |
| Business | 151 | 4.6% |

---

## Revealed Preferences: What Users Actually Want

### 1. 🤖 AI/ML Self-Improvement is #1 Desire
**Top 2 skills by downloads are AI/ML: Capability Evolver (35K) + self-improving-agent (16K)**

Users want agents that can:
- Evolve their own capabilities
- Self-improve autonomously
- Extend their own functionality

**Inference Implication:** These skills likely make heavy API calls to iterate on prompts, test capabilities, and run evaluation loops. This means **high token volume** for reasoning and code generation.

### 2. 🛠️ Tooling & Automation is Strong
- **Wacli (16K)** + **ByteRover (16K)** + **ATXP (14K)** = 46K+ downloads
- Users want agents to execute commands, manage files, automate workflows

**Inference Implication:** Code generation, command synthesis, file operations → strong demand for **fast, cheap inference** for utility tasks.

### 3. 🌐 Web Automation is Critical
- **Agent Browser (11K)** + **Tavily Web Search (8K)** = 20K+ downloads
- Web scraping, search, browsing automation

**Inference Implication:** Web automation requires models good at:
- Understanding page structure
- Synthesizing actions
- Parsing results
→ Mix of **fast cheap models for simple extraction** + **smart models for complex reasoning**

### 4. 📊 Summarization & Content Processing
- **Summarize (11K)** + **Humanize AI text (9K)** = 20K+ downloads
- Users process a lot of content

**Inference Implication:** High volume of **long-context requests**. Users want to compress articles, transcriptions, documents. Models with large context windows and fast processing are key.

---

## Inference Demand Profile (for Morpheus Gateway)

Based on revealed preferences:

| Use Case | Demand Level | Model Requirements |
|----------|--------------|-------------------|
| Self-improvement loops | Very High | Reasoning models, extended thinking |
| Code generation | High | Smart code models, fast response |
| Web automation | High | Mixed (smart for planning, fast for extraction) |
| Summarization | High | Large context, fast processing |
| Utility tasks | Medium | Fast, cheap models |
| Content humanization | Medium | Style transfer, creative models |

### Key Insight for Kyle

**The top skill is "Capability Evolver"** — users want agents that can autonomously improve themselves. This implies:
1. Recursive inference (agents calling inference to improve inference)
2. High token volume for experimentation/iteration
3. Need for both smart reasoning models AND cheap fast models

The **self-improving-agent** skill has the **highest star count (132)** — strong community endorsement that this is the direction agents should go.

---

## Security Note (Context)

ClawHub had a security incident ("ClawHavoc", Feb 2026):
- 341 malicious skills discovered (data theft)
- 283 skills with critical flaws (7.1%)
- Registry reduced from 5,705 → 3,286 skills
- VirusTotal partnership added for scanning
- Auto-hide after 3 reports

This validates the need for **skillguard** and security scanning when installing skills.