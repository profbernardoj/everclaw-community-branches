# Task 6: Model Routing Comparison — Research Brief

**Date:** 2026-02-14
**Status:** Complete
**For:** [REDACTED]

---

## Executive Summary

Model routing is the practice of sending different prompts to different LLMs based on complexity, cost, and capability. Everclaw v0.6 includes a custom 13-dimension weighted router that runs in <1ms locally. This document compares it against the major alternatives to validate the approach and identify improvement opportunities.

---

## The Landscape

### Major Model Routers

| Router | Approach | Latency | Cost | Open Source |
|--------|----------|---------|------|-------------|
| **Everclaw (v0.6)** | 13-dimension weighted keyword classifier | <1ms | Free (local) | Yes |
| **Not Diamond** | ML-trained classifier, custom training | ~50ms | SaaS (API) | Partially |
| **RouteLLM (LMSYS)** | Preference-trained classifiers (4 methods) | ~10-50ms | Free (local) | Yes (MIT) |
| **OpenRouter** | `:nitro` (speed) / `:floor` (cost) shortcuts | N/A | Markup per token | No |
| **Martian** | RouterBench-trained ML model | ~30ms | SaaS | No |
| **Unify AI** | Auto-routing based on benchmark scores | ~20ms | SaaS | No |
| **IBM Router** | BERT-based quality predictor | ~50ms | Research | Partially |
| **LiteLLM** | Rule-based fallback chains | <1ms | Free (local) | Yes |
| **Portkey** | Config-based routing rules | ~5ms | Freemium | No |
| **Pulze AI** | KNN semantic neighbor routing | ~20ms | Self-hosted | Yes (Go) |

### Approach Categories

1. **Rule-based / Keyword** (Everclaw, LiteLLM) — fastest, no external calls, deterministic
2. **ML-trained classifiers** (RouteLLM, Not Diamond, Martian, IBM) — higher accuracy, requires training data, adds latency
3. **Platform routing** (OpenRouter, Unify) — routing as a service, adds cost/latency
4. **KNN / Embedding-based** (Pulze) — semantic similarity to known good examples

---

## Everclaw Router vs Competitors

### Everclaw's Approach (v0.6)

- **13 weighted dimensions:** reasoningMarkers, codePresence, synthesis, technicalTerms, multiStepPatterns, simpleIndicators, agenticTask, creativeMarkers, questionComplexity, tokenCount, constraintCount, domainSpecificity, outputFormat
- **3 tiers:** LIGHT (glm-4.7-flash), STANDARD (kimi-k2.5), HEAVY (claude-opus-4-6)
- **Reasoning override:** 2+ reasoning keywords → force HEAVY
- **Ambiguous default:** → STANDARD (safe middle)
- **Performance:** <1ms, no API calls, no dependencies

### Strengths vs Competition

| Advantage | Everclaw | Typical ML Router |
|-----------|----------|-------------------|
| Latency | <1ms | 20-100ms |
| Dependencies | Zero (pure JS regex) | Python, ML frameworks, maybe API call |
| Cost | $0 | $0-$0.001/query |
| Transparency | Fully deterministic, debuggable | Black-box ML model |
| Offline | ✅ | Often needs API |
| Custom tiers | Maps to owned (Morpheus) vs premium (Venice) | Usually cheap/expensive binary |

### Weaknesses vs Competition

| Weakness | Everclaw | ML Routers |
|----------|----------|------------|
| Accuracy on edge cases | Keyword matching can miss nuance | ML-trained on millions of examples |
| Adaptation | Manual weight tuning | Learns from data |
| Multi-language | English-centric keywords | Can handle any language |
| Quality guarantee | No quality prediction | Can predict output quality |

---

## RouteLLM (LMSYS) — Closest Competitor

RouteLLM is the most relevant open-source comparison. Published by the LMSYS team (creators of Chatbot Arena):

**4 routing methods:**
1. **Similarity-weighted (SW) ranking** — Compares prompt embeddings to Arena preference data
2. **Matrix factorization** — Collaborative filtering on model preference data  
3. **BERT classifier** — Fine-tuned BERT on win/loss preference data
4. **Causal LLM classifier** — Uses an LLM to decide routing

**Key finding:** RouteLLM achieved 2x cost reduction on MT Bench with <5% quality degradation vs always-GPT-4.

**Comparison with Everclaw:**
- RouteLLM is binary (strong vs weak model) — Everclaw has 3 tiers
- RouteLLM requires embedding computation — adds 10-50ms latency
- RouteLLM needs preference training data — Everclaw works out of the box
- RouteLLM is Python-only — Everclaw is pure JavaScript (OpenClaw-native)

**Verdict:** RouteLLM is more accurate on edge cases but impractical for Everclaw's use case (needs to be zero-latency, zero-dependency, JS-native).

---

## Not Diamond — The Premium Option

Not Diamond is the leading commercial router:
- Custom training on your evaluation data
- Routes in less time than streaming a single token
- Claims 40%+ cost savings with equal quality
- Optimizes prompt format per model (right model + right prompt)

**Why it doesn't fit Everclaw:**
- SaaS dependency (defeats decentralization thesis)
- Requires sending prompts to Not Diamond's servers (privacy concern)
- Adds per-query cost
- Centralized — violates Johnston's Law

---

## IBM Router — Academic Excellence

IBM Research published a BERT-based router that:
- Slightly **beat GPT-4** on quality while saving $0.05/query
- Used Martian's RouterBench for evaluation
- Trains on quality prediction rather than classification

**Relevance to Everclaw:** The insight that a router can improve quality (not just reduce cost) is valuable. If a prompt is better suited to Kimi K2.5 than Claude for a specific domain, routing there improves the answer.

---

## Recommendations for Everclaw Router

### Keep What Works
1. **<1ms local execution** — this is a massive advantage; don't trade it for ML accuracy
2. **3-tier system** — maps perfectly to owned (Morpheus) vs premium (Venice) economics
3. **Deterministic + debuggable** — essential for trust in a self-sovereign agent

### Potential Improvements
1. **Add token estimation** — weigh expected output length to better predict cost impact
2. **Feedback loop** — track which tier actually handled each prompt and whether the user was satisfied; use this to tune weights over time
3. **Language detection** — add basic language detection for multi-language support
4. **Domain-specific overrides** — allow users to configure domain keywords that always route to specific tiers (e.g., "solidity" → HEAVY)
5. **Confidence reporting** — already exists; surface it to the user so they can override on low-confidence routes

### Don't Add
- ML classifiers (too heavy for OpenClaw runtime)
- API-dependent routing (defeats offline/decentralized goals)
- Embedding-based similarity (requires embedding model, adds latency)

---

## Cost Impact Analysis

Everclaw's router already delivers significant savings:

| Scenario | Without Router | With Router | Savings |
|----------|---------------|-------------|---------|
| 10 cron jobs/day | All Claude ($30-50 DIEM) | All Kimi K2.5 ($0) | $30-50 DIEM/day |
| 5 sub-agents/day | All Claude ($15-25 DIEM) | Kimi K2.5 ($0) unless complex | $10-20 DIEM/day |
| Main session (10 msgs) | All Claude ($100+ DIEM) | Claude only (unchanged) | $0 |
| **Total daily savings** | | | **$40-70 DIEM/day** |

The router's primary value isn't accuracy — it's **routing background work to owned inference** (Morpheus) while reserving premium models (Venice/Claude) for direct conversation. This is unique to the Everclaw architecture and no other router does it.
