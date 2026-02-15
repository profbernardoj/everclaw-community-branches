#!/usr/bin/env node
/**
 * Everclaw Model Router — 3-tier local classifier
 *
 * Scores a prompt across weighted dimensions and maps to one of three tiers:
 *   LIGHT    → morpheus/glm-4.7-flash  (free, fast — cron, heartbeats, simple Q&A)
 *   STANDARD → morpheus/glm-5           (free, capable — coding, analysis, most tasks)
 *   HEAVY    → morpheus/glm-5           (free, frontier — complex reasoning, strategy)
 *              → venice/claude-opus-4-6  (fallback only — when GLM-5 can't complete)
 *
 * Design: Open-source first. Morpheus handles everything it can.
 * Claude is the escape hatch for tasks that exceed GLM-5's capabilities.
 *
 * Runs in <1ms, zero external calls. Inspired by ClawRouter's 14-dimension
 * weighted scoring (MIT license), adapted for a 3-tier private model stack.
 *
 * Usage:
 *   node router.mjs "Prove that sqrt(2) is irrational"
 *   node router.mjs --json "What time is it?"
 *   echo '{"prompt":"Build a React app","system":"You are helpful"}' | node router.mjs --stdin
 *
 * Programmatic:
 *   import { route, classify } from './router.mjs';
 *   const decision = route("Check the weather in Austin");
 *   // { tier: "LIGHT", model: "morpheus/glm-4.7-flash", confidence: 0.92, ... }
 *
 * @license MIT
 * @see https://github.com/BlockRunAI/ClawRouter (scoring concept)
 */

// ─── Tier → Model Mapping ───────────────────────────────────────────────────

// ─── Open-Source First Design ────────────────────────────────────────────
// Philosophy: Own your inference. Morpheus (GLM-5) handles everything it can.
// Claude is the escape hatch, not the default.
//
//   LIGHT    → glm-4.7-flash  (trivial: greetings, time, simple lookups)
//   STANDARD → glm-5          (most real work: coding, analysis, drafting)
//   HEAVY    → glm-5 first    (complex reasoning — GLM-5 matches Opus 4.5)
//              claude fallback (only if GLM-5 can't complete the task)
//
// When does Claude kick in? Only via the fallback path — if a HEAVY task
// fails or the caller explicitly requests escalation. The router itself
// never defaults to a paid model.

const TIER_MODELS = {
  LIGHT:    { primary: "morpheus/glm-4.7-flash", fallback: "morpheus/glm-5" },
  STANDARD: { primary: "morpheus/glm-5",         fallback: "morpheus/glm-4.7-flash" },
  HEAVY:    { primary: "morpheus/glm-5",          fallback: "venice/claude-opus-4-6" },
};

// ─── Scoring Config ─────────────────────────────────────────────────────────

const CONFIG = {
  tokenThresholds: { simple: 20, complex: 200 },

  // Tier boundaries on the weighted score axis
  // score < lightStandard → LIGHT
  // score < standardHeavy → STANDARD
  // score >= standardHeavy → HEAVY
  tierBoundaries: { lightStandard: -0.02, standardHeavy: 0.12 },

  confidenceSteepness: 8,
  confidenceThreshold: 0.55,

  // ── Keyword lists ──

  reasoningKeywords: [
    "prove", "theorem", "derive", "step by step", "chain of thought",
    "formally", "mathematical", "proof", "logically", "induction",
    "contradiction", "axiom", "lemma", "corollary", "conjecture",
  ],
  codeKeywords: [
    "function", "class", "import", "def", "select", "async", "await",
    "const", "let", "var", "return", "```", "compile", "refactor",
    "debug", "stack trace", "error log", "typescript", "python", "rust",
  ],
  technicalKeywords: [
    "algorithm", "optimize", "architecture", "distributed", "kubernetes",
    "microservice", "database", "infrastructure", "protocol", "encryption",
    "consensus", "smart contract", "solidity", "blockchain", "merkle",
    "cryptograph", "zero-knowledge", "zk-proof",
  ],
  multiStepPatterns: [
    /first.*then/i, /step \d/i, /\d\.\s/, /after that/i,
    /once done/i, /and also/i, /finally/i,
  ],
  creativeKeywords: [
    "story", "poem", "compose", "brainstorm", "creative", "imagine",
    "write a", "narrative", "fiction", "dialogue",
  ],
  synthesisKeywords: [
    "summarize", "summary", "compare", "contrast", "analyze", "evaluate",
    "pros and cons", "trade-off", "tradeoff", "recommendation",
    "draft", "outline", "plan", "strategy", "assess", "review",
    "synthesize", "follow-up", "follow up", "report",
  ],
  // Simple keywords — these are matched with word boundaries to avoid
  // false positives (e.g., "hi" matching inside "architecture")
  simpleKeywords: [
    "what is", "define", "translate", "hello", "yes or no", "capital of",
    "how old", "who is", "when was", "what time", "what day",
    "thanks", "thank you", "good morning", "good night",
    "weather", "temperature", "how are you",
  ],
  // These short words need word-boundary matching
  simpleKeywordsExact: [
    "hi", "ok", "okay", "hey", "yo", "sup", "bye", "thx",
  ],
  agenticKeywords: [
    "read file", "read the file", "look at", "check the", "open the",
    "edit", "modify", "update the", "change the", "write to", "create file",
    "execute", "deploy", "install", "npm", "pip", "compile",
    "fix", "debug", "iterate", "make sure", "verify", "confirm",
    "search for", "find all", "scan", "audit",
  ],
  constraintKeywords: [
    "at most", "at least", "within", "no more than", "maximum",
    "minimum", "limit", "budget", "o(", "complexity",
  ],
  domainKeywords: [
    "quantum", "fpga", "vlsi", "risc-v", "asic", "photonics",
    "genomics", "proteomics", "topological", "homomorphic",
    "lattice-based", "elliptic curve",
  ],
  outputFormatKeywords: [
    "json", "yaml", "xml", "table", "csv", "markdown", "schema",
    "format as", "structured", "spreadsheet",
  ],

  // Dimension weights — must sum to ~1.0
  weights: {
    tokenCount:       0.04,
    codePresence:     0.14,
    reasoningMarkers: 0.20,
    technicalTerms:   0.10,
    multiStepPatterns:0.10,
    creativeMarkers:  0.04,
    simpleIndicators: 0.06,
    agenticTask:      0.06,
    constraintCount:  0.04,
    domainSpecificity:0.04,
    outputFormat:     0.03,
    questionComplexity:0.04,
    synthesis:        0.11,
  },
};

// ─── Dimension Scorers ──────────────────────────────────────────────────────

function scoreTokenCount(tokens) {
  if (tokens < CONFIG.tokenThresholds.simple)
    return { name: "tokenCount", score: -1.0, signal: `short (${tokens} tok)` };
  if (tokens > CONFIG.tokenThresholds.complex)
    return { name: "tokenCount", score: 1.0, signal: `long (${tokens} tok)` };
  return { name: "tokenCount", score: 0, signal: null };
}

function scoreKeywords(text, keywords, name, label, thresholds, scores) {
  const matches = keywords.filter(kw => text.includes(kw.toLowerCase()));
  if (matches.length >= thresholds.high)
    return { name, score: scores.high, signal: `${label} (${matches.slice(0,3).join(", ")})` };
  if (matches.length >= thresholds.low)
    return { name, score: scores.low, signal: `${label} (${matches.slice(0,3).join(", ")})` };
  return { name, score: scores.none, signal: null };
}

function scoreMultiStep(text) {
  const hits = CONFIG.multiStepPatterns.filter(p => p.test(text));
  if (hits.length >= 2) return { name: "multiStepPatterns", score: 0.7, signal: "multi-step (strong)" };
  if (hits.length === 1) return { name: "multiStepPatterns", score: 0.4, signal: "multi-step" };
  return { name: "multiStepPatterns", score: 0, signal: null };
}

function scoreSimple(text) {
  const phraseMatches = CONFIG.simpleKeywords.filter(kw => text.includes(kw.toLowerCase()));
  const wordMatches = CONFIG.simpleKeywordsExact.filter(kw => {
    const re = new RegExp(`\\b${kw}\\b`, "i");
    return re.test(text);
  });
  const total = phraseMatches.length + wordMatches.length;
  const examples = [...phraseMatches, ...wordMatches].slice(0, 3);
  if (total >= 2) return { name: "simpleIndicators", score: -1.0, signal: `simple (${examples.join(", ")})` };
  if (total >= 1) return { name: "simpleIndicators", score: -0.8, signal: `simple (${examples.join(", ")})` };
  return { name: "simpleIndicators", score: 0, signal: null };
}

function scoreQuestionComplexity(prompt) {
  const count = (prompt.match(/\?/g) || []).length;
  if (count > 3) return { name: "questionComplexity", score: 0.6, signal: `${count} questions` };
  if (count > 1) return { name: "questionComplexity", score: 0.3, signal: `${count} questions` };
  return { name: "questionComplexity", score: 0, signal: null };
}

// ─── Sigmoid Confidence ─────────────────────────────────────────────────────

function sigmoid(distance, steepness) {
  return 1 / (1 + Math.exp(-steepness * distance));
}

// ─── Main Classifier ────────────────────────────────────────────────────────

export function classify(prompt, systemPrompt) {
  const text = `${systemPrompt ?? ""} ${prompt}`.toLowerCase();
  const userText = prompt.toLowerCase();
  const estimatedTokens = Math.ceil(text.length / 4);

  const dimensions = [
    scoreTokenCount(estimatedTokens),
    scoreKeywords(text, CONFIG.codeKeywords, "codePresence", "code",
      { low: 1, high: 3 }, { none: 0, low: 0.5, high: 1.0 }),
    // Reasoning uses USER text only (system prompts often contain "step by step")
    scoreKeywords(userText, CONFIG.reasoningKeywords, "reasoningMarkers", "reasoning",
      { low: 1, high: 2 }, { none: 0, low: 0.6, high: 1.0 }),
    scoreKeywords(text, CONFIG.technicalKeywords, "technicalTerms", "technical",
      { low: 2, high: 4 }, { none: 0, low: 0.5, high: 1.0 }),
    scoreKeywords(text, CONFIG.creativeKeywords, "creativeMarkers", "creative",
      { low: 1, high: 2 }, { none: 0, low: 0.4, high: 0.6 }),
    // Simple indicators score NEGATIVE (push toward LIGHT)
    scoreSimple(text),
    scoreMultiStep(text),
    scoreQuestionComplexity(prompt),
    scoreKeywords(text, CONFIG.agenticKeywords, "agenticTask", "agentic",
      { low: 2, high: 4 }, { none: 0, low: 0.3, high: 0.6 }),
    scoreKeywords(text, CONFIG.constraintKeywords, "constraintCount", "constraints",
      { low: 1, high: 3 }, { none: 0, low: 0.3, high: 0.6 }),
    scoreKeywords(text, CONFIG.domainKeywords, "domainSpecificity", "domain",
      { low: 1, high: 2 }, { none: 0, low: 0.5, high: 0.8 }),
    scoreKeywords(text, CONFIG.outputFormatKeywords, "outputFormat", "format",
      { low: 1, high: 2 }, { none: 0, low: 0.3, high: 0.5 }),
    scoreKeywords(text, CONFIG.synthesisKeywords, "synthesis", "synthesis",
      { low: 1, high: 2 }, { none: 0, low: 0.5, high: 0.8 }),
  ];

  const signals = dimensions.filter(d => d.signal).map(d => d.signal);

  // Weighted sum
  let weightedScore = 0;
  for (const d of dimensions) {
    const w = CONFIG.weights[d.name] ?? 0;
    weightedScore += d.score * w;
  }

  // Reasoning override: 2+ reasoning keywords in user prompt → force HEAVY
  const reasoningHits = CONFIG.reasoningKeywords.filter(kw => userText.includes(kw));
  if (reasoningHits.length >= 2) {
    return {
      score: weightedScore,
      tier: "HEAVY",
      confidence: Math.max(sigmoid(Math.max(weightedScore, 0.3), CONFIG.confidenceSteepness), 0.88),
      signals,
      reasoning: `reasoning override (${reasoningHits.slice(0,3).join(", ")})`,
    };
  }

  // Map score to tier
  const { lightStandard, standardHeavy } = CONFIG.tierBoundaries;
  let tier, distFromBoundary;

  if (weightedScore < lightStandard) {
    tier = "LIGHT";
    distFromBoundary = lightStandard - weightedScore;
  } else if (weightedScore < standardHeavy) {
    tier = "STANDARD";
    distFromBoundary = Math.min(weightedScore - lightStandard, standardHeavy - weightedScore);
  } else {
    tier = "HEAVY";
    distFromBoundary = weightedScore - standardHeavy;
  }

  const confidence = sigmoid(distFromBoundary, CONFIG.confidenceSteepness);

  // Low confidence → default to STANDARD (safe middle ground)
  if (confidence < CONFIG.confidenceThreshold) {
    return {
      score: weightedScore,
      tier: "STANDARD",
      confidence,
      signals,
      reasoning: `ambiguous (score=${weightedScore.toFixed(3)}) → default STANDARD`,
    };
  }

  return {
    score: weightedScore,
    tier,
    confidence,
    signals,
    reasoning: `score=${weightedScore.toFixed(3)} → ${tier}`,
  };
}

// ─── Route (classifier + model selection) ───────────────────────────────────

export function route(prompt, systemPrompt) {
  const result = classify(prompt, systemPrompt);
  const tierConfig = TIER_MODELS[result.tier];
  return {
    ...result,
    model: tierConfig.primary,
    fallback: tierConfig.fallback,
  };
}

// ─── CLI ────────────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);
  const jsonFlag = args.includes("--json");
  const stdinFlag = args.includes("--stdin");
  const cleanArgs = args.filter(a => !a.startsWith("--"));

  let prompt, system;

  if (stdinFlag) {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    const input = JSON.parse(Buffer.concat(chunks).toString());
    prompt = input.prompt ?? input.message ?? "";
    system = input.system ?? input.systemPrompt ?? undefined;
  } else {
    prompt = cleanArgs.join(" ");
  }

  if (!prompt) {
    console.error("Usage: node router.mjs [--json] [--stdin] <prompt>");
    console.error('  node router.mjs "What is 2+2?"');
    console.error('  node router.mjs --json "Build a distributed database"');
    console.error('  echo \'{"prompt":"hello"}\' | node router.mjs --stdin');
    process.exit(1);
  }

  const decision = route(prompt, system);

  if (jsonFlag) {
    console.log(JSON.stringify(decision, null, 2));
  } else {
    const bar = "─".repeat(50);
    console.log(bar);
    console.log(`  Tier:       ${decision.tier}`);
    console.log(`  Model:      ${decision.model}`);
    console.log(`  Fallback:   ${decision.fallback}`);
    console.log(`  Confidence: ${(decision.confidence * 100).toFixed(1)}%`);
    console.log(`  Score:      ${decision.score.toFixed(3)}`);
    console.log(`  Reasoning:  ${decision.reasoning}`);
    if (decision.signals.length > 0)
      console.log(`  Signals:    ${decision.signals.join(" | ")}`);
    console.log(bar);
  }
}

// Run CLI if invoked directly
const isMain = process.argv[1]?.endsWith("router.mjs");
if (isMain) main().catch(e => { console.error(e); process.exit(1); });
