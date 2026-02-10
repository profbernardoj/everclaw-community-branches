#!/usr/bin/env node
/**
 * Morpheus → OpenAI-compatible proxy for OpenClaw
 *
 * Translates standard OpenAI /v1/chat/completions requests into
 * Morpheus proxy-router calls with proper Basic auth + session/model headers.
 *
 * Features:
 * - Auto-opens sessions on demand (lazy)
 * - Auto-renews sessions before expiry
 * - Maps model names to blockchain model IDs
 * - Health endpoint at GET /health
 * - Models endpoint at GET /v1/models (for OpenClaw discovery)
 */

import http from "node:http";
import fs from "node:fs";
import path from "node:path";

// --- Configuration ---
const PROXY_PORT = parseInt(process.env.MORPHEUS_PROXY_PORT || "8083", 10);
const ROUTER_URL = process.env.MORPHEUS_ROUTER_URL || "http://localhost:8082";
const COOKIE_PATH = process.env.MORPHEUS_COOKIE_PATH || path.join(process.env.HOME, "morpheus/.cookie");
const SESSION_DURATION = parseInt(process.env.MORPHEUS_SESSION_DURATION || "604800", 10); // 7 days default
const RENEW_BEFORE_SEC = parseInt(process.env.MORPHEUS_RENEW_BEFORE || "3600", 10); // renew 1 hour before expiry
const PROXY_API_KEY = process.env.MORPHEUS_PROXY_API_KEY || "morpheus-local"; // bearer token OpenClaw sends

// --- Model ID map (blockchain model IDs) ---
const MODEL_MAP = {
  "kimi-k2.5":         "0xbb9e920d94ad3fa2861e1e209d0a969dbe9e1af1cf1ad95c49f76d7b63d32d93",
  "kimi-k2.5:web":     "0xb487ee62516981f533d9164a0a3dcca836b06144506ad47a5c024a7a2a33fc58",
  "kimi-k2-thinking":  "0xc40b0a1ea1b20e042449ae44ffee8e87f3b8ba3d0be3ea61b86e6a89ba1a44e3",
  "glm-4.7-flash":     "0xfdc54de0b7f3e3525b4173f49e3819aebf1ed31e06d96be4eefaca04f2fcaeff",
  "glm-4.7":           "0xed0a2bc2a6e28cc87a9b55bc24b61f089f3c86b15d94e5776bc0312e0b4df34b",
  "qwen3-235b":        "0x2a71d1dfad6a7ead6e0c7f3d87d9a3c64e8bfa53f9a62fb71b83e7f49e3a6c0b",
  "llama-3.3-70b":     "0xc753061a5d2640decfbbc1d1d35744e6805015d30d32872f814a93784c627fc3",
  "gpt-oss-120b":      "0x2e7228fe07523d84307838aa617141a5e47af0e00b4eaeab1522bc71985ffd11",
};

// --- State ---
const sessions = new Map(); // modelId -> { sessionId, expiresAt }

// --- Helpers ---

function getBasicAuth() {
  try {
    const cookie = fs.readFileSync(COOKIE_PATH, "utf-8").trim();
    return "Basic " + Buffer.from(cookie).toString("base64");
  } catch (e) {
    console.error(`[morpheus-proxy] Failed to read cookie file: ${e.message}`);
    return null;
  }
}

function routerFetch(method, urlPath, body = null, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlPath, ROUTER_URL);
    const headers = {
      "Authorization": getBasicAuth(),
      ...extraHeaders,
    };
    if (body) headers["Content-Type"] = "application/json";

    const req = http.request(url, { method, headers }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const raw = Buffer.concat(chunks);
        resolve({ status: res.statusCode, headers: res.headers, body: raw });
      });
    });
    req.on("error", reject);
    if (body) req.write(typeof body === "string" ? body : JSON.stringify(body));
    req.end();
  });
}

async function openSession(modelId) {
  console.log(`[morpheus-proxy] Opening session for model ${modelId} (duration: ${SESSION_DURATION}s)`);
  const res = await routerFetch("POST", `/blockchain/models/${modelId}/session`, {
    sessionDuration: SESSION_DURATION,
  });
  if (res.status !== 200) {
    const text = res.body.toString();
    throw new Error(`Failed to open session (${res.status}): ${text}`);
  }
  const data = JSON.parse(res.body.toString());
  const sessionId = data.sessionID;
  const expiresAt = Date.now() + (SESSION_DURATION - RENEW_BEFORE_SEC) * 1000;
  sessions.set(modelId, { sessionId, expiresAt });
  console.log(`[morpheus-proxy] Session opened: ${sessionId} (expires ~${new Date(expiresAt).toISOString()})`);
  return sessionId;
}

async function getOrCreateSession(modelId) {
  const existing = sessions.get(modelId);
  if (existing && Date.now() < existing.expiresAt) {
    return existing.sessionId;
  }
  // Session expired or doesn't exist — open a new one
  if (existing) {
    console.log(`[morpheus-proxy] Session for ${modelId} expired, opening new one`);
  }
  return openSession(modelId);
}

function resolveModelId(modelName) {
  // Direct match
  if (MODEL_MAP[modelName]) return MODEL_MAP[modelName];
  // If it looks like a hex model ID already, use it
  if (modelName.startsWith("0x") && modelName.length === 66) return modelName;
  // Try lowercase
  const lower = modelName.toLowerCase();
  for (const [key, val] of Object.entries(MODEL_MAP)) {
    if (key.toLowerCase() === lower) return val;
  }
  return null;
}

// --- Request handler ---

async function handleChatCompletions(req, res, body) {
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (e) {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: { message: "Invalid JSON body" } }));
    return;
  }

  const requestedModel = parsed.model || "kimi-k2.5";
  const modelId = resolveModelId(requestedModel);
  if (!modelId) {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      error: { message: `Unknown model: ${requestedModel}. Available: ${Object.keys(MODEL_MAP).join(", ")}` }
    }));
    return;
  }

  let sessionId;
  try {
    sessionId = await getOrCreateSession(modelId);
  } catch (e) {
    console.error(`[morpheus-proxy] Session error: ${e.message}`);
    res.writeHead(502, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: { message: `Failed to open Morpheus session: ${e.message}` } }));
    return;
  }

  // Forward to Morpheus router
  const isStreaming = parsed.stream === true;

  const upstreamUrl = new URL("/v1/chat/completions", ROUTER_URL);
  const upstreamHeaders = {
    "Authorization": getBasicAuth(),
    "Content-Type": "application/json",
    "session_id": sessionId,
    "model_id": modelId,
  };

  const upstreamReq = http.request(upstreamUrl, {
    method: "POST",
    headers: upstreamHeaders,
    timeout: 120000, // 2 min timeout for P2P inference
  }, (upstreamRes) => {
    // Pass through status and headers
    const outHeaders = { "Content-Type": upstreamRes.headers["content-type"] || "application/json" };
    if (isStreaming && upstreamRes.headers["content-type"]?.includes("text/event-stream")) {
      outHeaders["Content-Type"] = "text/event-stream";
      outHeaders["Cache-Control"] = "no-cache";
      outHeaders["Connection"] = "keep-alive";
    }
    res.writeHead(upstreamRes.statusCode, outHeaders);

    upstreamRes.on("data", (chunk) => res.write(chunk));
    upstreamRes.on("end", () => res.end());
    upstreamRes.on("error", (e) => {
      console.error(`[morpheus-proxy] Upstream response error: ${e.message}`);
      res.end();
    });
  });

  upstreamReq.on("error", (e) => {
    console.error(`[morpheus-proxy] Upstream request error: ${e.message}`);
    if (!res.headersSent) {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: { message: `Morpheus upstream error: ${e.message}` } }));
    }
  });

  upstreamReq.on("timeout", () => {
    console.error(`[morpheus-proxy] Upstream request timed out`);
    upstreamReq.destroy();
    if (!res.headersSent) {
      res.writeHead(504, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: { message: "Morpheus inference timed out" } }));
    }
  });

  upstreamReq.write(body);
  upstreamReq.end();
}

function handleModels(req, res) {
  const models = Object.entries(MODEL_MAP).map(([name, id]) => ({
    id: name,
    object: "model",
    created: Math.floor(Date.now() / 1000),
    owned_by: "morpheus",
  }));
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ object: "list", data: models }));
}

function handleHealth(req, res) {
  const activeSessions = [];
  for (const [modelId, sess] of sessions) {
    const modelName = Object.entries(MODEL_MAP).find(([_, v]) => v === modelId)?.[0] || modelId;
    activeSessions.push({
      model: modelName,
      sessionId: sess.sessionId,
      expiresAt: new Date(sess.expiresAt).toISOString(),
      active: Date.now() < sess.expiresAt,
    });
  }
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({
    status: "ok",
    routerUrl: ROUTER_URL,
    activeSessions,
    availableModels: Object.keys(MODEL_MAP),
  }));
}

// --- Auth check ---
function checkAuth(req) {
  if (PROXY_API_KEY === "morpheus-local") return true; // no auth required if default
  const authHeader = req.headers.authorization;
  if (!authHeader) return false;
  const token = authHeader.replace(/^Bearer\s+/i, "");
  return token === PROXY_API_KEY;
}

// --- Server ---

const server = http.createServer((req, res) => {
  // Auth check
  if (!checkAuth(req)) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: { message: "Unauthorized" } }));
    return;
  }

  const url = new URL(req.url, `http://localhost:${PROXY_PORT}`);

  if (req.method === "GET" && url.pathname === "/health") {
    return handleHealth(req, res);
  }

  if (req.method === "GET" && url.pathname === "/v1/models") {
    return handleModels(req, res);
  }

  if (req.method === "POST" && url.pathname === "/v1/chat/completions") {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString();
      handleChatCompletions(req, res, body).catch((e) => {
        console.error(`[morpheus-proxy] Unhandled error: ${e.message}`);
        if (!res.headersSent) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: { message: e.message } }));
        }
      });
    });
    return;
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: { message: "Not found" } }));
});

server.listen(PROXY_PORT, "127.0.0.1", () => {
  console.log(`[morpheus-proxy] Listening on http://127.0.0.1:${PROXY_PORT}`);
  console.log(`[morpheus-proxy] Router: ${ROUTER_URL}`);
  console.log(`[morpheus-proxy] Available models: ${Object.keys(MODEL_MAP).join(", ")}`);
  console.log(`[morpheus-proxy] Session duration: ${SESSION_DURATION}s, renew before: ${RENEW_BEFORE_SEC}s`);
});

server.on("error", (e) => {
  console.error(`[morpheus-proxy] Server error: ${e.message}`);
  process.exit(1);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("[morpheus-proxy] Shutting down...");
  server.close(() => process.exit(0));
});
process.on("SIGINT", () => {
  console.log("[morpheus-proxy] Shutting down...");
  server.close(() => process.exit(0));
});
