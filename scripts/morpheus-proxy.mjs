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
// Hardcoded defaults used as fallback if the router is unreachable at startup.
// On startup (and periodically), refreshModelMap() overwrites this with
// live data from the router's /blockchain/models endpoint.
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

// --- Dynamic model refresh ---
const MODEL_REFRESH_INTERVAL = parseInt(process.env.MORPHEUS_MODEL_REFRESH_INTERVAL || "300", 10); // 5 min default

async function refreshModelMap() {
  try {
    const res = await routerFetch("GET", "/blockchain/models");
    if (res.status !== 200) {
      console.warn(`[morpheus-proxy] Model refresh returned ${res.status}, keeping existing map`);
      return;
    }
    const models = JSON.parse(res.body.toString());
    if (!Array.isArray(models) || models.length === 0) {
      console.warn("[morpheus-proxy] Model refresh returned empty list, keeping existing map");
      return;
    }
    let added = 0;
    for (const m of models) {
      const name = m.Name || m.name;
      const id = m.Id || m.id;
      if (name && id && !MODEL_MAP[name]) {
        MODEL_MAP[name] = id;
        added++;
      } else if (name && id) {
        // Update existing entry in case the on-chain ID changed
        MODEL_MAP[name] = id;
      }
    }
    console.log(`[morpheus-proxy] Refreshed MODEL_MAP: ${Object.keys(MODEL_MAP).length} models (${added} new)`);
  } catch (e) {
    console.warn(`[morpheus-proxy] Failed to refresh MODEL_MAP, using defaults: ${e.message}`);
  }
}

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

// --- OpenAI-compatible error helper ---
// Returns errors in the exact format OpenAI uses so OpenClaw's failover
// engine classifies them correctly (server_error, not billing).
function oaiError(res, status, message, type = "server_error", code = null) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify({
    error: {
      message,
      type,        // "server_error" | "invalid_request_error" | "rate_limit_error"
      code: code,  // null or string like "model_not_found"
      param: null,
    }
  }));
}

// --- Forward a single inference attempt ---
function forwardToRouter(body, sessionId, modelId, isStreaming, timeoutMs = 300000) {
  return new Promise((resolve, reject) => {
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
      timeout: timeoutMs,
    }, (upstreamRes) => {
      // Collect full response to inspect for errors before piping
      if (isStreaming && upstreamRes.headers["content-type"]?.includes("text/event-stream")) {
        // For streaming, resolve immediately with the response to pipe through
        resolve({ status: upstreamRes.statusCode, stream: upstreamRes, headers: upstreamRes.headers });
      } else {
        const chunks = [];
        upstreamRes.on("data", (c) => chunks.push(c));
        upstreamRes.on("end", () => {
          resolve({ status: upstreamRes.statusCode, body: Buffer.concat(chunks), headers: upstreamRes.headers });
        });
        upstreamRes.on("error", (e) => reject(e));
      }
    });

    upstreamReq.on("error", (e) => reject(new Error(`upstream_connect: ${e.message}`)));
    upstreamReq.on("timeout", () => {
      upstreamReq.destroy();
      reject(new Error("upstream_timeout"));
    });

    upstreamReq.write(body);
    upstreamReq.end();
  });
}

// Check if an error response from the router indicates an invalid/expired session
function isSessionError(status, bodyStr) {
  if (status >= 400 && status < 500) {
    const lower = bodyStr.toLowerCase();
    return lower.includes("session") && (lower.includes("not found") || lower.includes("expired") || lower.includes("invalid") || lower.includes("closed"));
  }
  return false;
}

async function handleChatCompletions(req, res, body) {
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (e) {
    return oaiError(res, 400, "Invalid JSON body", "invalid_request_error");
  }

  const requestedModel = parsed.model || "kimi-k2.5";
  const modelId = resolveModelId(requestedModel);
  if (!modelId) {
    return oaiError(res, 400,
      `Unknown model: ${requestedModel}. Available: ${Object.keys(MODEL_MAP).join(", ")}`,
      "invalid_request_error", "model_not_found");
  }

  // --- Attempt 1: use existing/new session ---
  let sessionId;
  try {
    sessionId = await getOrCreateSession(modelId);
  } catch (e) {
    console.error(`[morpheus-proxy] Session open error: ${e.message}`);
    // This is a Morpheus infrastructure error, NOT a billing error
    return oaiError(res, 502, `Morpheus session unavailable: ${e.message}`, "server_error", "morpheus_session_error");
  }

  const isStreaming = parsed.stream === true;
  let attempt1Error = null;

  try {
    const result = await forwardToRouter(body, sessionId, modelId, isStreaming);

    // --- Streaming response ---
    if (result.stream) {
      const outHeaders = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
      };
      res.writeHead(result.status, outHeaders);
      result.stream.on("data", (chunk) => res.write(chunk));
      result.stream.on("end", () => res.end());
      result.stream.on("error", (e) => {
        console.error(`[morpheus-proxy] Stream error: ${e.message}`);
        res.end();
      });
      return;
    }

    // --- Non-streaming response ---
    const bodyStr = result.body.toString();

    // If router returned success, pass through
    if (result.status >= 200 && result.status < 300) {
      res.writeHead(result.status, { "Content-Type": result.headers["content-type"] || "application/json" });
      res.end(result.body);
      return;
    }

    // If it's a session error, we can retry with a fresh session
    if (isSessionError(result.status, bodyStr)) {
      console.log(`[morpheus-proxy] Session error detected (${result.status}), will retry with new session`);
      sessions.delete(modelId); // invalidate cached session
      attempt1Error = `session_invalid (${result.status})`;
      // Fall through to retry below
    } else {
      // Non-session upstream error — return as server_error (not billing!)
      console.error(`[morpheus-proxy] Router error (${result.status}): ${bodyStr.substring(0, 200)}`);
      return oaiError(res, result.status >= 500 ? 502 : result.status,
        `Morpheus inference error: ${bodyStr.substring(0, 500)}`,
        "server_error", "morpheus_inference_error");
    }
  } catch (e) {
    if (e.message === "upstream_timeout") {
      console.error(`[morpheus-proxy] Upstream timed out on attempt 1`);
      return oaiError(res, 504, "Morpheus inference timed out", "server_error", "timeout");
    }
    // Connection error — might be transient, try to invalidate session and retry
    console.error(`[morpheus-proxy] Attempt 1 failed: ${e.message}`);
    sessions.delete(modelId);
    attempt1Error = e.message;
  }

  // --- Attempt 2: open a fresh session and retry once ---
  if (attempt1Error) {
    console.log(`[morpheus-proxy] Retrying with fresh session (attempt 1 failed: ${attempt1Error})`);
    let newSessionId;
    try {
      newSessionId = await openSession(modelId);
    } catch (e) {
      console.error(`[morpheus-proxy] Session re-open failed: ${e.message}`);
      return oaiError(res, 502, `Morpheus session unavailable after retry: ${e.message}`, "server_error", "morpheus_session_error");
    }

    try {
      const result = await forwardToRouter(body, newSessionId, modelId, isStreaming);

      if (result.stream) {
        const outHeaders = {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          "Connection": "keep-alive",
        };
        res.writeHead(result.status, outHeaders);
        result.stream.on("data", (chunk) => res.write(chunk));
        result.stream.on("end", () => res.end());
        result.stream.on("error", (e) => {
          console.error(`[morpheus-proxy] Stream error (retry): ${e.message}`);
          res.end();
        });
        return;
      }

      const bodyStr = result.body.toString();
      if (result.status >= 200 && result.status < 300) {
        res.writeHead(result.status, { "Content-Type": result.headers["content-type"] || "application/json" });
        res.end(result.body);
        return;
      }

      console.error(`[morpheus-proxy] Retry also failed (${result.status}): ${bodyStr.substring(0, 200)}`);
      return oaiError(res, 502,
        `Morpheus inference failed after retry: ${bodyStr.substring(0, 500)}`,
        "server_error", "morpheus_inference_error");
    } catch (e) {
      if (e.message === "upstream_timeout") {
        return oaiError(res, 504, "Morpheus inference timed out (retry)", "server_error", "timeout");
      }
      console.error(`[morpheus-proxy] Retry failed: ${e.message}`);
      return oaiError(res, 502, `Morpheus upstream error after retry: ${e.message}`, "server_error", "morpheus_upstream_error");
    }
  }
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

// v5.12.0: Align server timeouts with upstream consumer→provider total (270s)
server.requestTimeout = 300000;   // 5 min
server.headersTimeout = 305000;   // slightly above requestTimeout
server.keepAliveTimeout = 300000;

server.listen(PROXY_PORT, "127.0.0.1", async () => {
  console.log(`[morpheus-proxy] Listening on http://127.0.0.1:${PROXY_PORT}`);
  console.log(`[morpheus-proxy] Router: ${ROUTER_URL}`);
  console.log(`[morpheus-proxy] Session duration: ${SESSION_DURATION}s, renew before: ${RENEW_BEFORE_SEC}s`);

  // Refresh model map from router on startup
  await refreshModelMap();
  console.log(`[morpheus-proxy] Available models: ${Object.keys(MODEL_MAP).join(", ")}`);

  // Periodically refresh to pick up new on-chain models
  if (MODEL_REFRESH_INTERVAL > 0) {
    setInterval(refreshModelMap, MODEL_REFRESH_INTERVAL * 1000);
    console.log(`[morpheus-proxy] Model refresh interval: ${MODEL_REFRESH_INTERVAL}s`);
  }
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
