#!/usr/bin/env node
import { createServer } from "node:http";
import { spawnSync } from "node:child_process";
import { Readable } from "node:stream";

const host = process.env.GENSEE_GATEWAY_HOST || "127.0.0.1";
const port = Number(process.env.GENSEE_GATEWAY_PORT || "8787");
const upstreamBase = process.env.ANTHROPIC_UPSTREAM_BASE_URL || "https://api.anthropic.com";
const upstreamApiKey = process.env.ANTHROPIC_UPSTREAM_API_KEY || "";
const upstreamAuthToken = process.env.ANTHROPIC_UPSTREAM_AUTH_TOKEN || "";
const gatewayToken = process.env.GENSEE_GATEWAY_TOKEN || "";
const action = (process.env.GENSEE_GATEWAY_STEGO_ACTION || "block").toLowerCase();
const genseeBin = process.env.GENSEE_BIN || "";

const allowedPaths = new Set(
  (process.env.GENSEE_GATEWAY_ALLOWED_PATHS || "/v1/messages,/v1/messages/count_tokens")
    .split(",")
    .map((path) => path.trim())
    .filter(Boolean),
);

if (process.argv.includes("--self-test")) {
  runSelfTest();
  process.exit(0);
}

createServer(handleRequest).listen(port, host, () => {
  console.error(`gensee anthropic gateway listening on http://${host}:${port}`);
});

async function handleRequest(request, response) {
  try {
    if (request.method === "GET" && new URL(request.url, "http://localhost").pathname === "/healthz") {
      return sendJson(response, 200, { ok: true });
    }
    if (request.method === "OPTIONS") {
      response.writeHead(204);
      return response.end();
    }
    if (gatewayToken && !requestHasGatewayToken(request, gatewayToken)) {
      return sendJson(response, 401, anthropicError("unauthorized gateway token"));
    }

    const requestUrl = new URL(request.url, "http://localhost");
    if (!allowedPaths.has(requestUrl.pathname)) {
      return sendJson(response, 404, anthropicError(`gateway path not allowed: ${requestUrl.pathname}`));
    }

    const body = await readBody(request);
    const screening = screenRequestBody(body, request.headers["content-type"] || "");
    if (screening.findings.length > 0) {
      const sessionId = sessionIdForRequest(request, screening.parsed);
      recordAlert({
        sessionId,
        action,
        severity: screening.severity,
        message: `LLM gateway ${action === "block" ? "blocked" : "flagged"} suspicious prompt steganography markers`,
        evidence: {
          source: "anthropic_gateway",
          upstream_path: requestUrl.pathname,
          findings: screening.findings,
        },
      });
      if (action === "block") {
        return sendJson(
          response,
          403,
          anthropicError("Gensee gateway blocked request: suspicious prompt steganography markers detected"),
        );
      }
    }

    return forwardRequest(request, response, requestUrl, body);
  } catch (error) {
    console.error(`gensee anthropic gateway error: ${error.stack || error}`);
    sendJson(response, 502, anthropicError("gateway error"));
  }
}

function requestHasGatewayToken(request, expected) {
  const auth = String(request.headers.authorization || "");
  const apiKey = String(request.headers["x-api-key"] || "");
  return auth === `Bearer ${expected}` || apiKey === expected;
}

function sessionIdForRequest(request, parsed) {
  return (
    request.headers["x-gensee-session-id"] ||
    parsed?.metadata?.gensee_session_id ||
    parsed?.metadata?.user_id ||
    "llm-gateway"
  ).toString();
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks);
}

function screenRequestBody(body, contentType) {
  if (!contentType.toLowerCase().includes("application/json")) {
    return { findings: [], severity: "info", parsed: null };
  }
  let parsed;
  try {
    parsed = JSON.parse(body.toString("utf8"));
  } catch {
    return {
      findings: [{ path: "$", category: "invalid_json", message: "request body is not valid JSON" }],
      severity: "high",
      parsed: null,
    };
  }

  const findings = [];
  walkJson(parsed, ["$"], findings);
  const severity = findings.some((finding) => finding.category !== "variant_punctuation")
    ? "high"
    : findings.length > 0
      ? "medium"
      : "info";
  return { findings, severity, parsed };
}

function walkJson(value, path, findings) {
  if (typeof value === "string") {
    findings.push(...screenString(value, path));
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => walkJson(item, [...path, String(index)], findings));
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      walkJson(child, [...path, key], findings);
    }
  }
}

function screenString(value, path) {
  const findings = [];
  const invisible = codepoints(value).filter((cp) => isInvisibleStegoCodepoint(cp));
  if (invisible.length > 0) {
    findings.push(finding(path, "invisible_control", invisible));
  }

  if (isTrustedPromptScaffoldingPath(path)) {
    const punctuation = codepoints(value).filter((cp) => isVariantPunctuation(cp));
    if (punctuation.length > 0) {
      findings.push(finding(path, "variant_punctuation", punctuation));
    }
  }
  return findings;
}

function finding(path, category, cps) {
  return {
    path: path.join("."),
    category,
    count: cps.length,
    code_points: [...new Set(cps)].slice(0, 12).map((cp) => `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`),
  };
}

function codepoints(value) {
  const cps = [];
  for (const char of value) cps.push(char.codePointAt(0));
  return cps;
}

function isInvisibleStegoCodepoint(cp) {
  return (
    (cp >= 0x200b && cp <= 0x200f) ||
    (cp >= 0x202a && cp <= 0x202e) ||
    (cp >= 0x2060 && cp <= 0x206f) ||
    (cp >= 0xfe00 && cp <= 0xfe0f) ||
    (cp >= 0xe0100 && cp <= 0xe01ef) ||
    (cp >= 0xe0000 && cp <= 0xe007f) ||
    cp === 0xfeff
  );
}

function isVariantPunctuation(cp) {
  return (
    cp === 0x00a0 ||
    (cp >= 0x2010 && cp <= 0x201f) ||
    (cp >= 0x2032 && cp <= 0x2037)
  );
}

function isTrustedPromptScaffoldingPath(path) {
  const parts = new Set(path.map(String));
  return (
    parts.has("system") ||
    parts.has("developer") ||
    parts.has("tools") ||
    parts.has("description") ||
    parts.has("input_schema")
  );
}

async function forwardRequest(originalRequest, clientResponse, requestUrl, body) {
  const upstreamUrl = new URL(requestUrl.pathname + requestUrl.search, upstreamBase);
  const headers = headersForUpstream(originalRequest.headers);
  const upstreamResponse = await fetch(upstreamUrl, {
    method: originalRequest.method,
    headers,
    body,
  });

  clientResponse.statusCode = upstreamResponse.status;
  for (const [key, value] of upstreamResponse.headers) {
    if (["content-encoding", "content-length", "connection", "transfer-encoding"].includes(key.toLowerCase())) {
      continue;
    }
    clientResponse.setHeader(key, value);
  }
  if (upstreamResponse.body) {
    Readable.fromWeb(upstreamResponse.body).pipe(clientResponse);
  } else {
    clientResponse.end(await upstreamResponse.text());
  }
}

function headersForUpstream(source) {
  const headers = new Headers();
  for (const [key, value] of Object.entries(source)) {
    if (["host", "connection", "content-length", "authorization", "x-api-key"].includes(key.toLowerCase())) {
      continue;
    }
    if (Array.isArray(value)) {
      for (const item of value) headers.append(key, item);
    } else if (value !== undefined) {
      headers.set(key, String(value));
    }
  }
  if (upstreamApiKey) headers.set("x-api-key", upstreamApiKey);
  if (upstreamAuthToken) headers.set("authorization", `Bearer ${upstreamAuthToken}`);
  return headers;
}

function recordAlert({ sessionId, action, severity, message, evidence }) {
  if (!genseeBin) {
    console.error(JSON.stringify({ level: "warn", message, action, severity, sessionId, evidence }));
    return;
  }
  const result = spawnSync(
    genseeBin,
    [
      "gateway-alert",
      "--session-id",
      sessionId,
      "--action",
      action === "block" ? "block" : "warn",
      "--severity",
      severity,
      "--message",
      message,
      "--evidence-json",
      JSON.stringify(evidence),
    ],
    { stdio: "ignore", env: process.env },
  );
  if (result.status !== 0) {
    console.error(`gensee anthropic gateway: failed to record alert with status ${result.status}`);
  }
}

function anthropicError(message) {
  return {
    type: "error",
    error: {
      type: "invalid_request_error",
      message,
    },
  };
}

function sendJson(response, status, body) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

function runSelfTest() {
  const blocked = screenRequestBody(
    Buffer.from(JSON.stringify({ system: "Current date is 2026-07-02\u200B" })),
    "application/json",
  );
  if (blocked.findings.length !== 1 || blocked.findings[0].category !== "invisible_control") {
    throw new Error("expected zero-width system prompt marker to be blocked");
  }
  const userProse = screenRequestBody(
    Buffer.from(JSON.stringify({ messages: [{ role: "user", content: "That is \u201Cfine\u201D." }] })),
    "application/json",
  );
  if (userProse.findings.length !== 0) {
    throw new Error("ordinary smart quotes in user prose should not be flagged");
  }
  const systemPunctuation = screenRequestBody(
    Buffer.from(JSON.stringify({ system: "Use today\u2019s date." })),
    "application/json",
  );
  if (systemPunctuation.findings.length !== 1 || systemPunctuation.findings[0].category !== "variant_punctuation") {
    throw new Error("variant punctuation in trusted prompt scaffolding should be flagged");
  }
}
