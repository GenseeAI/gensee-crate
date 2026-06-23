import { createServer } from "node:http";
import { createReadStream } from "node:fs";
import { access, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { homedir, hostname } from "node:os";
import { extname, isAbsolute, join, normalize, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const root = resolve(fileURLToPath(new URL("../src", import.meta.url)));
const port = Number.parseInt(process.env.PORT || "5173", 10);
// Bind to loopback only: the dashboard exposes local security telemetry
// (paths, commands, alert evidence) that must not be reachable from the LAN.
const bindHost = "127.0.0.1";
const genseeHome = resolve(process.env.GENSEE_HOME || join(homedir(), ".gensee"));
const dbPath = join(genseeHome, "gensee.db");
const policyFilePath = join(genseeHome, "policy.json");
const policyRequiredKeys = ["schema_version", "operations", "secret_paths", "persistence_writes", "categories"];

// Resolve the gensee binary for `policy print-default` (best effort): GENSEE_BIN,
// else the built artifact in this repo, else PATH.
function genseeBinCandidates() {
  const repoRoot = resolve(fileURLToPath(new URL("../../..", import.meta.url)));
  return [
    process.env.GENSEE_BIN,
    join(repoRoot, "target", "release", "gensee"),
    join(repoRoot, "target", "debug", "gensee"),
    "gensee",
  ].filter(Boolean);
}

// Run the gensee binary against the same GENSEE_HOME the dashboard reads,
// trying each candidate path until one resolves. Returns the resolved stdout or
// a structured error (e.g. validation failure / no binary found).
async function genseeRun(args) {
  for (const bin of genseeBinCandidates()) {
    try {
      const { stdout } = await execFileAsync(bin, args, {
        maxBuffer: 4 * 1024 * 1024,
        env: { ...process.env, GENSEE_HOME: genseeHome },
      });
      return { ok: true, stdout };
    } catch (error) {
      if (error.code === "ENOENT") continue; // unresolved candidate — try next
      return { ok: false, error: (error.stderr || error.message || "").toString().trim() };
    }
  }
  return { ok: false, error: "gensee binary not found (set GENSEE_BIN or build it)" };
}

async function bundledDefaultPolicy() {
  for (const bin of genseeBinCandidates()) {
    try {
      const { stdout } = await execFileAsync(bin, ["policy", "print-default"], { maxBuffer: 4 * 1024 * 1024 });
      if (stdout.trim()) return stdout;
    } catch {
      // try the next candidate
    }
  }
  return null;
}

const loopbackHostnames = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

// CSRF guard for state-changing requests: a same-origin dashboard fetch sets the
// custom X-Gensee-Dashboard header (a "non-simple" header that forces a CORS
// preflight cross-origin, which this server never approves), and any present
// Origin/Referer must be loopback.
function isWriteAllowed(request) {
  if (!request.headers["x-gensee-dashboard"]) return false;
  const origin = request.headers.origin || request.headers.referer;
  if (origin) {
    try {
      if (!loopbackHostnames.has(new URL(origin).hostname.toLowerCase())) return false;
    } catch {
      return false;
    }
  }
  return true;
}

// Fully validate a candidate policy with the real engine (`gensee policy
// validate` on a temp file). Falls back to a required-key check if no gensee
// binary is found, so the dashboard still works without one (the shield itself
// re-validates fail-closed on load either way).
async function validatePolicy(jsonText) {
  const tmp = join(genseeHome, `.policy-validate-${process.pid}.json`);
  try {
    await mkdir(genseeHome, { recursive: true });
    await writeFile(tmp, jsonText, "utf8");
    for (const bin of genseeBinCandidates()) {
      try {
        await execFileAsync(bin, ["policy", "validate", tmp], { maxBuffer: 1024 * 1024 });
        return { ok: true, validatedBy: "gensee policy validate" };
      } catch (error) {
        // exit!=0 from a resolved binary = a real validation failure; surface it.
        if (error.code !== "ENOENT" && typeof error.stderr === "string" && error.stderr.trim()) {
          return { ok: false, error: error.stderr.trim() };
        }
        // ENOENT / unresolved candidate -> try the next one.
      }
    }
  } finally {
    try {
      await rm(tmp, { force: true });
    } catch {
      // best effort
    }
  }
  // No binary available: structural fallback.
  let parsed;
  try {
    parsed = JSON.parse(jsonText);
  } catch (error) {
    return { ok: false, error: `not valid JSON: ${error.message}` };
  }
  const missing = policyRequiredKeys.filter((key) => !(key in parsed));
  if (missing.length) return { ok: false, error: `missing required keys: ${missing.join(", ")}` };
  return { ok: true, validatedBy: "structural check (gensee binary not found)" };
}

function readBody(request) {
  return new Promise((resolveBody, rejectBody) => {
    const chunks = [];
    let size = 0;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > 4 * 1024 * 1024) {
        rejectBody(new Error("policy document too large"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolveBody(Buffer.concat(chunks).toString("utf8")));
    request.on("error", rejectBody);
  });
}

// Only honor requests whose Host header is a loopback name. Together with the
// loopback bind this blocks DNS-rebinding: a remote page that rebinds its
// hostname to 127.0.0.1 still sends its own Host header, which is rejected.
const allowedHosts = new Set([
  `localhost:${port}`,
  `127.0.0.1:${port}`,
  `[::1]:${port}`,
]);

function isAllowedHost(hostHeader) {
  return typeof hostHeader === "string" && allowedHosts.has(hostHeader.toLowerCase());
}

const contentTypes = new Map([
  [".html", "text/html; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".svg", "image/svg+xml"],
  [".png", "image/png"],
  [".jpg", "image/jpeg"],
  [".jpeg", "image/jpeg"],
]);

const actionRank = new Map([
  ["block", 3],
  ["deny", 3],
  ["ask", 2],
  ["warn", 1],
  ["allow", 0],
]);

function sendJson(response, status, body) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  response.end(JSON.stringify(body));
}

function isInsideRoot(candidate) {
  const pathFromRoot = relative(root, candidate);
  return pathFromRoot === "" || (!pathFromRoot.startsWith("..") && !isAbsolute(pathFromRoot));
}

class BadRequestError extends Error {}

function parseRequestUrl(url) {
  try {
    return new URL(url || "/", "http://localhost");
  } catch {
    throw new BadRequestError("Malformed request URL");
  }
}

function resolveRequestPath(url) {
  let requestPath;
  try {
    // decodeURIComponent throws on malformed escapes (e.g. a bare `%`); treat
    // those as a bad request rather than letting the rejection hang the socket.
    requestPath = decodeURIComponent(parseRequestUrl(url).pathname);
  } catch {
    throw new BadRequestError("Malformed request URL");
  }
  const normalizedPath = normalize(requestPath).replace(/^(\.\.[/\\])+/, "");
  const candidate = resolve(join(root, normalizedPath));
  return isInsideRoot(candidate) ? candidate : null;
}

async function fileForRequest(url) {
  const candidate = resolveRequestPath(url);
  if (!candidate) return null;

  try {
    const info = await stat(candidate);
    if (info.isDirectory()) return join(candidate, "index.html");
    return info.isFile() ? candidate : null;
  } catch {
    return join(root, "index.html");
  }
}

async function pathExists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function readJsonl(fileName, limit = 200) {
  const filePath = join(genseeHome, fileName);
  try {
    const content = await readFile(filePath, "utf8");
    return content
      .split("\n")
      .filter(Boolean)
      .slice(-limit)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
  } catch {
    return [];
  }
}

async function sqliteJson(sql) {
  if (!(await pathExists(dbPath))) return [];

  try {
    // busy_timeout: WAL writers (a live hook ingest, or the seed's checkpoint)
    // briefly lock the DB. Without a timeout the reader errors immediately with
    // "database is locked" and the whole poll returns empty (a visible flash);
    // waiting up to 3s lets the read succeed instead.
    const { stdout } = await execFileAsync(
      "/usr/bin/sqlite3",
      ["-cmd", ".timeout 3000", "-json", dbPath, sql],
      { maxBuffer: 1024 * 1024 * 8 },
    );
    return stdout.trim() ? JSON.parse(stdout) : [];
  } catch (error) {
    throw new Error(`sqlite query failed: ${error.message}`);
  }
}

async function loadGenseeState(errors) {
  const result = await genseeRun(["dashboard-state"]);
  if (!result.ok) {
    errors.push(`gensee dashboard-state failed: ${result.error}`);
    return null;
  }
  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    errors.push(`gensee dashboard-state returned invalid JSON: ${error.message}`);
    return null;
  }
}

function toNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function withinRange(ts, range, window) {
  if (range === "custom" && window) {
    const number = toNumber(ts);
    if (!number) return true;
    return number >= window.from && number <= window.to;
  }
  if (range === "24h" || range === "1h") {
    const number = toNumber(ts);
    if (!number) return true;
    const ageMs = Date.now() - number;
    return ageMs <= (range === "1h" ? 60 * 60 * 1000 : 24 * 60 * 60 * 1000);
  }
  return true;
}

function actionForAlert(alert) {
  if (alert.action === "block") return "deny";
  return alert.action || "warn";
}

function compareRecent(a, b) {
  return (toNumber(b.ts) || 0) - (toNumber(a.ts) || 0);
}

function shortPath(value) {
  if (!value) return "";
  return String(value).replace(`file://${homedir()}`, "~").replace(homedir(), "~");
}

function parseJson(value) {
  if (!value || typeof value !== "string") return value || null;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function commandFromInput(value) {
  const input = parseJson(value);
  if (!input) return "";
  if (typeof input === "string") return input;
  return input.command || input.file_path || input.path || input.url || JSON.stringify(input);
}

function normalizeAlert(alert) {
  const action = alert.rule_id === "policy_memory_poison_detected" ? "warn" : actionForAlert(alert);
  return {
    id: `alert-${alert.alert_id ?? alert.id ?? `${alert.created_at}-${alert.rule_id}`}`,
    kind: "alert",
    ts: toNumber(alert.created_at) || Date.now(),
    action,
    severity: alert.severity || "medium",
    title: alert.message || alert.rule_id || "Policy alert",
    description: alert.path ? `${alert.rule_id || "policy"} matched ${shortPath(alert.path)}` : alert.rule_id || "",
    path: alert.path || "",
    tool: alert.entity_kind || "policy",
    evidence: parseJson(alert.evidence),
    policy: alert.rule_id || "",
    request: alert.request_id ? `req_${alert.request_id}` : "unknown",
    session: alert.session_id || "unknown",
  };
}

function collapseMemoryPoisonAlerts(alerts) {
  const collapsed = [];
  const groups = new Map();
  for (const alert of alerts) {
    if (alert.kind !== "alert" || alert.policy !== "policy_memory_poison_detected") {
      collapsed.push(alert);
      continue;
    }
    const key = alert.session || "unknown";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(alert);
  }

  for (const [session, group] of groups) {
    group.sort(compareRecent);
    const newest = group[0];
    const paths = [...new Set(group.map((alert) => alert.path).filter(Boolean))];
    const shownPaths = paths.slice(0, 3).map(shortPath);
    const suffix = paths.length > shownPaths.length ? ` +${paths.length - shownPaths.length} more` : "";
    collapsed.push({
      ...newest,
      id: `memory-poison-${session}-${newest.ts}`,
      action: "warn",
      title: `Instruction-override poison detected in ${paths.length || group.length} memory/skill file${(paths.length || group.length) === 1 ? "" : "s"}`,
      description: shownPaths.length
        ? `policy_memory_poison_detected matched ${shownPaths.join(", ")}${suffix}`
        : "policy_memory_poison_detected matched auto-loaded memory or skill files",
      evidence: {
        ...(newest.evidence || {}),
        collapsed_count: group.length,
        collapsed_paths: paths,
      },
    });
  }

  return collapsed;
}

function normalizeAgentEvent(event) {
  const tool = event.tool_name || event.type || "tool";
  const evidence = commandFromInput(event.tool_input);
  return {
    id: `agent-${event.event_id ?? event.id ?? `${event.ts}-${tool}`}`,
    kind: "tool",
    ts: toNumber(event.ts) || Date.now(),
    action: "allow",
    severity: "info",
    title: `${tool} ${event.type || "event"}`,
    description: evidence || event.cwd || "",
    command: evidence || "",
    path: event.cwd || "",
    tool,
    evidence,
    policy: event.permission_mode || event.source || "",
    request: event.request_id ? `req_${event.request_id}` : "unknown",
    session: event.session_id || "unknown",
  };
}

function compactAgentToolEvents(events) {
  const groups = new Map();
  const standalone = [];

  for (const event of events) {
    if (!["PreToolUse", "PostToolUse", "PermissionRequest"].includes(event.type || "")) {
      standalone.push(normalizeAgentEvent(event));
      continue;
    }
    const command = commandFromInput(event.tool_input);
    const key = event.tool_use_id
      ? `${event.session_id || "unknown"}:${event.tool_use_id}`
      : `${event.session_id || "unknown"}:${event.request_id || "unknown"}:${event.tool_name || "tool"}:${command}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(event);
  }

  const compacted = [...standalone];
  for (const [key, group] of groups) {
    const pre = group.find((event) => event.type === "PreToolUse");
    const post = group.find((event) => event.type === "PostToolUse");
    const permission = group.find((event) => event.type === "PermissionRequest");
    const chosen = post || permission || pre || group[0];
    const command = commandFromInput((pre || permission || post || chosen).tool_input);
    const tool = chosen.tool_name || pre?.tool_name || post?.tool_name || permission?.tool_name || "tool";
    const status = post ? "completed" : permission ? "permission requested" : "started";
    compacted.push({
      id: `tool-${key}`,
      kind: "tool",
      ts: toNumber(post?.ts || permission?.ts || pre?.ts || chosen.ts) || Date.now(),
      action: "allow",
      severity: "info",
      title: `${tool} ${status}`,
      description: command || chosen.cwd || "",
      command: command || "",
      path: chosen.cwd || pre?.cwd || post?.cwd || permission?.cwd || "",
      tool,
      evidence: {
        pre_event_id: pre?.event_id,
        post_event_id: post?.event_id,
        permission_event_id: permission?.event_id,
        tool_use_id: chosen.tool_use_id || pre?.tool_use_id || post?.tool_use_id || permission?.tool_use_id,
      },
      policy: chosen.permission_mode || chosen.source || "",
      request: chosen.request_id ? `req_${chosen.request_id}` : "unknown",
      session: chosen.session_id || "unknown",
    });
  }

  return compacted;
}

function hookPromptText(event) {
  const value = parseJson(event.raw_json);
  if (value && typeof value === "object") return value.prompt || value.user_prompt || value.message || "";
  return event.prompt || "";
}

function hookResponseText(event) {
  const value = parseJson(event.raw_json);
  if (value && typeof value === "object") return value.last_assistant_message || "";
  return event.last_assistant_message || "";
}

function looksUnsafeDestructivePrompt(prompt) {
  const lower = String(prompt || "").toLowerCase();
  return /\brm\s+(-[a-z]*r[a-z]*f|-rf|-fr)\b/.test(lower)
    || /\brm\s+.*(~\/|\/|\$home)/.test(lower)
    || /delete (my |the )?(home directory|entire home|all files|everything)/.test(lower);
}

function looksLikeAgentRefusal(response) {
  const lower = String(response || "").toLowerCase();
  return /\bi (can['’]?t|cannot|won['’]?t) (run|execute|do|help with)\b/.test(lower)
    || /\bcan['’]?t run\b/.test(lower)
    || /\bwould destructively delete\b/.test(lower);
}

function deriveAgentRefusalEvents(hookEvents) {
  const hookTs = (event) => toNumber(event.ts || event.observed_at_ms || event.timestamp_ms || event.created_at) || Date.now();
  const prompts = hookEvents
    .filter((event) => event.hook_event_name === "UserPromptSubmit")
    .map((event) => ({ ...event, prompt: hookPromptText(event), ts: hookTs(event) }))
    .filter((event) => looksUnsafeDestructivePrompt(event.prompt));
  if (!prompts.length) return [];

  const refusals = [];
  for (const event of hookEvents.filter((hook) => hook.hook_event_name === "Stop")) {
    const response = hookResponseText(event);
    if (!looksLikeAgentRefusal(response)) continue;
    const ts = hookTs(event);
    const prompt = prompts
      .filter((candidate) => candidate.session_id === event.session_id && candidate.ts <= ts)
      .sort((a, b) => b.ts - a.ts)[0];
    if (!prompt) continue;
    refusals.push({
      id: `agent-refusal-${event.session_id || "unknown"}-${ts}`,
      kind: "alert",
      ts,
      action: "deny",
      severity: "high",
      title: "Agent refused unsafe destructive request",
      description: response || prompt.prompt,
      command: prompt.prompt || "",
      path: event.cwd || prompt.cwd || "",
      tool: "agent",
      evidence: { source: "agent_refusal", prompt: prompt.prompt, response },
      policy: "agent_refusal_destructive_request",
      request: "unknown",
      session: event.session_id || "unknown",
    });
  }
  return refusals;
}

function normalizeSystemEvent(event) {
  const args = parseJson(event.args);
  const description = typeof args === "string" ? args : args?.path || args?.command || event.cwd || "";
  return {
    id: `system-${event.event_id ?? event.id ?? `${event.ts}-${event.type}`}`,
    kind: "system",
    ts: toNumber(event.ts) || Date.now(),
    action: "watch",
    severity: "info",
    title: `Observed ${event.type || "system event"}`,
    description,
    path: args?.path || event.cwd || "",
    tool: event.source || "system",
    evidence: args,
    policy: event.type || "",
    request: event.request_id ? `req_${event.request_id}` : "unknown",
    session: event.session_id || "unknown",
  };
}

function normalizeWorkspaceEffect(effect, index) {
  return {
    id: `effect-${effect.observed_at_ms ?? index}`,
    kind: "file",
    ts: toNumber(effect.observed_at_ms || effect.observed_at) || Date.now(),
    action: "watch",
    severity: "info",
    title: `Filesystem ${effect.effect_type || effect.kind || "effect"}`,
    description: shortPath(effect.path || effect.uri || ""),
    path: effect.path || effect.uri || "",
    tool: effect.source || "watch",
    evidence: effect,
    policy: effect.confidence ? `confidence ${effect.confidence}` : "",
    request: effect.request_id ? `req_${effect.request_id}` : "unknown",
    session: effect.session_id || "unknown",
  };
}

function normalizeHookEvent(event, index) {
  const hook = event.hook_event_name || event.event_name || event.type || "hook";
  const tool = event.tool_name || event.tool || hook;
  const input = event.tool_input || event.input;
  return {
    id: `hook-${event.tool_use_id || event.session_id || index}`,
    kind: hook.includes("Prompt") ? "prompt" : "tool",
    ts: toNumber(event.ts || event.timestamp_ms || event.created_at) || Date.now(),
    action: "allow",
    severity: "info",
    title: hook,
    description: commandFromInput(typeof input === "string" ? input : JSON.stringify(input || event.prompt || "")),
    path: event.cwd || "",
    tool,
    evidence: input || event.prompt || "",
    policy: event.permissionDecision || event.permission_decision || "",
    request: event.request_id ? `req_${event.request_id}` : "unknown",
    session: event.session_id || "unknown",
  };
}

function sessionSummary(sessions) {
  const current = sessions[0];
  if (!current) {
    return {
      present: false,
      title: "No active Gensee session",
      subtitle: "Waiting for local Gensee data",
      endpoint: hostname(),
      cwd: "",
      storePath: genseeHome,
    };
  }

  const active = !current.last_event_at && !current.ended_at_ms;
  return {
    present: true,
    title: `${current.agent_id || current.agent_binary || "Agent"} ${active ? "active" : "last run"}`,
    subtitle: current.sandbox_profile || current.mode || current.workspace_mode || "local profile",
    endpoint: hostname(),
    cwd: current.cwd || current.repo_path || "",
    storePath: genseeHome,
  };
}

function buildSurfaces(events, artifacts) {
  const countBy = (predicate) => events.filter(predicate).length;
  return [
    {
      key: "workspace",
      title: "Workspace filesystem",
      detail: "Read/write/copy/delete intent",
      count: countBy((event) => event.kind === "file" || /file|write|read|delete|rename/i.test(event.title)),
    },
    {
      key: "secrets",
      title: "Credential paths",
      detail: ".ssh, .aws, .kube, .env",
      count: countBy((event) => /ssh|aws|kube|env|secret|credential/i.test(`${event.path} ${event.title}`)),
    },
    {
      key: "scripts",
      title: "Executable artifacts",
      detail: "Digest-verified pre-exec checks",
      count: artifacts.filter((artifact) => artifact.is_persistent_target || /script|exec|\.sh|\.py|\.js/i.test(artifact.uri || "")).length,
    },
    {
      key: "network",
      title: "Metadata endpoints",
      detail: "IMDS and cloud internals",
      count: countBy((event) => /169\.254\.169\.254|metadata|network|curl|wget/i.test(`${event.description} ${event.title}`)),
    },
  ];
}

function decisionCounts(events) {
  const counts = { allow: 0, ask: 0, deny: 0, warn: 0 };
  for (const event of events) {
    if (event.action === "deny" || event.action === "block") counts.deny += 1;
    else if (event.action === "ask") counts.ask += 1;
    else if (event.action === "warn") counts.warn += 1;
    else if (event.action === "allow") counts.allow += 1;
    else counts.warn += 1;
  }
  return {
    total: events.length,
    allow: counts.allow,
    ask: counts.ask,
    deny: counts.deny,
    warn: counts.warn,
  };
}

const emptySqlite = { source: "jsonl", alerts: [], agentEvents: [], systemEvents: [], sessions: [], artifacts: [], relations: [] };

// Whether `column` exists on `table` — the dashboard reads SQLite directly, so
// a store last opened by an older gensee binary may predate a column added by a
// later Rust migration (e.g. agent_events.tool_use_id). Returns false on any
// error (missing table, locked db) so callers can degrade rather than throw.
async function tableHasColumn(table, column) {
  try {
    const cols = await sqliteJson(`PRAGMA table_info(${table})`);
    return Array.isArray(cols) && cols.some((c) => c.name === column);
  } catch {
    return false;
  }
}

// Whether `table` exists at all (migration-created tables like human_feedback
// are absent on a store last opened by an older binary).
async function tableExists(table) {
  try {
    const cols = await sqliteJson(`PRAGMA table_info(${table})`);
    return Array.isArray(cols) && cols.length > 0;
  } catch {
    return false;
  }
}

async function loadSqliteData(errors) {
  if (!(await pathExists(dbPath))) return emptySqlite;

  try {
    // tool_use_id was added to agent_events by a later migration; an older
    // sqlite-only store lacks it. Select NULL for it there so the query (and the
    // whole dashboard read) doesn't fail with "no such column".
    const hasToolUseId = await tableHasColumn("agent_events", "tool_use_id");
    const toolUseIdCol = hasToolUseId ? "tool_use_id" : "NULL AS tool_use_id";
    const [alerts, agentEvents, systemEvents, sessions, artifacts, relations] = await Promise.all([
      sqliteJson(`SELECT alert_id, alerts.request_id, entity_kind, entity_id, severity, action, rule_id, message, path, evidence, created_at, requests.session_id FROM alerts LEFT JOIN requests ON requests.request_id = alerts.request_id ORDER BY created_at DESC, alert_id DESC LIMIT 200`),
      sqliteJson(`SELECT event_id, pid, agent_events.request_id, requests.session_id, ts, source, type, cwd, permission_mode, tool_name, tool_input, ${toolUseIdCol} FROM agent_events LEFT JOIN requests ON requests.request_id = agent_events.request_id ORDER BY ts DESC, event_id DESC LIMIT 200`),
      sqliteJson(`SELECT event_id, pid, request_id, ts, source, type, cwd, args FROM system_events ORDER BY ts DESC, event_id DESC LIMIT 200`),
      sqliteJson(`SELECT session_id, agent_id, first_event_at, last_event_at, flagged FROM sessions ORDER BY COALESCE(last_event_at, first_event_at) DESC LIMIT 20`),
      sqliteJson(`SELECT kind, uri, current_digest, last_seen_at, last_modified_at, last_modified_source, last_modified_session_id, risk_level, risk_rule_id, is_agent_authored, is_unmatched_modified, is_memory_artifact, is_persistent_target, is_control_plane FROM artifact_facts ORDER BY last_seen_at DESC LIMIT 80`),
      // Real artifact->artifact lineage edges (copy source->dest, derived_from, …),
      // resolved to artifact URIs so the graph can connect the right nodes.
      sqliteJson(`SELECT r.relation_type AS type, r.confidence AS confidence, sa.uri AS src_uri, da.uri AS dst_uri FROM relations r JOIN artifacts sa ON r.src_kind = 'artifact' AND r.src_id = sa.artifact_id JOIN artifacts da ON r.dst_kind = 'artifact' AND r.dst_id = da.artifact_id ORDER BY r.relation_id DESC LIMIT 200`),
    ]);

    return { source: "sqlite", alerts, agentEvents, systemEvents, sessions, artifacts, relations };
  } catch (error) {
    errors.push(error.message);
    return emptySqlite;
  }
}

const severityRank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
// Multi-step / cross-session markers that, by themselves, signal a chain even
// when each step was individually allowed (read -> egress, poison -> trigger).
const chainMarker = /egress|poison|triggered|sensitive_read/;

function maxSeverity(items) {
  return items.reduce(
    (worst, item) => ((severityRank[item.severity] ?? 1) > (severityRank[worst] ?? 1) ? item.severity : worst),
    "info",
  );
}

function chainStep(alert) {
  const target = alert.command || alert.path || alert.description || alert.title;
  const tool = alert.tool && alert.tool !== "policy" ? alert.tool : "";
  return {
    ts: alert.ts,
    action: alert.action,
    severity: alert.severity,
    label: alert.title,
    rule: alert.policy,
    path: alert.path,
    tool,
    command: alert.command || "",
    summary: [tool, target].filter(Boolean).join(": ") || alert.title,
    session: alert.session,
  };
}

// Phase-1 long-horizon safety chains, computed on read from the alert stream:
//  - intra-session: a session with >=2 review/deny steps OR a multi-step marker
//    (sensitive-read -> egress, memory poison -> triggered egress);
//  - cross-session: the same path is the subject of risk alerts in >=2 sessions
//    (reuse / poisoning / tampering across runs).
function buildChains(alerts) {
  const chains = [];

  // Only consider alerts tied to a real session. alerts.request_id is nullable,
  // so the requests LEFT JOIN can yield no session_id; normalizeAlert maps those
  // to "unknown". Grouping unrelated requestless alerts under that placeholder
  // would synthesize bogus "session unknown" chains (and inflate cross-session
  // chains with a fake second session), so keep unscoped alerts out entirely.
  const scoped = alerts.filter((alert) => alert.session && alert.session !== "unknown");

  const bySession = new Map();
  scoped.forEach((alert) => {
    if (!bySession.has(alert.session)) bySession.set(alert.session, []);
    bySession.get(alert.session).push(alert);
  });
  for (const [session, items] of bySession) {
    const ordered = [...items].sort((a, b) => a.ts - b.ts);
    const steps = ordered.filter(
      (a) => a.action === "deny" || a.action === "ask" || chainMarker.test(a.policy || ""),
    );
    const hasMarker = ordered.some((a) => chainMarker.test(a.policy || ""));
    if (steps.length < 2) continue;
    chains.push({
      id: `session:${session}`,
      kind: hasMarker ? "read → exfil / poison chain" : "multi-step session",
      scope: "session",
      sessions: [session],
      severity: maxSeverity(steps),
      span: { start: steps[0].ts, end: steps[steps.length - 1].ts },
      steps: steps.map(chainStep),
    });
  }

  const byPath = new Map();
  scoped.forEach((alert) => {
    if (!alert.path || (alert.action !== "deny" && alert.action !== "ask")) return;
    if (!byPath.has(alert.path)) byPath.set(alert.path, []);
    byPath.get(alert.path).push(alert);
  });
  for (const [, items] of byPath) {
    const sessions = [...new Set(items.map((a) => a.session))];
    if (sessions.length < 2) continue;
    const ordered = [...items].sort((a, b) => a.ts - b.ts);
    chains.push({
      id: `path:${ordered[0].path}`,
      kind: "cross-session artifact reuse / tamper",
      scope: "cross-session",
      sessions,
      severity: maxSeverity(ordered),
      span: { start: ordered[0].ts, end: ordered[ordered.length - 1].ts },
      steps: ordered.map(chainStep),
    });
  }

  return chains
    .sort((a, b) => (severityRank[b.severity] - severityRank[a.severity]) || (b.span.end - a.span.end))
    .slice(0, 20);
}

async function loadState(url) {
  const params = new URL(url, "http://localhost").searchParams;
  const range = params.get("range") || "live";
  // Custom range: explicit [from, to] epoch-ms window from the dashboard.
  const from = toNumber(params.get("from"));
  const to = toNumber(params.get("to"));
  const window = range === "custom" && from !== null && to !== null ? { from, to } : null;
  const errors = [];
  let sqlite = await loadGenseeState(errors);
  let hookEvents = sqlite?.hookEvents || [];
  let workspaceEffects = sqlite?.workspaceEffects || [];
  let jsonSessions = sqlite?.jsonSessions || [];
  if (!sqlite) {
    sqlite = await loadSqliteData(errors);
    [hookEvents, workspaceEffects, jsonSessions] = await Promise.all([
      readJsonl("hooks.jsonl"),
      readJsonl("workspace-effects.jsonl"),
      readJsonl("sessions.jsonl", 40),
    ]);
  }

  const humanFeedback = sqlite.humanFeedback || await loadHumanFeedback(errors);
  const ranToolUseIds = sqlite.source === "gensee"
    ? new Set(sqlite.agentEvents.filter((event) => event.type === "PostToolUse" && event.tool_use_id).map((event) => event.tool_use_id))
    : await loadRanToolUseIds(errors);
  const sessions = sqlite.sessions.length ? sqlite.sessions : jsonSessions.reverse();

  // Map each tool call's id to the shell command that ran it, so an alert (which
  // stores only the tool_use_id in its evidence) can show the triggering command
  // rather than just the rule name. Take the literal `command` only — derived
  // file_intent rows share the tool_use_id but carry a path, not the command.
  const commandByToolUse = new Map();
  for (const event of sqlite.agentEvents) {
    const input = parseJson(event.tool_input);
    const command =
      input && typeof input === "object" ? input.command : typeof input === "string" ? input : null;
    if (event.tool_use_id && command && !commandByToolUse.has(event.tool_use_id)) {
      commandByToolUse.set(event.tool_use_id, command);
    }
  }
  const alerts = collapseMemoryPoisonAlerts(sqlite.alerts.map(normalizeAlert).map((alert) => {
    const command = alert.evidence?.tool_use_id
      ? commandByToolUse.get(alert.evidence.tool_use_id)
      : null;
    return command ? { ...alert, command } : alert;
  }));
  const agentEvents = compactAgentToolEvents(sqlite.agentEvents);
  const systemEvents = sqlite.systemEvents.map(normalizeSystemEvent);
  const effects = workspaceEffects.map(normalizeWorkspaceEffect);
  const hooks = sqlite.agentEvents.length ? [] : hookEvents.map(normalizeHookEvent);
  const agentRefusals = deriveAgentRefusalEvents(hookEvents);
  const events = [...alerts, ...agentRefusals, ...agentEvents, ...systemEvents, ...effects, ...hooks]
    .filter((event) => withinRange(event.ts, range, window))
    .sort(compareRecent)
    .slice(0, 200);

  // Derive the outcome of each `ask` from whether the tool actually ran: a
  // PostToolUse hook for the same tool_use_id means Claude Code's inline prompt
  // was approved; its absence means denied or still pending (we can't tell which
  // without a session-end signal, hence the combined label).
  for (const event of events) {
    if (event.kind === "alert" && event.action === "ask") {
      const toolUseId = event.evidence?.tool_use_id;
      event.askOutcome = toolUseId
        ? (ranToolUseIds.has(toolUseId) ? "approved" : "denied_or_pending")
        : "unknown";
    }
  }

  const queue = alerts
    .filter((alert) => actionRank.get(alert.action) >= 1)
    .filter((alert) => withinRange(alert.ts, range, window))
    .sort((a, b) => (actionRank.get(b.action) || 0) - (actionRank.get(a.action) || 0) || compareRecent(a, b))
    .slice(0, 80);

  const artifacts = sqlite.artifacts.map((artifact) => ({
    ...artifact,
    uri: artifact.uri || "",
    shortUri: shortPath(artifact.uri || ""),
  }));

  // Real lineage edges, keyed by the same full URIs the artifact nodes use.
  const lineageEdges = (sqlite.relations || [])
    .filter((relation) => relation.src_uri && relation.dst_uri)
    .map((relation) => ({
      from: relation.src_uri,
      to: relation.dst_uri,
      type: relation.type || "related",
      confidence: relation.confidence,
    }));

  return {
    meta: {
      generatedAt: Date.now(),
      source: sqlite.source,
      live: sqlite.source === "gensee" || sqlite.source === "sqlite" || hookEvents.length > 0 || workspaceEffects.length > 0,
      storePath: genseeHome,
      dbPath,
      endpoint: hostname(),
      errors,
    },
    session: sessionSummary(sessions),
    decisions: decisionCounts(events),
    surfaces: buildSurfaces(events, artifacts),
    queue,
    timeline: events,
    artifacts,
    lineageEdges,
    chains: buildChains(alerts),
    feedback: humanFeedback,
  };
}

// tool_use_ids that have a PostToolUse row = the tool actually ran. An older DB
// whose agent_events lacks tool_use_id simply yields no correlation (empty set).
async function loadRanToolUseIds(errors) {
  if (!(await pathExists(dbPath))) return new Set();
  if (!(await tableHasColumn("agent_events", "tool_use_id"))) return new Set();
  try {
    const rows = await sqliteJson(
      `SELECT DISTINCT tool_use_id AS tool_use_id FROM agent_events
       WHERE type = 'PostToolUse' AND tool_use_id IS NOT NULL`,
    );
    return new Set(rows.map((row) => row.tool_use_id));
  } catch (error) {
    errors.push(`ask-outcome: ${error.message}`);
    return new Set();
  }
}

// Recorded human verdicts (newest first), tolerant of an older DB without the
// human_feedback table (returns []). The frontend keys the latest per event.
async function loadHumanFeedback(errors) {
  if (!(await pathExists(dbPath))) return [];
  if (!(await tableExists("human_feedback"))) return [];
  try {
    return await sqliteJson(
      `SELECT event_key, tool_use_id, session_id, gensee_action, human_verdict, label, rule_id, path, note, created_at
       FROM human_feedback ORDER BY created_at DESC, feedback_id DESC LIMIT 200`,
    );
  } catch (error) {
    // Missing table on an older store, etc. — non-fatal for the rest of the view.
    errors.push(`feedback: ${error.message}`);
    return [];
  }
}

const server = createServer(async (request, response) => {
  if (!isAllowedHost(request.headers.host)) {
    response.writeHead(403);
    response.end("Forbidden host");
    return;
  }

  let url;
  try {
    url = parseRequestUrl(request.url);
  } catch (error) {
    response.writeHead(400);
    response.end(error.message);
    return;
  }

  if (request.method === "GET" && url.pathname === "/api/state") {
    try {
      sendJson(response, 200, await loadState(request.url || "/api/state"));
    } catch (error) {
      sendJson(response, 500, { error: error.message });
    }
    return;
  }

  if (url.pathname === "/api/policy") {
    if (request.method === "GET") {
      try {
        const customized = await pathExists(policyFilePath);
        const content = customized
          ? await readFile(policyFilePath, "utf8")
          : await bundledDefaultPolicy();
        sendJson(response, 200, { path: policyFilePath, customized, content });
      } catch (error) {
        sendJson(response, 500, { error: error.message });
      }
      return;
    }
    if (request.method === "POST" || request.method === "PUT") {
      // CSRF: require a custom header (forces a CORS preflight cross-origin,
      // which we never approve — so a no-CORS form/`fetch` POST from a malicious
      // page can't set it) AND reject a non-loopback Origin/Referer.
      if (!isWriteAllowed(request)) {
        sendJson(response, 403, { ok: false, error: "forbidden: cross-origin or missing X-Gensee-Dashboard header" });
        return;
      }
      try {
        const body = await readBody(request);
        let parsed;
        try {
          parsed = JSON.parse(body);
        } catch (error) {
          sendJson(response, 400, { ok: false, error: `not valid JSON: ${error.message}` });
          return;
        }
        // Full validation via the same engine as `gensee policy validate`,
        // when the binary is available; else fall back to a required-key check.
        const verdict = await validatePolicy(body);
        if (!verdict.ok) {
          sendJson(response, 400, { ok: false, error: verdict.error });
          return;
        }
        await mkdir(genseeHome, { recursive: true });
        await writeFile(policyFilePath, `${JSON.stringify(parsed, null, 2)}\n`, "utf8");
        sendJson(response, 200, { ok: true, path: policyFilePath, validatedBy: verdict.validatedBy });
      } catch (error) {
        sendJson(response, 500, { ok: false, error: error.message });
      }
      return;
    }
  }

  if (url.pathname === "/api/review") {
    if (request.method !== "POST" && request.method !== "PUT") {
      sendJson(response, 405, { ok: false, error: "use POST" });
      return;
    }
    // Same CSRF guard as /api/policy: custom header + loopback Origin/Referer.
    if (!isWriteAllowed(request)) {
      sendJson(response, 403, { ok: false, error: "forbidden: cross-origin or missing X-Gensee-Dashboard header" });
      return;
    }
    try {
      const body = await readBody(request);
      let parsed;
      try {
        parsed = JSON.parse(body);
      } catch (error) {
        sendJson(response, 400, { ok: false, error: `not valid JSON: ${error.message}` });
        return;
      }
      const verdict = String(parsed.verdict || "");
      if (!["agree", "allow", "deny"].includes(verdict)) {
        sendJson(response, 400, { ok: false, error: "verdict must be agree, allow, or deny" });
        return;
      }
      const args = ["feedback", "record", "--verdict", verdict];
      const flagFor = {
        gensee: "gensee",
        eventKey: "event-key",
        toolUseId: "tool-use-id",
        session: "session",
        rule: "rule",
        path: "path",
        note: "note",
        label: "label",
      };
      for (const [key, flag] of Object.entries(flagFor)) {
        const value = parsed[key];
        if (value !== undefined && value !== null && String(value) !== "") {
          args.push(`--${flag}`, String(value));
        }
      }
      const result = await genseeRun(args);
      if (!result.ok) {
        sendJson(response, 500, { ok: false, error: result.error });
        return;
      }
      sendJson(response, 200, { ok: true, recorded: result.stdout.trim() });
    } catch (error) {
      sendJson(response, 500, { ok: false, error: error.message });
    }
    return;
  }

  if (request.method !== "GET" && request.method !== "HEAD") {
    response.writeHead(405);
    response.end("Method not allowed");
    return;
  }

  let filePath;
  try {
    filePath = await fileForRequest(request.url || "/");
  } catch (error) {
    if (error instanceof BadRequestError) {
      response.writeHead(400);
      response.end(error.message);
      return;
    }
    response.writeHead(500);
    response.end("Server error");
    return;
  }
  if (!filePath) {
    response.writeHead(403);
    response.end("Forbidden");
    return;
  }

  response.setHeader("Content-Type", contentTypes.get(extname(filePath)) || "application/octet-stream");
  if (request.method === "HEAD") {
    response.end();
    return;
  }

  createReadStream(filePath)
    .on("error", () => {
      response.writeHead(404);
      response.end("Not found");
    })
    .pipe(response);
});

server.listen(port, bindHost, () => {
  console.log(`Gensee Crate dashboard: http://${bindHost}:${port}/`);
  console.log(`Reading local store: ${genseeHome}`);
});
