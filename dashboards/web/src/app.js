const state = {
  data: null,
  range: "live",
  rangeFrom: null,
  rangeTo: null,
  filter: "all",
  timelinePage: 1,
  paused: false,
  selectedEventId: null,
  selectedArtifactUri: "",
  verdicts: loadVerdicts(),
  policyWorking: null,
  pollTimer: null,
  lastGoodSession: null,
  lastLineageSig: "",
};

const views = document.querySelectorAll(".view");
const navItems = document.querySelectorAll(".nav-item");
const rangeButtons = document.querySelectorAll("[data-range]");
const filterButtons = document.querySelectorAll("[data-filter]");

const els = {
  endpointStatus: document.querySelector("#endpoint-status"),
  endpointName: document.querySelector("#endpoint-name"),
  endpointCwd: document.querySelector("#endpoint-cwd"),
  endpointStore: document.querySelector("#endpoint-store"),
  rangeCustomBtn: document.querySelector("#range-custom"),
  customRange: document.querySelector("#custom-range"),
  rangeFrom: document.querySelector("#range-from"),
  rangeTo: document.querySelector("#range-to"),
  rangeApply: document.querySelector("#range-apply"),
  rangeStatus: document.querySelector("#range-status"),
  eventTotal: document.querySelector("#event-total"),
  allowCount: document.querySelector("#allow-count"),
  askCount: document.querySelector("#ask-count"),
  warnCount: document.querySelector("#warn-count"),
  denyCount: document.querySelector("#deny-count"),
  eventsChart: document.querySelector("#events-chart"),
  ratioAllow: document.querySelector("#ratio-allow"),
  ratioAsk: document.querySelector("#ratio-ask"),
  ratioWarn: document.querySelector("#ratio-warn"),
  ratioDeny: document.querySelector("#ratio-deny"),
  surfacesActive: document.querySelector("#surfaces-active"),
  surfaceList: document.querySelector("#surface-list"),
  timelineList: document.querySelector("#timeline-list"),
  timelineSelectedTitle: document.querySelector("#timeline-selected-title"),
  inspectDecision: document.querySelector("#inspect-decision"),
  inspectCommand: document.querySelector("#inspect-command"),
  inspectOutcome: document.querySelector("#inspect-outcome"),
  timelineSelectedRequest: document.querySelector("#timeline-selected-request"),
  timelineSelectedArtifact: document.querySelector("#timeline-selected-artifact"),
  timelineSelectedConfidence: document.querySelector("#timeline-selected-confidence"),
  verdictCurrent: document.querySelector("#verdict-current"),
  verdictAgree: document.querySelector("#verdict-agree"),
  verdictAllow: document.querySelector("#verdict-allow"),
  verdictDeny: document.querySelector("#verdict-deny"),
  verdictNote: document.querySelector("#verdict-note"),
  verdictClear: document.querySelector("#verdict-clear"),
  lineageSearch: document.querySelector("#lineage-search"),
  lineageGraphContent: document.querySelector("#lineage-graph-content"),
  factUri: document.querySelector("#fact-uri"),
  factModifier: document.querySelector("#fact-modifier"),
  factRegistry: document.querySelector("#fact-registry"),
  factRisk: document.querySelector("#fact-risk"),
  sqlPanel: document.querySelector("#sql-panel"),
  policySettings: document.querySelector("#policy-settings"),
  policyArtifacts: document.querySelector("#policy-artifacts"),
  policyRules: document.querySelector("#policy-rules"),
  policySettingsStatus: document.querySelector("#policy-settings-status"),
  policyDocEditor: document.querySelector("#policy-doc-editor"),
  policyDocSource: document.querySelector("#policy-doc-source"),
  policyDocStatus: document.querySelector("#policy-doc-status"),
  policyDocReload: document.querySelector("#policy-doc-reload"),
  policyDocSave: document.querySelector("#policy-doc-save"),
  mtpTimeline: document.querySelector("#mtp-timeline"),
  toast: document.querySelector("#toast"),
};

// Settable policy keys, grouped for the Policy tab form. Mirrors the CLI's
// SETTABLE_POLICY_KEYS (the env-knob replacements); rule lists are edited as raw
// JSON in the Advanced panel. Each item: dotted key + type + label + help.
const POLICY_SETTINGS = [
  {
    group: "Resource governance",
    hint: "Per-tool and per-session quotas. 0 / blank leaves the built-in default.",
    items: [
      { key: "resource_governance.max_read_bytes", type: "int", label: "Max read bytes", help: "Largest single file read the shield allows." },
      { key: "resource_governance.max_file_subjects_per_tool", type: "int", label: "Max file subjects / tool", help: "File paths a single tool call may touch." },
      { key: "resource_governance.max_shell_segments_per_tool", type: "int", label: "Max shell segments / tool", help: "Chained commands (|, &&, ;) per Bash call." },
      { key: "resource_governance.max_tool_calls_per_session", type: "int", label: "Max tool calls / session", help: "Total tool calls before the session is throttled." },
      { key: "resource_governance.max_network_egress_per_session", type: "int", label: "Max network egress / session", help: "Outbound network operations per session." },
      { key: "resource_governance.max_file_accessed_rate_per_min", type: "float", label: "Max file access rate / min", help: "File operations per minute before flagging." },
      { key: "resource_governance.max_network_rate_per_min", type: "float", label: "Max network rate / min", help: "Network operations per minute before flagging." },
    ],
  },
  {
    group: "Network egress",
    hint: "Where the agent may reach out, and whether it must go through a proxy.",
    items: [
      { key: "egress.allow_hosts", type: "list", label: "Allowed hosts", help: "Hosts the agent may connect to. Everything else is denied." },
      { key: "egress.proxy_url", type: "string", label: "Proxy URL", help: "Egress proxy to route outbound traffic through." },
      { key: "egress.require_proxy", type: "bool", label: "Require proxy", help: "Deny direct egress that bypasses the proxy." },
    ],
  },
  {
    group: "Runtime",
    hint: "",
    items: [
      { key: "runtime.max_runtime_seconds", type: "int", label: "Max runtime (seconds)", help: "Wall-clock cap for a guarded run." },
    ],
  },
  {
    group: "Enforcement",
    hint: "",
    items: [
      { key: "enforcement.noninteractive", type: "bool", label: "Non-interactive fail-closed", help: "When no human can answer, escalate medium+ asks to deny instead of allowing." },
    ],
  },
  {
    group: "Allowlisted paths",
    hint: "Path prefixes that are always trusted (e.g. shared template dirs).",
    items: [
      { key: "allow_path_prefixes", type: "list", label: "Allowed path prefixes", help: "Absolute path prefixes exempt from secret/sensitive checks." },
    ],
  },
];

function getDotted(obj, key) {
  return key.split(".").reduce((cur, part) => (cur == null ? undefined : cur[part]), obj);
}

function setDotted(obj, key, value) {
  const parts = key.split(".");
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i += 1) {
    if (cur[parts[i]] == null || typeof cur[parts[i]] !== "object") cur[parts[i]] = {};
    cur = cur[parts[i]];
  }
  cur[parts[parts.length - 1]] = value;
}

// Human verdicts are recorded dashboard-side only for now (keyed by event id).
// The server-side feedback store + false-positive labelling lands in a follow-up.
const VERDICTS_KEY = "gensee-crate-dashboard-verdicts";

function loadVerdicts() {
  try {
    const parsed = JSON.parse(localStorage.getItem(VERDICTS_KEY) || "{}");
    return new Map(Object.entries(parsed));
  } catch {
    return new Map();
  }
}

function saveVerdicts() {
  localStorage.setItem(VERDICTS_KEY, JSON.stringify(Object.fromEntries(state.verdicts)));
}

// How a recorded human verdict relates to what the shield decided:
//  - agree           -> human confirms the shield
//  - allow over deny/ask -> candidate false positive (shield was too strict)
//  - deny over allow     -> candidate false negative / miss (shield was too lax)
function verdictLabel(genseeAction, humanVerdict) {
  if (humanVerdict === "agree") return "confirmed";
  const gensee = displayAction(genseeAction);
  if (humanVerdict === "allow" && (gensee === "deny" || gensee === "ask")) return "false_positive";
  if (humanVerdict === "deny" && (gensee === "allow" || gensee === "watch")) return "false_negative";
  return "override";
}

function text(value, fallback = "-") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

function formatTime(ts) {
  const date = new Date(Number(ts));
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function formatDateTime(ts) {
  const date = new Date(Number(ts));
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function parseDateTimeInput(input) {
  if (!input) return Number.NaN;
  for (const candidate of [input.value, input.getAttribute("value")]) {
    const value = normalizeDateInputText(candidate);
    if (!value) continue;
    const isoLocal = value.match(
      /^(\d{4})-(\d{2})-(\d{2})[T\s](\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?$/
    );
    if (isoLocal) {
      const [, year, month, day, hour, minute, second = "0"] = isoLocal;
      const date = new Date(
        Number(year),
        Number(month) - 1,
        Number(day),
        Number(hour),
        Number(minute),
        Number(second)
      );
      return date.getTime();
    }
    const localized = value
      .replace(/[\u00a0\u202f]/g, " ")
      .replace(/\s+/g, " ")
      .match(/^(\d{1,2})\/(\d{1,2})\/(\d{4}),?\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([AP]M)$/i);
    if (localized) {
      const [, month, day, year, rawHour, minute, second = "0", meridiem] = localized;
      let hour = Number(rawHour) % 12;
      if (meridiem.toUpperCase() === "PM") hour += 12;
      const date = new Date(
        Number(year),
        Number(month) - 1,
        Number(day),
        hour,
        Number(minute),
        Number(second)
      );
      return date.getTime();
    }
    const parsed = Date.parse(value.replace(/[\u00a0\u202f]/g, " ").replace(/\s+/g, " "));
    if (Number.isFinite(parsed)) return parsed;
  }
  return Number.isFinite(input.valueAsNumber) ? input.valueAsNumber : Number.NaN;
}

function normalizeDateInputText(value) {
  return String(value || "")
    .normalize("NFKC")
    .replace(/[\u200e\u200f\u061c\u2066-\u2069]/g, "")
    .replace(/[\u00a0\u202f]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function formatDateInputValue(ts) {
  const date = new Date(Number(ts));
  if (Number.isNaN(date.getTime())) return "";
  const pad = (value) => String(value).padStart(2, "0");
  const hour24 = date.getHours();
  const hour12 = hour24 % 12 || 12;
  const meridiem = hour24 >= 12 ? "PM" : "AM";
  return `${pad(date.getMonth() + 1)}/${pad(date.getDate())}/${date.getFullYear()}, ${pad(hour12)}:${pad(date.getMinutes())} ${meridiem}`;
}

function eventTimeExtent() {
  const times = (state.data?.timeline || []).map((event) => Number(event.ts)).filter(Number.isFinite);
  if (!times.length) return null;
  return [Math.min(...times), Math.max(...times)];
}

function seedCustomRangeInputs() {
  if (!els.rangeFrom || !els.rangeTo) return;
  if (els.rangeFrom.value && els.rangeTo.value) return;
  let from = state.rangeFrom;
  let to = state.rangeTo;
  if (from === null || to === null) {
    const extent = eventTimeExtent();
    if (extent) {
      [from, to] = extent;
    } else {
      to = Date.now();
      from = to - 60 * 60 * 1000;
    }
  }
  if (!els.rangeFrom.value) els.rangeFrom.value = formatDateInputValue(from);
  if (!els.rangeTo.value) els.rangeTo.value = formatDateInputValue(to);
}

function displayAction(action) {
  if (action === "block") return "deny";
  return action || "watch";
}

function eventClass(action) {
  const normalized = displayAction(action);
  if (normalized === "deny" || normalized === "ask" || normalized === "warn" || normalized === "allow") return normalized;
  return "neutral";
}

function createEl(tag, className, value) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (value !== undefined) element.textContent = text(value, "");
  return element;
}

function clear(element) {
  while (element.firstChild) element.removeChild(element.firstChild);
}

function showToast(message) {
  els.toast.textContent = message;
  els.toast.hidden = false;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => {
    els.toast.hidden = true;
  }, 2600);
}

function setView(viewName) {
  views.forEach((view) => {
    view.classList.toggle("active", view.id === `view-${viewName}`);
  });

  navItems.forEach((item) => {
    const active = item.dataset.view === viewName;
    item.classList.toggle("active", active);
    if (active) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  });

  if (viewName === "policy") loadPolicyDocument();
}

async function loadPolicyDocument() {
  if (!els.policyDocEditor) return;
  els.policyDocStatus.textContent = "";
  if (els.policySettingsStatus) els.policySettingsStatus.textContent = "";
  try {
    const response = await fetch("/api/policy", { headers: { Accept: "application/json" }, cache: "no-store" });
    if (!response.ok) throw new Error(`policy request failed: ${response.status}`);
    const data = await response.json();
    els.policyDocEditor.value = data.content || "";
    els.policyDocSource.textContent = data.customized
      ? `Editing ${data.path}`
      : "Bundled default (not yet customized — saving writes a copy)";
    els.policyDocEditor.disabled = data.content == null;

    // A single working clone of the whole document. The settings form, artifact
    // editors, and rule editors all mutate this object directly; Save serializes
    // it and Reload re-fetches, so edits are discardable.
    if (data.content) {
      try {
        state.policyWorking = JSON.parse(data.content);
      } catch {
        state.policyWorking = null;
      }
    } else {
      state.policyWorking = null;
      els.policyDocStatus.textContent = "Could not load the default policy (gensee binary not found).";
    }
    renderPolicy();
  } catch (error) {
    els.policyDocSource.textContent = "Failed to load policy";
    els.policyDocStatus.textContent = error.message;
    if (els.policySettingsStatus) els.policySettingsStatus.textContent = error.message;
  }
}

// POST a full policy JSON string to the server (CSRF-guarded, validated by the
// real engine server-side). Returns {ok, data}.
async function postPolicy(jsonText) {
  const response = await fetch("/api/policy", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "X-Gensee-Dashboard": "1",
    },
    body: jsonText,
  });
  const data = await response.json().catch(() => ({}));
  return { ok: response.ok && data.ok !== false, status: response.status, data };
}

// Save the working policy document (settings form, artifact defs, and rule
// edits all mutate it in place).
async function savePolicySettings() {
  if (!state.policyWorking) {
    els.policySettingsStatus.textContent = "No policy loaded yet.";
    return;
  }
  els.policySettingsStatus.textContent = "Saving…";
  try {
    const { ok, status, data } = await postPolicy(`${JSON.stringify(state.policyWorking, null, 2)}\n`);
    if (!ok) {
      els.policySettingsStatus.textContent = `Not saved: ${data.error || status}`;
      return;
    }
    els.policySettingsStatus.textContent = `Saved to ${data.path} (auto-loaded on next hook).`;
    showToast("Policy settings saved");
    loadPolicyDocument();
  } catch (error) {
    els.policySettingsStatus.textContent = error.message;
  }
}

async function savePolicyDocument() {
  if (!els.policyDocEditor) return;
  els.policyDocStatus.textContent = "Saving…";
  try {
    const { ok, status, data } = await postPolicy(els.policyDocEditor.value);
    if (!ok) {
      els.policyDocStatus.textContent = `Not saved: ${data.error || status}`;
      return;
    }
    els.policyDocStatus.textContent = `Saved to ${data.path} (auto-loaded on next hook).`;
    showToast("Policy saved");
    loadPolicyDocument();
  } catch (error) {
    els.policyDocStatus.textContent = error.message;
  }
}

async function fetchState() {
  // Keep the server read unfiltered so one client-side source of truth drives
  // every Activity widget: cards, chart, ratio bar, inspector, and event list.
  const response = await fetch("/api/state?range=live", {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`state request failed: ${response.status}`);
  state.data = await response.json();
  // Sticky session: a poll where the sessions query is momentarily empty
  // returns a "No active session" placeholder; keep the last real session so the
  // sidebar endpoint doesn't flip to the placeholder on every such refresh.
  const session = state.data.session;
  if (session && session.present) state.lastGoodSession = session;
  else if (state.lastGoodSession) state.data.session = state.lastGoodSession;
  if (!state.selectedEventId) {
    // Prefer the highest-severity event (deny > ask > …) so the inspector opens
    // on something actionable rather than the most recent allow.
    const events = state.data.timeline || [];
    const firstFlagged = events.find((event) => displayAction(event.action) === "deny")
      || events.find((event) => displayAction(event.action) === "ask")
      || events.find((event) => displayAction(event.action) === "warn");
    state.selectedEventId = (firstFlagged || events[0])?.id || null;
  }
  applyServerFeedback();
  reconcileTimelinePage();
  render();
}

function startPolling() {
  window.clearInterval(state.pollTimer);
  state.pollTimer = window.setInterval(() => {
    if (!state.paused) {
      fetchState().catch((error) => renderLoadError(error));
    }
  }, 12000);
}

function renderLoadError(error) {
  els.endpointStatus.classList.remove("online");
  showToast(`Unable to read local Gensee data: ${error.message}`);
}

function selectedEvent() {
  const events = visibleTimeline();
  return events.find((event) => event.id === state.selectedEventId) || events[0] || null;
}

function activeRangeWindow() {
  const now = state.data?.meta?.generatedAt || Date.now();
  if (state.range === "custom" && state.rangeFrom !== null && state.rangeTo !== null) {
    return [state.rangeFrom, state.rangeTo];
  }
  if (state.range === "1h") return [now - 60 * 60 * 1000, now];
  if (state.range === "24h") return [now - 24 * 60 * 60 * 1000, now];
  return null;
}

function isInActiveRange(event) {
  const window = activeRangeWindow();
  if (!window) return true;
  const ts = Number(event.ts);
  if (!Number.isFinite(ts)) return true;
  return ts >= window[0] && ts <= window[1];
}

function rangeFilteredTimeline() {
  return (state.data?.timeline || []).filter(isInActiveRange);
}

function visibleTimeline() {
  const timeline = rangeFilteredTimeline();
  if (state.filter === "all") return timeline;
  // Decision-type filter: allow / ask / deny.
  return timeline.filter((event) => displayAction(event.action) === state.filter);
}

function render() {
  if (!state.data) return;
  renderShell();
  renderRangeStatus();
  renderDecisions();
  renderEventsChart();
  renderSurfaces();
  renderTimeline();
  renderLineage();
  renderProvenanceTimeline();
  // Policy form is rendered on demand (tab open / load), not on every poll, so
  // a 12s refresh never clobbers in-progress edits.
}

function renderRangeStatus(message) {
  if (!els.rangeStatus) return;
  if (message) {
    els.rangeStatus.textContent = message;
    return;
  }
  if (state.range === "custom") {
    if (state.rangeFrom !== null && state.rangeTo !== null) {
      const count = rangeFilteredTimeline().length;
      els.rangeStatus.textContent = `Custom: ${formatDateTime(state.rangeFrom)} to ${formatDateTime(state.rangeTo)} (${count} event${count === 1 ? "" : "s"})`;
    } else {
      els.rangeStatus.textContent = "Custom range selected; enter start and end, then Apply";
    }
    return;
  }
  if (state.range === "1h") {
    els.rangeStatus.textContent = `Showing last hour (${rangeFilteredTimeline().length} events)`;
  } else if (state.range === "24h") {
    els.rangeStatus.textContent = `Showing last 24 hours (${rangeFilteredTimeline().length} events)`;
  } else {
    els.rangeStatus.textContent = "Showing all loaded events";
  }
}

// Bar chart of event volume over time, stacked by decision. Uses the selected
// time window rather than just event extent so time-range controls visibly
// reshape the chart even when the window has sparse activity.
const CHART_BUCKET_MS = 5 * 60 * 1000;
const CHART_MAX_BUCKETS = 288;
const TIMELINE_PAGE_SIZE = 25;

function renderEventsChart() {
  if (!els.eventsChart) return;
  clear(els.eventsChart);
  const events = visibleTimeline().filter((event) =>
    ["allow", "ask", "warn", "deny", "block"].includes(displayAction(event.action))
  );
  if (!events.length) {
    els.eventsChart.append(emptyState("No allow/ask/warn/deny events in this window"));
    return;
  }

  const [windowStart, windowEnd] = chartWindow(events);
  const bucketMs = chartBucketMs(windowStart, windowEnd);
  const counts = new Map();
  for (const event of events) {
    const key = Math.floor((Number(event.ts) || 0) / bucketMs);
    if (!counts.has(key)) counts.set(key, { allow: 0, ask: 0, warn: 0, deny: 0 });
    const bucket = counts.get(key);
    const action = displayAction(event.action);
    if (action === "deny") bucket.deny += 1;
    else if (action === "ask") bucket.ask += 1;
    else if (action === "warn") bucket.warn += 1;
    else if (action === "allow") bucket.allow += 1;
  }
  const minKey = Math.floor(windowStart / bucketMs);
  const maxKey = Math.max(minKey, Math.ceil(windowEnd / bucketMs) - 1);

  let peak = 1;
  for (let key = minKey; key <= maxKey; key += 1) {
    const bucket = counts.get(key);
    if (bucket) peak = Math.max(peak, bucket.allow + bucket.ask + bucket.warn + bucket.deny);
  }

  const grid = createEl("div", "chart-bars");
  grid.style.gridTemplateColumns = `repeat(${maxKey - minKey + 1}, minmax(2px, 1fr))`;
  for (let key = minKey; key <= maxKey; key += 1) {
    const bucket = counts.get(key) || { allow: 0, ask: 0, warn: 0, deny: 0 };
    const total = bucket.allow + bucket.ask + bucket.warn + bucket.deny;
    const col = createEl("div", "chart-col");
    const bar = createEl("div", "chart-bar");
    bar.style.height = `${(total / peak) * 100}%`;
    for (const type of ["deny", "warn", "ask", "allow"]) {
      if (bucket[type] > 0) {
        const seg = createEl("div", `chart-seg ${type}`);
        seg.style.flexGrow = String(bucket[type]);
        bar.append(seg);
      }
    }
    col.append(bar);
    col.title = `${formatTime(key * bucketMs)} · ${total} event${total === 1 ? "" : "s"} (allow ${bucket.allow}, ask ${bucket.ask}, warn ${bucket.warn}, deny ${bucket.deny})`;
    grid.append(col);
  }

  const axis = createEl("div", "chart-axis");
  for (const tick of chartTimeTicks(windowStart, windowEnd)) {
    const mark = createEl("span", "chart-x-tick");
    mark.style.left = `${tick.position * 100}%`;
    mark.append(createEl("i", "chart-tick-mark"));
    mark.append(createEl("span", "chart-tick-label", formatTime(tick.ts)));
    axis.append(mark);
  }

  const yAxis = createEl("div", "chart-y-axis");
  yAxis.append(createEl("span", "chart-y-label", `Events / ${formatBucketLabel(bucketMs)}`));
  yAxis.append(createEl("span", "chart-y-tick top", String(peak)));
  yAxis.append(createEl("span", "chart-y-tick middle", String(Math.floor(peak / 2))));
  yAxis.append(createEl("span", "chart-y-tick bottom", "0"));

  const plot = createEl("div", "chart-plot");
  plot.append(grid, axis);
  const body = createEl("div", "chart-body");
  body.append(yAxis, plot);
  els.eventsChart.append(body);
}

function chartWindow(events) {
  const activeWindow = activeRangeWindow();
  if (activeWindow) return activeWindow;
  const times = events.map((event) => Number(event.ts)).filter(Number.isFinite);
  const min = Math.min(...times);
  const max = Math.max(...times);
  return [min, Math.max(max + CHART_BUCKET_MS, min + CHART_BUCKET_MS)];
}

function chartTimeTicks(start, end) {
  const tickCount = 5;
  if (end <= start) return [{ ts: start, position: 0 }];
  return Array.from({ length: tickCount }, (_, index) => {
    const position = index / (tickCount - 1);
    return { ts: start + (end - start) * position, position };
  });
}

function chartBucketMs(start, end) {
  const bucketCount = Math.max(1, Math.ceil((end - start) / CHART_BUCKET_MS));
  if (bucketCount <= CHART_MAX_BUCKETS) return CHART_BUCKET_MS;
  return Math.ceil(bucketCount / CHART_MAX_BUCKETS) * CHART_BUCKET_MS;
}

function formatBucketLabel(ms) {
  const minutes = Math.round(ms / 60000);
  if (minutes < 60) return `${minutes} min`;
  const hours = minutes / 60;
  return Number.isInteger(hours) ? `${hours} hr` : `${hours.toFixed(1)} hr`;
}

// Render multi-turn / cross-session chains as horizontal timelines (one lane
// per chain) below the artifact provenance graph. Each event is a box anchored
// at its clock-time position on a shared time axis.
function renderProvenanceTimeline() {
  if (!els.mtpTimeline) return;
  clear(els.mtpTimeline);
  const chains = state.data.chains || [];
  if (!chains.length) {
    els.mtpTimeline.append(emptyState("No multi-turn or cross-session sequences detected yet"));
    return;
  }
  chains.forEach((chain) => els.mtpTimeline.append(buildProvenanceLane(chain)));
}

function buildProvenanceLane(chain) {
  const lane = createEl("div", `mtp-lane scope-${chain.scope || "session"} sev-${chain.severity || "info"}`);

  const head = createEl("div", "mtp-lane-head");
  head.append(createEl("span", "mtp-kind", chain.kind));
  const scope =
    chain.scope === "cross-session"
      ? `${chain.sessions.length} sessions`
      : `session ${chain.sessions[0]}`;
  head.append(createEl("span", "mtp-scope", scope));
  head.append(
    createEl("span", "mtp-span", `${formatTime(chain.span.start)} – ${formatTime(chain.span.end)}`)
  );
  lane.append(head);

  const track = createEl("div", "mtp-track");
  const positions = timelinePositions(chain.steps);
  const rows = timelineRows(positions);
  const rowCount = Math.max(...rows, 0) + 1;
  track.style.setProperty("--mtp-track-height", `${118 + (rowCount - 1) * 74}px`);
  chain.steps.forEach((step, i) => {
    const pos = positions[i];
    const row = rows[i] || 0;
    // Anchor the callout box so it never clips at the track edges.
    const anchor = pos < 0.12 ? "anchor-start" : pos > 0.88 ? "anchor-end" : "";
    const event = createEl("div", `mtp-event ${displayAction(step.action)} ${anchor}`.trim());
    event.style.left = `${(pos * 100).toFixed(2)}%`;
    event.style.setProperty("--mtp-box-offset", `${62 + row * 74}px`);
    event.style.setProperty("--mtp-stem-height", `${16 + row * 74}px`);

    const box = createEl("div", "mtp-box");
    box.append(createEl("span", "mtp-box-label", step.summary || step.command || step.path || step.label));
    const detail = [step.label, step.rule, chain.scope === "cross-session" ? `session ${step.session}` : ""]
      .filter(Boolean)
      .join(" · ");
    if (detail) box.append(createEl("small", "mtp-box-detail", detail));
    box.title = [
      step.tool,
      step.command,
      step.path && shortPath(step.path),
      step.label,
      step.rule,
      formatTime(step.ts),
    ]
      .filter(Boolean)
      .join("\n");
    event.append(box);
    event.append(createEl("span", "mtp-dot"));
    event.append(createEl("time", "mtp-tick", formatTime(step.ts)));
    track.append(event);
  });
  lane.append(track);
  return lane;
}

// Map step timestamps onto 0..1 positions along a lane. Positions track real
// clock time, but consecutive events are de-clustered by a minimum gap so boxes
// that fire milliseconds apart (synthetic or rapid tool bursts) stay readable;
// chronological order and relative spacing are preserved where there's room.
function timelinePositions(steps) {
  const n = steps.length;
  if (n === 0) return [];
  if (n === 1) return [0.5];
  const times = steps.map((s) => Number(s.ts) || 0);
  const min = Math.min(...times);
  const span = Math.max(...times) - min;
  const minGap = Math.min(0.16, 0.92 / (n - 1));
  const pos = new Array(n);
  for (let i = 0; i < n; i++) {
    const t = span > 0 ? (times[i] - min) / span : i / (n - 1);
    pos[i] = i === 0 ? t : Math.max(t, pos[i - 1] + minGap);
  }
  const last = pos[n - 1];
  if (last > 1) for (let i = 0; i < n; i++) pos[i] /= last;
  return pos;
}

function timelineRows(positions) {
  const rows = [];
  const rowEnds = [];
  const minGap = 0.14;
  positions.forEach((pos, index) => {
    let row = rowEnds.findIndex((end) => pos - end >= minGap);
    if (row === -1) {
      row = rowEnds.length;
      rowEnds.push(-Infinity);
    }
    rows[index] = row;
    rowEnds[row] = pos;
  });
  return rows;
}

function shortPath(value) {
  return String(value || "").replace(/^file:\/\//, "");
}

function renderShell() {
  const meta = state.data.meta || {};
  const session = state.data.session || {};
  els.endpointName.textContent = text(session.endpoint || meta.endpoint, "Local endpoint");
  els.endpointCwd.textContent = text(session.cwd, "No active run cwd");
  els.endpointStore.textContent = `Local store: ${text(meta.storePath, "~/.gensee")}`;
  els.endpointStatus.classList.toggle("online", Boolean(meta.live));
}

function renderDecisions() {
  const decisions = decisionCountsForEvents(visibleTimeline());
  const allow = decisions.allow;
  const ask = decisions.ask;
  const warn = decisions.warn;
  const deny = decisions.deny;
  const total = decisions.total;

  els.eventTotal.textContent = String(total);
  els.allowCount.textContent = String(allow);
  els.askCount.textContent = String(ask);
  els.warnCount.textContent = String(warn);
  els.denyCount.textContent = String(deny);

  const safeTotal = Math.max(total, 1);
  els.ratioAllow.style.width = `${(allow / safeTotal) * 100}%`;
  els.ratioAsk.style.width = `${(ask / safeTotal) * 100}%`;
  els.ratioWarn.style.width = `${(warn / safeTotal) * 100}%`;
  els.ratioDeny.style.width = `${(deny / safeTotal) * 100}%`;
}

function decisionCountsForEvents(events) {
  const counts = { allow: 0, ask: 0, warn: 0, deny: 0 };
  for (const event of events) {
    const action = displayAction(event.action);
    if (action === "deny") counts.deny += 1;
    else if (action === "ask") counts.ask += 1;
    else if (action === "warn") counts.warn += 1;
    else if (action === "allow") counts.allow += 1;
  }
  return {
    ...counts,
    total: counts.allow + counts.ask + counts.warn + counts.deny,
  };
}

function renderSurfaces() {
  const surfaces = state.data.surfaces || [];
  els.surfacesActive.textContent = `${surfaces.filter((surface) => Number(surface.count) > 0).length} active`;
  clear(els.surfaceList);

  if (!surfaces.length) {
    els.surfaceList.append(emptyState("No watched surfaces yet"));
    return;
  }

  for (const surface of surfaces) {
    const row = createEl("div", "surface-row");
    row.append(createEl("span", `surface-glyph ${surface.key || "workspace"}`));
    const copy = createEl("div");
    copy.append(createEl("strong", "", surface.title));
    copy.append(createEl("p", "", surface.detail));
    row.append(copy);
    row.append(createEl("span", "", surface.count || 0));
    els.surfaceList.append(row);
  }
}

function renderTimeline() {
  clear(els.timelineList);
  const timeline = visibleTimeline();

  if (!timeline.length) {
    els.timelineList.append(emptyState("No timeline events for this filter"));
    renderTimelineInspector(null);
    return;
  }

  const selectedId = selectedEvent()?.id;
  const pageCount = Math.max(1, Math.ceil(timeline.length / TIMELINE_PAGE_SIZE));
  if (state.timelinePage > pageCount) state.timelinePage = pageCount;
  const pageStart = (state.timelinePage - 1) * TIMELINE_PAGE_SIZE;
  const pageItems = timeline.slice(pageStart, pageStart + TIMELINE_PAGE_SIZE);
  els.timelineList.append(renderTimelinePager(timeline.length, pageCount, pageStart, "top"));
  for (const item of pageItems) {
    // Alerts are policy decisions; everything else (Pre/PostToolUse, file/system
    // observations) is benign context — render it muted so the feed is
    // decisions-first.
    const observation = item.kind !== "alert";
    const event = createEl("li", `timeline-event ${eventClass(item.action)}${observation ? " observation" : ""}`);
    event.tabIndex = 0;
    event.dataset.eventId = item.id;
    event.classList.toggle("selected", item.id === selectedId);
    event.append(createEl("time", "", formatTime(item.ts)));
    const copy = createEl("div");
    copy.append(createEl("strong", "", item.title));
    // On a decision row, lead the subtitle with the command that triggered it
    // (mono) so you can tell two same-rule alerts apart; fall back otherwise.
    if (item.command) {
      copy.append(createEl("code", "event-cmd", item.command));
    } else {
      copy.append(createEl("p", "", item.description || item.path || item.policy));
    }
    event.append(copy);
    const right = createEl("div", "event-actions");
    const verdict = state.verdicts.get(item.id);
    if (verdict) {
      right.append(createEl("span", `verdict-badge ${verdict.verdict}`, verdictBadgeText(verdict)));
    }
    // Only decisions get a colored action badge; observations are all benign ALLOW.
    if (!observation) {
      right.append(createEl("span", `severity ${eventClass(item.action)}`, displayAction(item.action).toUpperCase()));
    }
    event.append(right);
    event.addEventListener("click", () => selectTimelineEvent(item));
    event.addEventListener("keydown", (keyboardEvent) => {
      if (keyboardEvent.key === "Enter" || keyboardEvent.key === " ") {
        keyboardEvent.preventDefault();
        selectTimelineEvent(item);
      }
    });
    els.timelineList.append(event);
  }
  if (pageCount > 1) {
    els.timelineList.append(renderTimelinePager(timeline.length, pageCount, pageStart, "bottom"));
  }

  renderTimelineInspector(selectedEvent());
}

function reconcileTimelinePage() {
  const timeline = visibleTimeline();
  const pageCount = Math.max(1, Math.ceil(timeline.length / TIMELINE_PAGE_SIZE));
  if (state.timelinePage > pageCount) state.timelinePage = pageCount;
  if (state.timelinePage < 1) state.timelinePage = 1;
}

function renderTimelinePager(total, pageCount, pageStart, position) {
  const pager = createEl("li", `timeline-pager ${position}`);
  const pageEnd = Math.min(pageStart + TIMELINE_PAGE_SIZE, total);
  pager.append(createEl("span", "", `${pageStart + 1}-${pageEnd} of ${total}`));

  const controls = createEl("div", "timeline-pager-actions");
  const previous = createEl("button", "icon-button", "‹");
  previous.type = "button";
  previous.title = "Previous events page";
  previous.disabled = state.timelinePage <= 1;
  previous.addEventListener("click", () => {
    state.timelinePage = Math.max(1, state.timelinePage - 1);
    renderTimeline();
  });
  const current = createEl("span", "timeline-page-label", `Page ${state.timelinePage} / ${pageCount}`);
  const next = createEl("button", "icon-button", "›");
  next.type = "button";
  next.title = "Next events page";
  next.disabled = state.timelinePage >= pageCount;
  next.addEventListener("click", () => {
    state.timelinePage = Math.min(pageCount, state.timelinePage + 1);
    renderTimeline();
  });
  controls.append(previous, current, next);
  pager.append(controls);
  return pager;
}

function verdictBadgeText(verdict) {
  if (verdict.verdict === "agree") return "✓ agree";
  return `→ ${verdict.verdict}`;
}

// What the human did with an `ask` inside Claude Code's inline prompt, derived
// server-side from whether the tool ran (PostToolUse seen). Only meaningful for
// ask events; deny was enforced without a prompt, allow ran without one.
function askOutcomeText(item) {
  if (displayAction(item.action) !== "ask") return "—";
  if (item.askOutcome === "approved") return "user approved (tool ran)";
  if (item.askOutcome === "denied_or_pending") return "denied or pending";
  return "unknown";
}

function selectTimelineEvent(item) {
  state.selectedEventId = item.id;
  if (item.path) {
    state.selectedArtifactUri = item.path;
    els.lineageSearch.value = item.path;
  }
  renderTimeline();
}

function renderTimelineInspector(item) {
  const hasItem = Boolean(item);
  els.verdictAgree.disabled = !hasItem;
  els.verdictAllow.disabled = !hasItem;
  els.verdictDeny.disabled = !hasItem;
  els.verdictNote.disabled = !hasItem;

  if (!hasItem) {
    els.timelineSelectedTitle.textContent = "No event selected";
    els.inspectDecision.textContent = "-";
    els.inspectDecision.className = "";
    els.inspectCommand.textContent = "-";
    els.inspectOutcome.textContent = "-";
    els.timelineSelectedRequest.textContent = "-";
    els.timelineSelectedArtifact.textContent = "-";
    els.timelineSelectedConfidence.textContent = "-";
    renderVerdictState(null);
    return;
  }
  els.timelineSelectedTitle.textContent = text(item.title);
  els.inspectDecision.textContent = displayAction(item.action).toUpperCase();
  els.inspectDecision.className = `severity ${eventClass(item.action)}`;
  els.inspectCommand.textContent = text(item.command, "—");
  els.inspectOutcome.textContent = askOutcomeText(item);
  els.timelineSelectedRequest.textContent = text(item.request);
  els.timelineSelectedArtifact.textContent = text(item.path || item.description);
  els.timelineSelectedConfidence.textContent = text(item.policy || item.severity);
  renderVerdictState(item);
}

// Reflect any recorded human verdict for the selected event in the inspector.
function renderVerdictState(item) {
  const verdict = item ? state.verdicts.get(item.id) : null;
  if (!verdict) {
    els.verdictCurrent.textContent = item ? "Not reviewed" : "—";
    els.verdictCurrent.className = "verdict-current";
    els.verdictNote.value = "";
    els.verdictClear.hidden = true;
    return;
  }
  const label = verdictLabel(verdict.gensee, verdict.verdict);
  const human = verdict.verdict === "agree" ? `agree (${displayAction(verdict.gensee)})` : verdict.verdict;
  const durable = verdict.source === "server";
  els.verdictCurrent.textContent = `${human} · ${label.replace("_", " ")}${durable ? " · recorded" : " · local only"}`;
  els.verdictCurrent.className = `verdict-current ${label}`;
  els.verdictNote.value = verdict.note || "";
  // A server-recorded verdict is durable (append-only feedback); clearing it
  // locally would just re-merge on the next poll, so only offer Clear for a
  // local-only verdict (e.g. one whose server write failed).
  els.verdictClear.hidden = durable;
}

async function recordVerdict(humanVerdict) {
  const item = selectedEvent();
  if (!item) return;
  const entry = {
    verdict: humanVerdict,
    gensee: displayAction(item.action),
    note: els.verdictNote.value.trim(),
    label: verdictLabel(item.action, humanVerdict),
    title: item.title || "",
    path: item.path || "",
    ts: Date.now(),
    source: "local",
  };
  // Optimistic local update so the UI responds immediately; the server write
  // (gensee feedback record) is the durable record and wins on the next poll.
  state.verdicts.set(item.id, entry);
  saveVerdicts();
  renderTimeline();

  const labelText = entry.label.replace("_", " ");
  try {
    const response = await fetch("/api/review", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Gensee-Dashboard": "1" },
      body: JSON.stringify({
        verdict: humanVerdict,
        gensee: entry.gensee,
        eventKey: item.id,
        toolUseId: item.evidence?.tool_use_id,
        session: item.session,
        rule: item.policy,
        path: item.path,
        note: entry.note,
        label: entry.label,
      }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.ok) throw new Error(data.error || `HTTP ${response.status}`);
    entry.source = "server";
    showToast(`Recorded: ${humanVerdict === "agree" ? "agree" : `override → ${humanVerdict}`} (${labelText})`);
  } catch (error) {
    showToast(`Saved locally only — server write failed: ${error.message}`);
  }
}

// Merge durable server-recorded verdicts (newest first) over local ones so a
// reload/another browser sees the persisted feedback. Local-only entries (a
// failed POST) survive because the server has no row for them.
function applyServerFeedback() {
  const rows = state.data?.feedback || [];
  const seen = new Set();
  for (const row of rows) {
    const key = row.event_key;
    if (!key || seen.has(key)) continue;
    seen.add(key);
    state.verdicts.set(key, {
      verdict: row.human_verdict,
      gensee: row.gensee_action || "",
      note: row.note || "",
      label: row.label || verdictLabel(row.gensee_action, row.human_verdict),
      path: row.path || "",
      ts: Number(row.created_at) || 0,
      source: "server",
    });
  }
  saveVerdicts();
}

function clearVerdict() {
  const item = selectedEvent();
  if (!item || !state.verdicts.has(item.id)) return;
  // Server-recorded verdicts are durable; the next poll would re-merge them, so
  // Clear is only meaningful (and only offered) for local-only verdicts.
  if (state.verdicts.get(item.id).source === "server") {
    showToast("Server-recorded verdicts are durable and can't be cleared here");
    return;
  }
  state.verdicts.delete(item.id);
  saveVerdicts();
  renderTimeline();
  showToast("Verdict cleared");
}

function renderLineage() {
  const artifacts = state.data.artifacts || [];
  const search = state.selectedArtifactUri || els.lineageSearch.value;
  const selected =
    artifacts.find((artifact) => artifact.uri === search || artifact.shortUri === search) ||
    artifacts.find((artifact) => search && artifact.uri?.includes(search)) ||
    artifacts[0] ||
    null;

  if (selected) {
    state.selectedArtifactUri = selected.uri;
    if (!els.lineageSearch.value) els.lineageSearch.value = selected.shortUri || selected.uri;
  }

  const edges = state.data.lineageEdges || [];
  const actions = lineagePathActions();
  // Skip the SVG rebuild when nothing relevant changed, so the 12s poll doesn't
  // tear down and flicker the graph (or lose the user's selection mid-inspect).
  // Classification is in the signature so node colors refresh when decisions do.
  const signature = JSON.stringify([
    artifacts.map((a) => [a.uri, a.current_digest, classifyArtifact(a, actions)]),
    edges.map((e) => [e.from, e.to, e.type]),
    selected?.uri || "",
  ]);
  if (signature === state.lastLineageSig) {
    renderFactPanel(selected);
    return;
  }
  state.lastLineageSig = signature;

  renderGraph(artifacts, selected, edges, actions);
  renderFactPanel(selected);
}

/// The strongest decision (deny > ask > allow) seen for each file path in the
/// alert stream — used to color lineage nodes by their actual outcome.
function lineagePathActions() {
  const rank = { deny: 3, ask: 2, allow: 1, watch: 0 };
  const map = new Map();
  (state.data.timeline || []).forEach((event) => {
    if (event.kind !== "alert" || !event.path) return;
    const path = String(event.path).replace(/^file:\/\//, "");
    if (!map.has(path) || (rank[event.action] || 0) > (rank[map.get(path)] || 0)) {
      map.set(path, event.action);
    }
  });
  return map;
}

/// Classify an artifact for coloring: deny / ask (it was the subject of a
/// blocked or review decision), sensitive (secret/control-plane/memory or
/// otherwise risk-flagged), else benign.
function classifyArtifact(artifact, actions) {
  const action = actions.get(String(artifact.uri || "").replace(/^file:\/\//, ""));
  if (action === "deny") return "deny";
  if (action === "ask") return "ask";
  if (
    artifact.risk_level ||
    artifact.is_memory_artifact ||
    artifact.is_control_plane ||
    artifact.is_persistent_target
  ) {
    return "sensitive";
  }
  return "benign";
}

/// Final path segment (filename) of a uri/path.
function basename(value) {
  const string = String(value || "")
    .replace(/^file:\/\//, "")
    .replace(/\/+$/, "");
  const index = string.lastIndexOf("/");
  return index >= 0 ? string.slice(index + 1) : string;
}

function renderGraph(artifacts, selected, edges, actions) {
  clear(els.lineageGraphContent);
  appendGraphMarkers();
  const visibleArtifacts = artifacts.slice(0, 6);
  if (!visibleArtifacts.length) {
    els.lineageGraphContent.append(svgText(280, 220, "No artifact facts in local store yet", "graph-empty"));
    return;
  }

  // Lay out nodes in a 3-wide grid and remember each node's center by URI.
  const NODE_W = 132;
  const NODE_H = 84;
  const pos = new Map();
  visibleArtifacts.forEach((artifact, index) => {
    const x = 40 + (index % 3) * 240;
    const y = 70 + Math.floor(index / 3) * 180;
    pos.set(artifact.uri, { x, y });
  });

  // Draw only REAL lineage edges (from the relations table) between two visible
  // nodes — under the nodes. No fabricated edges. Relation-type labels are drawn
  // last (on top) so they stay readable.
  const edgeLabels = [];
  let drawn = 0;
  (edges || []).forEach((edge) => {
    const from = pos.get(edge.from);
    const to = pos.get(edge.to);
    if (!from || !to) return;
    const start = nodeEdgePoint(from, to, NODE_W, NODE_H);
    const end = nodeEdgePoint(to, from, NODE_W, NODE_H);
    const mid = (start.x + end.x) / 2;
    const touchesSelected = selected && (edge.from === selected.uri || edge.to === selected.uri);
    const path = svgPath(
      edgePath(start, end),
      `graph-edge${touchesSelected ? " selected" : ""}`
    );
    const tip = document.createElementNS("http://www.w3.org/2000/svg", "title");
    tip.textContent = `${basename(edge.from)} → ${basename(edge.to)} · ${edge.type}${edge.confidence != null ? ` (${edge.confidence})` : ""}`;
    path.append(tip);
    els.lineageGraphContent.append(path);
    edgeLabels.push({ x: mid, y: (start.y + end.y) / 2 - 6, text: edge.type });
    drawn += 1;
  });

  visibleArtifacts.forEach((artifact) => {
    const point = pos.get(artifact.uri);
    els.lineageGraphContent.append(
      svgNode(point.x, point.y, artifact, selected?.uri === artifact.uri, classifyArtifact(artifact, actions))
    );
  });

  edgeLabels.forEach((label) => {
    const text = svgText(label.x, label.y, label.text, "graph-edge-label");
    text.setAttribute("text-anchor", "middle");
    els.lineageGraphContent.append(text);
  });

  if (!drawn) {
    els.lineageGraphContent.append(svgText(40, 420, "No recorded lineage edges between these artifacts yet", "graph-empty"));
  }
}

function appendGraphMarkers() {
  const ns = "http://www.w3.org/2000/svg";
  const defs = document.createElementNS(ns, "defs");
  const marker = document.createElementNS(ns, "marker");
  marker.setAttribute("id", "graph-arrowhead");
  marker.setAttribute("viewBox", "0 0 10 10");
  marker.setAttribute("refX", "9");
  marker.setAttribute("refY", "5");
  marker.setAttribute("markerWidth", "7");
  marker.setAttribute("markerHeight", "7");
  marker.setAttribute("orient", "auto-start-reverse");
  const arrow = document.createElementNS(ns, "path");
  arrow.setAttribute("d", "M 0 0 L 10 5 L 0 10 z");
  arrow.setAttribute("class", "graph-arrowhead");
  marker.append(arrow);
  defs.append(marker);
  els.lineageGraphContent.append(defs);
}

function nodeEdgePoint(node, target, width, height) {
  const cx = node.x + width / 2;
  const cy = node.y + height / 2;
  const tx = target.x + width / 2;
  const ty = target.y + height / 2;
  const dx = tx - cx;
  const dy = ty - cy;
  if (dx === 0 && dy === 0) return { x: cx, y: cy };
  const scale = Math.min(
    dx === 0 ? Infinity : (width / 2) / Math.abs(dx),
    dy === 0 ? Infinity : (height / 2) / Math.abs(dy)
  );
  return { x: cx + dx * scale, y: cy + dy * scale };
}

function edgePath(start, end) {
  const dx = end.x - start.x;
  const dy = end.y - start.y;
  if (Math.abs(dx) >= Math.abs(dy)) {
    const mid = start.x + dx / 2;
    return `M${start.x} ${start.y} C${mid} ${start.y} ${mid} ${end.y} ${end.x} ${end.y}`;
  }
  const mid = start.y + dy / 2;
  return `M${start.x} ${start.y} C${start.x} ${mid} ${end.x} ${mid} ${end.x} ${end.y}`;
}

function renderFactPanel(artifact) {
  if (!artifact) {
    els.factUri.textContent = "-";
    els.factModifier.textContent = "-";
    els.factRegistry.textContent = "-";
    els.factRisk.textContent = "-";
    return;
  }

  els.factUri.textContent = text(artifact.shortUri || artifact.uri);
  els.factModifier.textContent = text(artifact.last_modified_source || artifact.last_modified_session_id);
  els.factRegistry.textContent = registryText(artifact);
  els.factRisk.textContent = artifact.risk_rule_id || artifact.risk_level || "none";
}

// Render the whole Policy tab from the working document: scalar settings, the
// artifact definitions (what counts as executable / memory / skill / control
// plane), and the decision-rule inventory (each rule's ask/deny action). All
// controls mutate state.policyWorking directly; Save serializes it.
function renderPolicy() {
  if (!els.policySettings) return;
  clear(els.policySettings);
  clear(els.policyArtifacts);
  clear(els.policyRules);
  if (!state.policyWorking) {
    els.policySettings.append(emptyState("Loading policy…"));
    return;
  }
  renderScalarSettings();
  renderArtifactDefs();
  renderRulesInventory();
}

function renderScalarSettings() {
  for (const group of POLICY_SETTINGS) {
    const section = createEl("section", "settings-group");
    section.append(createEl("h4", "settings-group-title", group.group));
    if (group.hint) section.append(createEl("p", "settings-group-hint", group.hint));
    for (const item of group.items) section.append(buildSettingRow(item));
    els.policySettings.append(section);
  }
}

function buildSettingRow(item) {
  const row = createEl("div", "setting-row");
  const label = createEl("div", "setting-label");
  label.append(createEl("strong", "", item.label));
  label.append(createEl("p", "", item.help));
  row.append(label);

  const control = createEl("div", "setting-control");
  const value = getDotted(state.policyWorking, item.key);

  if (item.type === "bool") {
    const wrap = createEl("label", "switch");
    const input = document.createElement("input");
    input.type = "checkbox";
    input.checked = Boolean(value);
    const stateText = createEl("span", "", input.checked ? "On" : "Off");
    input.addEventListener("change", () => {
      setDotted(state.policyWorking, item.key, input.checked);
      stateText.textContent = input.checked ? "On" : "Off";
    });
    wrap.append(input, stateText);
    control.append(wrap);
  } else if (item.type === "list") {
    let arr = getDotted(state.policyWorking, item.key);
    if (!Array.isArray(arr)) {
      arr = [];
      setDotted(state.policyWorking, item.key, arr);
    }
    control.append(makeChipEditor(arr));
  } else {
    const input = document.createElement("input");
    input.type = item.type === "string" ? "text" : "number";
    if (item.type === "float") input.step = "any";
    if (item.type === "int") input.step = "1";
    input.value = value == null ? "" : String(value);
    input.addEventListener("input", () => {
      if (item.type === "string") {
        setDotted(state.policyWorking, item.key, input.value);
      } else if (input.value.trim() === "") {
        setDotted(state.policyWorking, item.key, null);
      } else {
        const num = Number(input.value);
        setDotted(state.policyWorking, item.key, Number.isFinite(num) ? num : input.value);
      }
    });
    control.append(input);
  }

  row.append(control);
  return row;
}

// A chips editor bound to a live array (mutated in place via splice/push).
function makeChipEditor(arr) {
  const wrap = createEl("div", "setting-control setting-list");
  const chips = createEl("div", "chip-list");
  const draw = () => {
    clear(chips);
    if (!arr.length) chips.append(createEl("span", "chip-empty", "none"));
    arr.forEach((entry, index) => {
      const chip = createEl("span", "chip", String(entry));
      const remove = createEl("button", "chip-remove", "×");
      remove.type = "button";
      remove.title = "Remove";
      remove.addEventListener("click", () => {
        arr.splice(index, 1);
        draw();
      });
      chip.append(remove);
      chips.append(chip);
    });
  };
  draw();
  const addRow = createEl("div", "chip-add");
  const input = document.createElement("input");
  input.type = "text";
  input.placeholder = "Add and press Enter";
  input.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    const entry = input.value.trim();
    if (!entry) return;
    if (!arr.includes(entry)) arr.push(entry);
    input.value = "";
    draw();
  });
  addRow.append(input);
  wrap.append(chips, addRow);
  return wrap;
}

// Artifact registries: what the shield classifies as executable / memory /
// skill / control-plane, by path & filename matchers.
const ARTIFACT_DEFS = [
  { key: "executable", title: "Executable artifacts", help: "Treated as runnable (scripts, skills, plugins, git hooks) — gates content rules and cross-session execution." },
  { key: "memory", title: "Memory files", help: "Agent memory the shield tracks for poisoning across turns/sessions." },
  { key: "skill", title: "Skill / plugin locations", help: "Where skill and plugin definitions live." },
  { key: "control_plane", title: "Control-plane files", help: "Gensee's own files (shield DB, policy) — writes here are blocked." },
];

const MATCHER_FIELDS = [
  { key: "segments", label: "Path segments (directory names)" },
  { key: "filenames", label: "Exact filenames" },
  { key: "filename_prefixes", label: "Filename prefixes" },
  { key: "filename_suffixes", label: "Filename suffixes / extensions" },
  { key: "filename_contains", label: "Filename contains" },
  { key: "path_suffixes", label: "Path ends with" },
  { key: "path_contains", label: "Path contains" },
];

function renderArtifactDefs() {
  const registries = state.policyWorking.artifact_registries;
  if (!registries) return;
  const header = createEl("div", "policy-section-head");
  header.append(createEl("h3", "", "Artifact definitions"));
  header.append(createEl("p", "policy-section-sub", "What the shield treats as executable, memory, skill, or control-plane files."));
  els.policyArtifacts.append(header);

  for (const def of ARTIFACT_DEFS) {
    const reg = registries[def.key];
    if (!reg) continue;
    const card = createEl("details", "rule-card");
    const summary = createEl("summary", "rule-card-summary");
    summary.append(createEl("strong", "", def.title));
    summary.append(createEl("span", "rule-card-sub", def.help));
    card.append(summary);

    for (const field of MATCHER_FIELDS) {
      if (!Array.isArray(reg[field.key])) reg[field.key] = [];
      const fieldRow = createEl("div", "matcher-row");
      fieldRow.append(createEl("span", "matcher-label", field.label));
      fieldRow.append(makeChipEditor(reg[field.key]));
      card.append(fieldRow);
    }
    els.policyArtifacts.append(card);
  }
}

// Every decision rule, grouped, with an editable action (deny / ask / allow).
const ACTION_OPTIONS = [
  { value: "block", label: "Deny" },
  { value: "ask", label: "Ask" },
  { value: "warn", label: "Warn" },
  { value: "allow", label: "Allow" },
];

function summarizeMatchers(node) {
  const parts = [];
  for (const field of ["patterns", "commands", "bare_commands", "hosts", "url_substrings", "segments", "filenames", "filename_suffixes", "path_contains", "exact_paths"]) {
    if (Array.isArray(node[field]) && node[field].length) {
      parts.push(...node[field]);
    }
  }
  if (!parts.length) return node.message || "";
  const shown = parts.slice(0, 4).join(", ");
  return parts.length > 4 ? `${shown} … (+${parts.length - 4})` : shown;
}

function collectRuleGroups(doc) {
  const fileRules = [];
  if (doc.secret_paths?.protected) {
    fileRules.push({ node: doc.secret_paths.protected, name: "Protected secrets", rule_id: doc.secret_paths.rule_id });
  }
  if (doc.persistence_writes) {
    fileRules.push({ node: doc.persistence_writes, name: "Persistence / startup writes", rule_id: doc.persistence_writes.rule_id });
  }
  for (const [key, node] of Object.entries(doc.categories || {})) {
    fileRules.push({ node, name: key.replace(/_/g, " "), rule_id: node.rule_id });
  }
  const contentRules = (doc.content_rules || []).map((node) => ({
    node,
    name: node.id || node.rule_id,
    rule_id: `applies to: ${(node.applies_to || ["any"]).join(", ")}`,
  }));
  const commandRules = (doc.command_rules || []).map((node) => ({
    node,
    name: node.id || node.rule_id,
    rule_id: node.rule_id,
  }));
  const urlRules = (doc.url_rules || []).map((node, i) => ({
    node,
    name: node.id || node.rule_id || `URL rule ${i + 1}`,
    rule_id: node.rule_id,
  }));
  return [
    { group: "File access rules", rules: fileRules },
    { group: "Command rules", rules: commandRules },
    { group: "Executable-content rules", rules: contentRules },
    { group: "Network / URL rules", rules: urlRules },
  ].filter((g) => g.rules.length);
}

function renderRulesInventory() {
  const header = createEl("div", "policy-section-head");
  header.append(createEl("h3", "", "Decision rules"));
  header.append(createEl("p", "policy-section-sub", "Each rule's action — Deny blocks, Ask prompts the user, Allow/Warn lets it through. Patterns are read-only here; edit them in Advanced."));
  els.policyRules.append(header);

  for (const { group, rules } of collectRuleGroups(state.policyWorking)) {
    const section = createEl("section", "settings-group");
    section.append(createEl("h4", "settings-group-title", `${group} (${rules.length})`));
    for (const rule of rules) {
      section.append(buildRuleRow(rule));
    }
    els.policyRules.append(section);
  }
}

function buildRuleRow(rule) {
  const row = createEl("div", "rule-inv-row");
  const info = createEl("div", "rule-inv-info");
  info.append(createEl("strong", "", rule.name));
  const sub = summarizeMatchers(rule.node);
  info.append(createEl("code", "rule-inv-match", text(sub || rule.rule_id, "")));
  row.append(info);

  const select = document.createElement("select");
  select.className = `rule-action act-${displayAction(rule.node.action)}`;
  const current = rule.node.action || "allow";
  const options = ACTION_OPTIONS.some((o) => o.value === current)
    ? ACTION_OPTIONS
    : [...ACTION_OPTIONS, { value: current, label: current }];
  for (const opt of options) {
    const optionEl = document.createElement("option");
    optionEl.value = opt.value;
    optionEl.textContent = opt.label;
    if (opt.value === current) optionEl.selected = true;
    select.append(optionEl);
  }
  select.addEventListener("change", () => {
    rule.node.action = select.value;
    select.className = `rule-action act-${displayAction(select.value)}`;
  });
  row.append(select);
  return row;
}

function emptyState(message) {
  return createEl("p", "empty-state", message);
}

function registryText(artifact) {
  const labels = [];
  if (artifact.is_agent_authored) labels.push("agent-authored");
  if (artifact.is_unmatched_modified) labels.push("outside modification");
  if (artifact.is_memory_artifact) labels.push("memory");
  if (artifact.is_persistent_target) labels.push("persistence");
  if (artifact.is_control_plane) labels.push("control plane");
  return labels.join(", ") || artifact.kind || "file";
}

function svgPath(d, className) {
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("class", className);
  path.setAttribute("d", d);
  return path;
}

function svgText(x, y, value, className) {
  const textNode = document.createElementNS("http://www.w3.org/2000/svg", "text");
  textNode.setAttribute("x", String(x));
  textNode.setAttribute("y", String(y));
  textNode.setAttribute("class", className);
  textNode.textContent = value;
  return textNode;
}

function svgNode(x, y, artifact, selected, klass) {
  const ns = "http://www.w3.org/2000/svg";
  const group = document.createElementNS(ns, "g");
  group.setAttribute("class", `graph-node ${klass || "benign"}${selected ? " selected" : ""}`);
  group.setAttribute("transform", `translate(${x} ${y})`);
  group.addEventListener("click", () => {
    state.selectedArtifactUri = artifact.uri;
    els.lineageSearch.value = artifact.shortUri || artifact.uri;
    renderLineage();
  });

  // Hover shows the full path; the fact panel shows it too on selection.
  const tip = document.createElementNS(ns, "title");
  tip.textContent = (artifact.shortUri || artifact.uri || "").replace(/^file:\/\//, "");
  group.append(tip);

  const rect = document.createElementNS(ns, "rect");
  rect.setAttribute("width", "132");
  rect.setAttribute("height", "84");
  rect.setAttribute("rx", "8");
  group.append(rect);

  // Primary label is the file name; the small tag is the classification.
  const name = svgText(16, 36, truncate(basename(artifact.uri), 15), "node-name");
  const tag = svgText(16, 62, (klass || "benign").toUpperCase(), "node-tag");
  group.append(name, tag);
  return group;
}

function truncate(value, max) {
  const string = text(value, "");
  return string.length > max ? `${string.slice(0, max - 1)}...` : string;
}

function applyCustomRange() {
  const from = parseDateTimeInput(els.rangeFrom);
  const to = parseDateTimeInput(els.rangeTo);
  if (Number.isNaN(from) || Number.isNaN(to)) {
    const message = "Could not parse custom range. Use 06/23/2026, 07:30 AM";
    renderRangeStatus(message);
    showToast(message);
    return;
  }
  if (from >= to) {
    const message = "Start time must be before end time";
    renderRangeStatus(message);
    showToast(message);
    return;
  }
  state.range = "custom";
  state.rangeFrom = from;
  state.rangeTo = to;
  state.timelinePage = 1;
  render();
}

function wireActions() {
  navItems.forEach((item) => {
    item.addEventListener("click", () => setView(item.dataset.view));
  });

  rangeButtons.forEach((button) => {
    button.addEventListener("click", () => {
      const range = button.dataset.range || "live";
      rangeButtons.forEach((peer) => peer.classList.toggle("selected", peer === button));
      // "Custom" just reveals the date inputs; the fetch happens on Apply.
      if (range === "custom") {
        state.range = "custom";
        els.customRange.hidden = false;
        seedCustomRangeInputs();
        render();
        return;
      }
      els.customRange.hidden = true;
      state.range = range;
      state.timelinePage = 1;
      render();
    });
  });

  if (els.rangeApply) {
    els.rangeApply.addEventListener("click", applyCustomRange);
  }
  for (const input of [els.rangeFrom, els.rangeTo]) {
    if (!input) continue;
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") applyCustomRange();
    });
  }

  filterButtons.forEach((button) => {
    button.addEventListener("click", () => {
      state.filter = button.dataset.filter || "all";
      state.timelinePage = 1;
      filterButtons.forEach((peer) => peer.classList.toggle("selected", peer === button));
      render();
    });
  });

  document.querySelector("#policy-settings-save").addEventListener("click", () => savePolicySettings());
  document.querySelector("#policy-settings-reload").addEventListener("click", () => loadPolicyDocument());
  if (els.policyDocSave) els.policyDocSave.addEventListener("click", () => savePolicyDocument());
  if (els.policyDocReload) els.policyDocReload.addEventListener("click", () => loadPolicyDocument());

  els.verdictAgree.addEventListener("click", () => recordVerdict("agree"));
  els.verdictAllow.addEventListener("click", () => recordVerdict("allow"));
  els.verdictDeny.addEventListener("click", () => recordVerdict("deny"));
  els.verdictClear.addEventListener("click", () => clearVerdict());

  document.querySelector("#open-lineage").addEventListener("click", () => {
    const item = selectedEvent();
    if (item?.path) {
      state.selectedArtifactUri = item.path;
      els.lineageSearch.value = item.path;
    }
    setView("lineage");
    renderLineage();
  });

  els.lineageSearch.addEventListener("input", () => {
    state.selectedArtifactUri = els.lineageSearch.value;
    renderLineage();
  });

  document.querySelector("#show-sql").addEventListener("click", () => {
    els.sqlPanel.hidden = !els.sqlPanel.hidden;
    els.sqlPanel.textContent = "SELECT kind, uri, last_seen_at, risk_level, risk_rule_id FROM artifact_facts ORDER BY last_seen_at DESC LIMIT 80;";
  });

  document.querySelector("#copy-uri").addEventListener("click", async () => {
    const uri = state.selectedArtifactUri || els.factUri.textContent;
    try {
      await navigator.clipboard.writeText(uri);
      showToast("Artifact URI copied");
    } catch {
      showToast(uri);
    }
  });

}

wireActions();
fetchState().catch((error) => renderLoadError(error));
startPolling();
