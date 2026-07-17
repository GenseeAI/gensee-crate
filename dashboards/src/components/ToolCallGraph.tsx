/**
 * ToolCallGraph — CrowdStrike-style tree + timeline for a single agent request.
 *
 * Layout per row:
 *   [20px tree col] [72px time] [tag] [detail flex] [60px duration] [200px timeline track]
 *
 * Grouping heuristic (Pre/PostToolUse pairing):
 *   - Pair Pre+Post by tool_use_id.
 *   - Two tool calls are PARALLEL if their time windows overlap.
 *   - A tool call is SEQUENTIAL if it starts after the previous group's last PostToolUse.
 */

import { useCallback, useState } from 'react';
import { Tag, Typography } from 'antd';
import { useApi } from '@/hooks/useApi';
import { api }   from '@/api/client';
import { ActionBadge, SeverityBadge } from '@/components/SeverityBadge';
import type { AgentEvent, Alert } from '@/api/types';

// ─── Constants ────────────────────────────────────────────────────────────────

const TRACK_W = 200;   // timeline track width (px)
const BAR_MIN = 4;    // minimum bar width so zero-duration tools are still visible

/**
 * Grid column template shared by every CallRow and the TimelineAxis header.
 *
 *  [bullet 14] [time 76] [tool 88] [severity 70] [action 60] [detail 1fr] [duration 64] [track 200]
 */
const ROW_COLS = `14px 76px 88px 70px 60px 1fr 64px ${TRACK_W}px`;

const TAG_COLOR: Record<string, string> = {
  ToolSearch: 'purple',
  WebSearch:  'blue',
  WebFetch:   'cyan',
  Read:       'default',
  Write:      'orange',
  Edit:       'gold',
  MultiEdit:  'gold',
  Bash:       'volcano',
};

const BAR_COLOR: Record<string, string> = {
  ToolSearch: '#9c27b0',
  WebSearch:  '#1677ff',
  WebFetch:   '#13c2c2',
  Read:       '#52c41a',
  Write:      '#fa8c16',
  Edit:       '#faad14',
  MultiEdit:  '#faad14',
  Bash:       '#f5222d',
};

function barColor(name: string) { return BAR_COLOR[name] ?? 'rgba(128,128,128,0.55)'; }
function tagColor(name: string) { return TAG_COLOR[name] ?? 'default'; }

// ─── Types ────────────────────────────────────────────────────────────────────

interface ToolCall {
  id:          string;
  toolName:    string;
  startTs:     number;
  endTs:       number | null;
  duration:    number | null;
  durationSource: 'reported' | 'elapsed' | null;
  input:       Record<string, unknown> | null;
  response:    Record<string, unknown> | null;
  detail:      string | null;   // short label (query, filename, url…)
  detailFull:  string | null;   // tooltip (full path when detail is basename)
}

interface ToolGroup {
  calls: ToolCall[];
}

// ─── Data processing ──────────────────────────────────────────────────────────

function parseJson(v: unknown): Record<string, unknown> | null {
  if (!v || typeof v !== 'string') return null;
  try { return JSON.parse(v); } catch { return null; }
}

function extractDetail(input: Record<string, unknown> | null): { label: string; full?: string } | null {
  if (!input) return null;
  if (typeof input.query   === 'string' && input.query)   return { label: input.query };
  if (typeof input.url     === 'string' && input.url)     return { label: input.url };
  if (typeof input.path    === 'string' && input.path) {
    const full = input.path;
    return { label: full.split('/').pop() ?? full, full };
  }
  if (typeof input.command === 'string' && input.command) return { label: input.command };
  return null;
}

export function buildToolCalls(events: AgentEvent[]): ToolCall[] {
  const pairs = new Map<string, { pre?: AgentEvent; post?: AgentEvent }>();

  for (const e of events) {
    // Use tool_use_id when present; fall back to a per-event key so nothing is lost.
    const key = e.tool_use_id ?? `__evt_${e.event_id}`;
    const p   = pairs.get(key) ?? {};
    if (e.type === 'PreToolUse')       p.pre  = e;
    else if (e.type === 'PostToolUse') p.post = e;
    else                               p.pre  = p.pre ?? e;   // other hook types → treat as pre
    pairs.set(key, p);
  }

  const calls: ToolCall[] = [];
  for (const [id, { pre, post }] of pairs) {
    if (!pre) continue;
    const input = parseJson(pre.tool_input);
    const resp  = post ? parseJson(post.tool_response) : null;
    const det   = extractDetail(input);
    const reportedDuration = typeof resp?.duration_ms === 'number'
      ? resp.duration_ms
      : null;
    const elapsedDuration = post && post.ts >= pre.ts
      ? post.ts - pre.ts
      : null;
    calls.push({
      id,
      toolName:   pre.tool_name ?? '(unknown)',
      startTs:    pre.ts,
      endTs:      post?.ts ?? null,
      duration:   reportedDuration ?? elapsedDuration,
      durationSource: reportedDuration !== null
        ? 'reported'
        : elapsedDuration !== null
          ? 'elapsed'
          : null,
      input,
      response:   resp,
      detail:     det?.label   ?? null,
      detailFull: det?.full    ?? null,
    });
  }

  return calls.sort((a, b) => a.startTs - b.startTs);
}

export function buildGroups(calls: ToolCall[]): ToolGroup[] {
  if (!calls.length) return [];
  const groups: ToolGroup[] = [];
  let group = [calls[0]];
  // groupEnd = the latest PostToolUse ts seen so far in the current group.
  // Use startTs + 1 as a conservative fallback when endTs is unknown.
  let groupEnd = calls[0].endTs ?? calls[0].startTs + 1;

  for (let i = 1; i < calls.length; i++) {
    const c = calls[i];
    if (c.startTs >= groupEnd) {
      // Starts after everything in the current group ended → new sequential step.
      groups.push({ calls: group });
      group    = [c];
      groupEnd = c.endTs ?? c.startTs + 1;
    } else {
      // Overlaps → parallel sibling.
      group.push(c);
      if (c.endTs !== null) groupEnd = Math.max(groupEnd, c.endTs);
    }
  }
  groups.push({ calls: group });
  return groups;
}

// ─── Action resolution ───────────────────────────────────────────────────────

const ACTION_RANK: Record<string, number> = { allow: 0, warn: 1, ask: 2, block: 3 };
const SEVERITY_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

interface AlertMeta { action: string; severity: string; }

/**
 * Build a map from tool_use_id → most-restrictive { action, severity }.
 * Falls back to { action: 'allow', severity: 'info' } for unmentioned tool calls.
 */
function buildActionMap(alerts: Alert[]): Map<string, AlertMeta> {
  const map = new Map<string, AlertMeta>();
  for (const a of alerts) {
    const tid = (a as Alert & { tool_use_id?: string }).tool_use_id;
    if (!tid) continue;
    const current  = map.get(tid);
    const incoming = { action: a.action, severity: a.severity };
    if (
      !current ||
      (ACTION_RANK[incoming.action]   ?? 0) > (ACTION_RANK[current.action]   ?? 0) ||
      (SEVERITY_RANK[incoming.severity] ?? 0) > (SEVERITY_RANK[current.severity] ?? 0)
    ) {
      map.set(tid, incoming);
    }
  }
  return map;
}

// ─── Top-level component ──────────────────────────────────────────────────────

export function ToolCallGraph({ requestId }: { requestId: number }) {
  const fetchEvents = useCallback(
    () => api.agentEvents({ request_id: requestId, limit: 200 }),
    [requestId],
  );
  const fetchAlerts = useCallback(
    () => api.alerts({ request_id: requestId, limit: 500 }),
    [requestId],
  );
  const { data: events, loading: eventsLoading } = useApi(fetchEvents);
  const { data: alerts, loading: alertsLoading  } = useApi(fetchAlerts);

  const loading = eventsLoading || alertsLoading;

  if (loading) return <Typography.Text type="secondary">Loading…</Typography.Text>;
  if (!events?.length) {
    return <Typography.Text type="secondary">No tool calls recorded for this request.</Typography.Text>;
  }

  const actionMap = buildActionMap(alerts ?? []);
  const DEFAULT_META: AlertMeta = { action: 'allow', severity: 'info' };
  const calls    = buildToolCalls(events);
  const groups   = buildGroups(calls);
  const minTs    = calls[0].startTs;
  // Span = range of START times + longest single-tool duration.
  // We deliberately do NOT use endTs (PostToolUse ts) because the LLM may
  // "think" for minutes between Pre and PostToolUse — that thinking time
  // would collapse all the actual tool durations to hairlines on the axis.
  const maxStart = calls.reduce((m, c) => Math.max(m, c.startTs), minTs);
  const maxDur   = calls.reduce((m, c) => Math.max(m, c.duration ?? 0), 0);
  const span     = Math.max(maxStart - minTs + maxDur, 1000);

  return (
    <div style={{ userSelect: 'none' }}>
      <TimelineAxis minTs={minTs} span={span} />
      {groups.map((g, gi) => (
        <GroupBlock
          key={gi}
          group={g}
          minTs={minTs}
          span={span}
          isFirst={gi === 0}
          isLast={gi === groups.length - 1}
          actionMap={actionMap}
          defaultMeta={DEFAULT_META}
        />
      ))}
    </div>
  );
}

// ─── Timeline axis header ─────────────────────────────────────────────────────

/**
 * Axis ticks aligned to the last grid column (timeline track).
 * Uses the same ROW_COLS grid so the track column is always pixel-perfect.
 */
function TimelineAxis({ minTs, span }: { minTs: number; span: number }) {
  const fmt = (ts: number) => new Date(ts).toLocaleTimeString();
  return (
    <div style={{
      display:             'grid',
      gridTemplateColumns: ROW_COLS,
      columnGap:           6,
      marginBottom:        2,
      paddingBottom:       2,
      borderBottom:        '1px solid rgba(128,128,128,0.15)',
    }}>
      {/* span the first 6 columns (bullet → duration) with nothing */}
      <div style={{ gridColumn: '1 / 7' }} />
      {/* last column: the tick labels */}
      <div style={{ width: TRACK_W, position: 'relative', height: 14 }}>
        {[0, 0.5, 1].map(f => (
          <Typography.Text
            key={f}
            type="secondary"
            style={{
              position:  'absolute',
              fontSize:  9,
              left:      `${f * 100}%`,
              transform: f === 1 ? 'translateX(-100%)' : f === 0.5 ? 'translateX(-50%)' : undefined,
              whiteSpace: 'nowrap',
            }}
          >
            {fmt(minTs + f * span)}
          </Typography.Text>
        ))}
        <div style={{ position: 'absolute', bottom: 0, left: 0, right: 0, height: 1, background: 'rgba(128,128,128,0.2)' }} />
      </div>
    </div>
  );
}

// ─── Tree geometry constants ──────────────────────────────────────────────────
const TX   = 5;   // x of vertical trunk line
const ARM  = 13;  // y offset within a group where the horizontal arm sits
const LINE = 'rgba(128,128,128,0.45)';

// ─── Group block ──────────────────────────────────────────────────────────────

function GroupBlock({
  group, minTs, span, isFirst, isLast, actionMap, defaultMeta,
}: {
  group:       ToolGroup;
  minTs:       number;
  span:        number;
  isFirst:     boolean;
  isLast:      boolean;
  actionMap:   Map<string, AlertMeta>;
  defaultMeta: AlertMeta;
}) {
  const isParallel = group.calls.length > 1;

  return (
    <div style={{ display: 'flex' }}>

      {/* ── Tree column (28 px) ──
       *
       *  isFirst          non-first, non-last        last
       *  ●               │                           │
       *  │               ├─ ●                        └─ ●
       *  ├─ ●             │
       */}
      <div style={{ width: 28, flexShrink: 0, position: 'relative' }}>

        {/* Trunk coming DOWN from the root bullet (first group) or
            continuing past the arm on intermediate groups. */}
        {!isLast && (
          <div style={{
            position:   'absolute',
            left:       TX,
            top:        isFirst ? ARM : ARM + 1,
            bottom:     0,
            borderLeft: `1.5px solid ${LINE}`,
          }} />
        )}

        {/* Vertical segment from the TOP of the group down to the arm
            (only for non-root groups — it connects to the trunk above). */}
        {!isFirst && (
          <div style={{
            position:   'absolute',
            left:       TX,
            top:        0,
            height:     ARM + 1,
            borderLeft: `1.5px solid ${LINE}`,
          }} />
        )}

        {/* Horizontal arm: ├─ or └─ (skip for root) */}
        {!isFirst && (
          <div style={{
            position:  'absolute',
            left:      TX,
            top:       ARM,
            width:     16,
            borderTop: `1.5px solid ${LINE}`,
          }} />
        )}

        {/* Parallel bracket — a vertical bar to the RIGHT of the arm end
            that visually groups the parallel rows together. */}
        {isParallel && (
          <div style={{
            position:     'absolute',
            left:         TX + 16,
            top:          ARM - 2,
            bottom:       6,
            borderLeft:   `1.5px solid ${LINE}`,
          }} />
        )}
      </div>

      {/* ── Call rows ── */}
      <div style={{ flex: 1, minWidth: 0 }}>
        {group.calls.map((call, ci) => (
          <CallRow
            key={call.id}
            call={call}
            minTs={minTs}
            span={span}
            indent={isParallel && ci > 0}
            isLastInGroup={ci === group.calls.length - 1}
            meta={actionMap.get(call.id) ?? defaultMeta}
          />
        ))}
      </div>
    </div>
  );
}

// ─── Individual call row ──────────────────────────────────────────────────────

function CallRow({
  call, minTs, span, indent, isLastInGroup, meta,
}: {
  call:          ToolCall;
  minTs:         number;
  span:          number;
  indent:        boolean;   // parallel sibling → shift bullet right
  isLastInGroup: boolean;
  meta:          AlertMeta;
}) {
  const [open, setOpen] = useState(false);
  const barLeft  = Math.round(((call.startTs - minTs) / span) * TRACK_W);
  // Prefer provider-reported duration_ms. When a provider omits it (VS Code),
  // use PreToolUse -> PostToolUse elapsed time; that fallback may include time
  // spent waiting for user approval, so the text label marks it as approximate.
  const barWidth = call.duration !== null
    ? Math.max(BAR_MIN, Math.round((call.duration / span) * TRACK_W))
    : BAR_MIN;
  const clampedWidth = Math.min(barWidth, TRACK_W - barLeft);

  return (
    <>
      {/* ── Main row ── */}
      <div
        role="button"
        tabIndex={0}
        onClick={() => setOpen(o => !o)}
        onKeyDown={e => e.key === 'Enter' && setOpen(o => !o)}
        style={{
          display:             'grid',
          gridTemplateColumns: ROW_COLS,
          columnGap:           6,
          alignItems:          'center',
          padding:             '3px 0',
          cursor:              'pointer',
          borderBottom: `1px solid rgba(128,128,128,${isLastInGroup ? '0.14' : '0.06'})`,
        }}
      >
        {/* Col 1 — Colored bullet (indent for parallel siblings) */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', paddingLeft: indent ? 8 : 0 }}>
          <div style={{
            width: 7, height: 7,
            borderRadius: '50%',
            background: barColor(call.toolName),
          }} />
        </div>

        {/* Col 2 — Timestamp */}
        <Typography.Text type="secondary" style={{ fontSize: 11 }}>
          {new Date(call.startTs).toLocaleTimeString()}
        </Typography.Text>

        {/* Col 3 — Tool name tag */}
        <div style={{ overflow: 'hidden' }}>
          <Tag
            color={tagColor(call.toolName)}
            style={{ margin: 0, fontSize: 11, maxWidth: '100%', overflow: 'hidden', textOverflow: 'ellipsis' }}
          >
            {call.toolName}
          </Tag>
        </div>

        {/* Col 4 — Severity badge */}
        <div style={{ overflow: 'hidden' }}>
          <SeverityBadge severity={meta.severity} />
        </div>

        {/* Col 5 — Policy action badge */}
        <div style={{ overflow: 'hidden' }}>
          <ActionBadge action={meta.action} />
        </div>

        {/* Col 5 — Detail text */}
        <Typography.Text
          ellipsis
          style={{ fontSize: 11 }}
          title={call.detailFull ?? call.detail ?? undefined}
        >
          {call.detail ?? (
            <Typography.Text type="secondary" style={{ fontSize: 11 }}>—</Typography.Text>
          )}
        </Typography.Text>

        {/* Col 6 — Duration (right-aligned) */}
        <Typography.Text
          type="secondary"
          style={{ fontSize: 11, textAlign: 'right' }}
          title={call.durationSource === 'elapsed'
            ? 'Elapsed from PreToolUse to PostToolUse; may include approval wait'
            : undefined}
        >
          {call.duration !== null
            ? `${call.durationSource === 'elapsed' ? '~' : ''}${call.duration} ms`
            : ''}
        </Typography.Text>

        {/* Col 7 — Timeline track */}
        <div style={{ width: TRACK_W, position: 'relative', height: 20 }}>
          <div style={{
            position: 'absolute', top: '50%', left: 0, right: 0,
            height: 1, background: 'rgba(128,128,128,0.12)',
          }} />
          <div style={{
            position:  'absolute',
            left:       barLeft,
            top:       '50%',
            transform: 'translateY(-50%)',
            width:      clampedWidth,
            height:     14,
            borderRadius: 3,
            background: barColor(call.toolName),
            boxShadow: `0 0 4px ${barColor(call.toolName)}55`,
          }} />
        </div>
      </div>

      {/* ── Expanded detail panel ── */}
      {open && (
        <ExpandedDetail call={call} />
      )}
    </>
  );
}

// ─── Expanded detail ──────────────────────────────────────────────────────────

function ExpandedDetail({ call }: { call: ToolCall }) {
  const hasInput    = call.input    && Object.keys(call.input).length > 0;
  const hasResponse = call.response && Object.keys(call.response).length > 0;
  const hasTiming   = call.duration !== null;
  if (!hasInput && !hasResponse && !hasTiming) return null;

  // Build a concise response summary (avoid dumping huge stdout).
  const respLines: string[] = [];
  if (call.duration !== null) {
    respLines.push(call.durationSource === 'elapsed'
      ? `elapsed: ~${call.duration} ms (may include approval wait)`
      : `duration: ${call.duration} ms`);
  }
  if (call.response) {
    const { stdout, stderr, interrupted } = call.response as Record<string, unknown>;
    if (typeof stdout === 'string' && stdout)
      respLines.push(`stdout: ${stdout.slice(0, 300)}${stdout.length > 300 ? '…' : ''}`);
    if (typeof stderr === 'string' && stderr)
      respLines.push(`stderr: ${stderr.slice(0, 200)}${stderr.length > 200 ? '…' : ''}`);
    if (interrupted) respLines.push('interrupted');
  }

  return (
    <div style={{
      padding:       '6px 8px 8px 36px',
      background:    'rgba(128,128,128,0.05)',
      borderBottom:  '1px solid rgba(128,128,128,0.12)',
      fontFamily:    'monospace',
      fontSize:       11,
    }}>
      {hasInput && (
        <div style={{ marginBottom: 4 }}>
          <Typography.Text type="secondary" style={{ fontSize: 10 }}>INPUT  </Typography.Text>
          <Typography.Text style={{ fontSize: 11, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
            {JSON.stringify(call.input, null, 2)}
          </Typography.Text>
        </div>
      )}
      {respLines.length > 0 && (
        <div>
          <Typography.Text type="secondary" style={{ fontSize: 10 }}>RESULT </Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 11 }}>
            {respLines.join(' · ')}
          </Typography.Text>
        </div>
      )}
    </div>
  );
}
