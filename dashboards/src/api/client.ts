import type {
  Session,
  Request,
  AgentEvent,
  Alert,
  Artifact,
  ArtifactGraphData,
  HumanFeedback,
  DashboardState,
  LineageGraphData,
  ActivityStats,
  SeverityCount,
  SystemEvent,
  TodayMetrics,
} from './types';

/**
 * Base URL for the versioned API.
 * Override with VITE_API_BASE_URL in .env for non-standard setups.
 */
const BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '/api/v1';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async function get<T>(
  path: string,
  params?: Record<string, string | number | boolean>,
): Promise<T> {
  const url = new URL(`${BASE}${path}`, window.location.origin);
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
    });
  }
  const res = await fetch(url.toString(), {
    headers: { 'X-Gensee-Dashboard': '1' },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`[${res.status}] ${text || res.statusText}`);
  }
  return res.json() as Promise<T>;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Gensee-Dashboard': '1',
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`[${res.status}] ${text || res.statusText}`);
  }
  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Public API surface
// ---------------------------------------------------------------------------

export const api = {
  // Dashboard summary counts.
  state: () => get<DashboardState>('/state'),

  // Sessions.
  sessions: (limit = 50, offset = 0, hideEmpty = false) =>
    get<Session[]>('/sessions', { limit, offset, ...(hideEmpty && { hide_empty: 'true' }) }),
  session: (id: string) => get<Session>(`/sessions/${encodeURIComponent(id)}`),
  sessionRequests: (id: string, limit = 50) =>
    get<Request[]>(`/sessions/${encodeURIComponent(id)}/requests`, { limit }),
  sessionEvents: (id: string) =>
    get<SystemEvent[]>(`/sessions/${encodeURIComponent(id)}/events`),

  // Agent events.
  agentEvents: (params?: Partial<{ request_id: number; limit: number; offset: number }>) =>
    get<AgentEvent[]>('/events/agent', params as Record<string, number>),

  // Alerts.
  alerts: (params?: Partial<{ severity: string; action: string; request_id: number; limit: number; offset: number }>) =>
    get<Alert[]>('/alerts', params as Record<string, string | number>),

  // Dashboard stats charts.
  activityStats: (range: '24h' | '7d' = '24h') =>
    get<ActivityStats>('/stats/activity', { range }),
  severityStats: () =>
    get<SeverityCount[]>('/stats/severity'),

  // Artifacts & lineage.
  artifacts: (limit = 50, offset = 0) =>
    get<Artifact[]>('/artifacts', { limit, offset }),
  artifactLineage: (id: number) =>
    get<LineageGraphData>(`/artifacts/${id}/lineage`),
  artifactGraph: () =>
    get<ArtifactGraphData>('/artifacts/graph'),

  // Policy document.
  policy: () => get<unknown>('/policy'),
  savePolicy: (body: unknown) => post<{ ok: boolean }>('/policy', body),

  // Human feedback.
  feedback: (limit = 50, offset = 0) =>
    get<HumanFeedback[]>('/feedback', { limit, offset }),
  recordFeedback: (data: Partial<HumanFeedback>) =>
    post<{ feedback_id: number }>('/feedback', data),

  /** SSE endpoint URL for the Live Feed page. */
  realtimeUrl: () => `${BASE}/events/stream`,

  // Today's (or any day's) activity metrics.
  todayMetrics: (date?: string) =>
    get<TodayMetrics>('/metrics/today', date ? { date } : undefined),
};
