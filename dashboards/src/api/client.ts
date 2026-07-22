/**
 * Tauri IPC client — replaces the HTTP fetch() layer.
 *
 * Every function calls a #[tauri::command] in the Rust backend via invoke().
 * No TCP port is used; communication goes through the Tauri WebView IPC bridge.
 */
import { invoke } from '@tauri-apps/api/core';
import type {
  Session,
  Request,
  AgentEvent,
  Alert,
  ArtifactGraphData,
  HumanFeedback,
  DashboardState,
  StoreSecurityStatus,
  LineageGraphData,
  ActivityStats,
  SeverityCount,
  SystemEvent,
  TodayMetrics,
  TransactionEvent,
} from './types';

export const api = {
  // Dashboard state
  state: () => invoke<DashboardState>('get_state'),
  storeSecurity: () => invoke<StoreSecurityStatus>('get_store_security'),

  // Sessions
  sessions: (limit = 50, offset = 0, hideEmpty = false) =>
    invoke<Session[]>('get_sessions', { limit, offset, hideEmpty }),
  session: (id: string) => invoke<Session>('get_session', { id }),
  sessionRequests: (id: string, limit = 50) =>
    invoke<Request[]>('get_session_requests', { id, limit }),
  sessionEvents: (id: string) =>
    invoke<SystemEvent[]>('get_session_events', { id }),

  // Agent events
  agentEvents: (params?: Partial<{ request_id: number; limit: number; offset: number }>) =>
    invoke<AgentEvent[]>('get_agent_events', {
      requestId: params?.request_id,
      limit:     params?.limit,
      offset:    params?.offset,
    }),

  // Alerts
  alerts: (params?: Partial<{ severity: string; action: string; request_id: number; limit: number; offset: number }>) =>
    invoke<Alert[]>('get_alerts', {
      severity:  params?.severity,
      action:    params?.action,
      requestId: params?.request_id,
      limit:     params?.limit,
      offset:    params?.offset,
    }),

  // Stats charts
  activityStats: (range: '24h' | '7d' = '24h') =>
    invoke<ActivityStats>('get_activity_stats', { range }),
  severityStats: () =>
    invoke<SeverityCount[]>('get_severity_stats'),

  // Artifacts
  artifacts: (limit = 50, offset = 0) =>
    invoke<unknown[]>('get_artifacts', { limit, offset }),
  artifactLineage: (id: number) =>
    invoke<LineageGraphData>('get_artifact_lineage', { id }),
  artifactGraph: () =>
    invoke<ArtifactGraphData>('get_artifact_graph'),

  // Policy
  policy: () => invoke<unknown>('get_policy'),
  savePolicy: (body: unknown) => invoke<void>('save_policy', { body }),

  // Feedback
  feedback: (limit = 50, offset = 0) =>
    invoke<HumanFeedback[]>('get_feedback', { limit, offset }),
  recordFeedback: (data: Partial<HumanFeedback>) =>
    invoke<{ feedback_id: number }>('record_feedback', { data }),

  // Today metrics
  todayMetrics: (date?: string) =>
    invoke<TodayMetrics>('get_today_metrics', { date }),

  // Transactional environments
  transactionEvents: (limit = 500, offset = 0) =>
    invoke<TransactionEvent[]>('get_transaction_events', { limit, offset }),
};
