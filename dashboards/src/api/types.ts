// ---------------------------------------------------------------------------
// API types — mirror the gensee-crate SQLite schema (db/schema.sql).
// ---------------------------------------------------------------------------

export interface Session {
  session_id: string;
  agent_id: string;
  first_event_at: number;
  last_event_at: number | null;
  flagged: number;
  /** Computed by the API — number of request rows for this session. */
  req_count?: number;
  /** Computed by the API — number of agent_event rows for this session. */
  event_count?: number;
}

export interface Request {
  request_id: number;
  session_id: string;
  original_user_prompt: string | null;
  final_response: string | null;
  events: unknown;
  file_accessed_rate: number;
  network_rate: number;
}

export interface AgentEvent {
  event_id: number;
  pid: number;
  request_id: number;
  ts: number;
  source: string;
  type: string;
  cwd: string;
  permission_mode: string | null;
  tool_name: string | null;
  tool_input: unknown;
  tool_response: unknown;
  tool_use_id: string | null;
}

export interface SystemEvent {
  event_id: number;
  pid: number;
  request_id: number;
  ts: number;
  source: string;
  type: string;
  cwd: string;
  args: unknown;
  /** Computed by the API from args JSON — the affected file path. */
  path: string | null;
  /** Computed by the API — the process that triggered the event. */
  process: string | null;
}

export type AlertSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type AlertAction   = 'allow' | 'warn' | 'ask' | 'block';

export interface Alert {
  alert_id: number;
  request_id: number | null;
  entity_kind: 'request' | 'agent_event' | 'system_event' | 'artifact' | null;
  entity_id: number | null;
  severity: AlertSeverity;
  action: AlertAction;
  rule_id: string;
  message: string;
  path: string | null;
  evidence: unknown;
  created_at: number;
}

export interface Artifact {
  artifact_id: number;
  kind: string;
  uri: string;
  digest: string;
  created_at: number | null;
  updated_at: number | null;
  metadata: unknown;
}

/** Row from artifact_facts — enriched view used by the lineage graph. */
export interface ArtifactFact {
  kind: string;
  uri: string;
  current_digest: string;
  last_seen_at: number | null;
  is_agent_authored: number;
  risk_level: string | null;
  is_memory_artifact: number;
  is_control_plane: number;
  is_persistent_target: number;
  last_modified_source: string | null;
}

export interface ArtifactEdge {
  type: string;
  confidence: number;
  src_uri: string;
  dst_uri: string;
}

export interface ArtifactGraphData {
  facts: ArtifactFact[];
  edges: ArtifactEdge[];
}

export interface Relation {
  relation_id: number;
  src_kind: string;
  src_id: number;
  dst_kind: string;
  dst_id: number;
  relation_type: string;
  confidence: number;
  evidence: unknown;
  created_at: number;
}

export interface HumanFeedback {
  feedback_id: number;
  event_key: string | null;
  tool_use_id: string | null;
  session_id: string | null;
  gensee_action: string | null;
  human_verdict: 'agree' | 'allow' | 'deny';
  label: string | null;
  rule_id: string | null;
  path: string | null;
  note: string | null;
  created_at: number;
}

// ---------------------------------------------------------------------------
// Composite / derived types used by the UI.
// ---------------------------------------------------------------------------

export interface DashboardState {
  sessions_count: number;
  requests_count: number;
  agent_events_count: number;
  system_events_count: number;
  alerts_count: number;
  recent_high_alerts: number;
  artifacts_count: number;
}

export interface StoreSecurityStatus {
  database_exists: boolean;
  encrypted_at_rest: boolean;
  db_path: string;
}

export interface BucketCount {
  bucket: number;   // Unix epoch ms
  count:  number;
}

export interface ActivityStats {
  range:       '24h' | '7d';
  bucketMs:    number;
  sessions:    BucketCount[];
  agentEvents: BucketCount[];
  alerts:      BucketCount[];
}

export interface SeverityCount {
  severity: string;
  count:    number;
}

export interface TodayMetrics {
  sessions:       number;
  requests:       number;
  tool_calls:     number;
  files_written:  number;
  files_read:     number;
  web_searches:   number;
  web_fetches:    number;
  bash_commands:  number;
  alerts_by_action:   Record<string, number>;
  alerts_by_severity: Record<string, number>;
  top_tools: Array<{ tool_name: string; count: number }>;
}

export interface LineageGraphData {  nodes: Array<{ id: string; kind: string; label: string; uri?: string }>;
  edges: Array<{
    source: string;
    target: string;
    relation_type: string;
    confidence: number;
  }>;
}

export interface PaginatedResult<T> {
  rows: T[];
  total: number;
  limit: number;
  offset: number;
}
