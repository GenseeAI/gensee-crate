import { useCallback, useState } from 'react';
import {
  Button,
  Card,
  Col,
  Collapse,
  Row,
  Select,
  Space,
  Switch,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { PageHeader }       from '@/components/PageHeader';
import { EmptyPlaceholder } from '@/components/EmptyPlaceholder';
import { SeverityBadge }    from '@/components/SeverityBadge';
import { useApi }           from '@/hooks/useApi';
import { api }              from '@/api/client';
import type { Session, Request, SystemEvent } from '@/api/types';
import { ToolCallGraph } from '@/components/ToolCallGraph';

// ---------------------------------------------------------------------------
// Sessions whose content is filesystem events rather than agent turns.
// Everything NOT in this set uses RequestsPanel + nested agent_events.
// ---------------------------------------------------------------------------
const SYSTEM_BASED = new Set(['sidecar-watch', 'system-monitor']);

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------
const SOURCE_OPTIONS = [
  { value: 'claude-code',    label: 'Claude Code'    },
  { value: 'codex',          label: 'Codex'          },
  { value: 'antigravity',    label: 'Antigravity'    },
  { value: 'sidecar-watch',  label: 'Sidecar Watch'  },
  { value: 'system-monitor', label: 'System Monitor' },
];

export default function Timeline() {
  const [source,    setSource]    = useState<string | undefined>(undefined);
  const [hideEmpty, setHideEmpty] = useState(true);

  const fetchSessions = useCallback(
    () => api.sessions(100, 0, hideEmpty),
    [hideEmpty],
  );
  const { data: sessions, loading, refetch } = useApi(fetchSessions);

  const filtered = source
    ? (sessions ?? []).filter(s => s.agent_id.includes(source))
    : (sessions ?? []);

  return (
    <div>
      <PageHeader
        title="Timeline"
        description="Chronological history of agent sessions and requests."
        extra={
          <Space>
            <Select
              placeholder="Filter by agent"
              allowClear
              style={{ width: 160 }}
              size="small"
              value={source}
              onChange={setSource}
              options={SOURCE_OPTIONS}
            />
            <Tooltip title="Hide sessions with no requests or events">
              <Space size={4}>
                <Switch
                  size="small"
                  checked={hideEmpty}
                  onChange={setHideEmpty}
                />
                <Typography.Text style={{ fontSize: 12 }}>Hide empty</Typography.Text>
              </Space>
            </Tooltip>
            <Button size="small" icon={<ReloadOutlined />} onClick={refetch}>
              Refresh
            </Button>
          </Space>
        }
      />

      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card size="small" loading={loading}>
            {filtered.length === 0 ? (
              <EmptyPlaceholder description="No sessions recorded yet." />
            ) : (
              <Collapse
                size="small"
                items={filtered.map(s => ({
                  key:   s.session_id,
                  label: <SessionLabel session={s} />,
                  children: SYSTEM_BASED.has(s.agent_id)
                    ? <SystemEventsPanel sessionId={s.session_id} />
                    : <RequestsPanel    sessionId={s.session_id} />,
                }))}
              />
            )}
          </Card>
        </Col>
      </Row>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Session row label
// ---------------------------------------------------------------------------

function SessionLabel({ session }: { session: Session }) {
  const isSystem = session.session_id === 'system';
  return (
    <Space size={12}>
      {session.flagged ? <SeverityBadge severity="high" /> : null}
      <Typography.Text code style={{ fontSize: 11 }}>
        {isSystem ? 'system' : `${session.session_id.slice(0, 16)}…`}
      </Typography.Text>
      <Tag color={isSystem ? 'orange' : undefined}>{session.agent_id}</Tag>
      {isSystem && (
        <Tag color="red" style={{ fontSize: 11 }}>unmatched filesystem effects</Tag>
      )}
      {session.req_count !== undefined && (
        <Typography.Text type="secondary" style={{ fontSize: 11 }}>
          {session.req_count} req · {session.event_count ?? 0} events
        </Typography.Text>
      )}
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        {new Date(session.first_event_at).toLocaleString()}
      </Typography.Text>
    </Space>
  );
}

// ---------------------------------------------------------------------------
// Panel for agent-based sessions: shows requests (user prompts / responses)
// ---------------------------------------------------------------------------

function RequestsPanel({ sessionId }: { sessionId: string }) {
  const fetchRequests = useCallback(
    () => api.sessionRequests(sessionId, 20),
    [sessionId],
  );
  const { data: requests, loading } = useApi(fetchRequests);

  if (loading) return <Typography.Text type="secondary">Loading…</Typography.Text>;
  if (!requests?.length) {
    return <EmptyPlaceholder description="No requests in this session yet." />;
  }

  return (
    <Collapse
      size="small"
      ghost
      items={requests.map((r: Request) => ({
        key:   r.request_id,
        label: (
          <Typography.Text
            style={{ fontSize: 12 }}
            ellipsis={{ tooltip: r.original_user_prompt ?? undefined }}
          >
            {r.original_user_prompt ?? (
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>(no prompt)</Typography.Text>
            )}
          </Typography.Text>
        ),
        children: <ToolCallGraph requestId={r.request_id} />,
      }))}
    />
  );
}

// ---------------------------------------------------------------------------
// Panel for watch/monitor sessions: shows system_events (file effects)
// ---------------------------------------------------------------------------

function SystemEventsPanel({ sessionId }: { sessionId: string }) {
  const fetchEvents = useCallback(
    () => api.sessionEvents(sessionId),
    [sessionId],
  );
  const { data: events, loading } = useApi(fetchEvents);

  if (loading) return <Typography.Text type="secondary">Loading…</Typography.Text>;
  if (!events?.length) {
    return (
      <EmptyPlaceholder
        description="No file-system effects recorded in this watch session."
      />
    );
  }

  return (
    <div style={{ paddingLeft: 8, fontFamily: 'monospace' }}>
      {events.map((e: SystemEvent) => {
        const displayPath = e.path ?? e.cwd ?? '';
        const processName = e.process ? e.process.split('/').pop() : null;
        return (
          <div
            key={e.event_id}
            style={{
              display:      'flex',
              gap:          12,
              padding:      '5px 0',
              borderBottom: '1px solid rgba(128,128,128,0.12)',
              alignItems:   'center',
            }}
          >
            <Typography.Text type="secondary" style={{ fontSize: 11, width: 75, flexShrink: 0 }}>
              {new Date(e.ts).toLocaleTimeString()}
            </Typography.Text>
            <Tag style={{ flexShrink: 0 }}>{e.type}</Tag>
            {processName && (
              <Typography.Text
                type="secondary"
                style={{ fontSize: 11, width: 130, flexShrink: 0 }}
                ellipsis={{ tooltip: e.process }}
              >
                {processName}
              </Typography.Text>
            )}
            <Typography.Text style={{ fontSize: 11 }} ellipsis title={displayPath}>
              {displayPath || <Typography.Text type="secondary">(no path)</Typography.Text>}
            </Typography.Text>
          </div>
        );
      })}
    </div>
  );
}
