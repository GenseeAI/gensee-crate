import { useCallback } from 'react';
import { Button, Card, Col, Row, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { ReloadOutlined }    from '@ant-design/icons';
import { useNavigate, useParams } from 'react-router-dom';
import { PageHeader }        from '@/components/PageHeader';
import { EmptyPlaceholder }  from '@/components/EmptyPlaceholder';
import { useApi }            from '@/hooks/useApi';
import { api }               from '@/api/client';
import type { Session }      from '@/api/types';

const { Text } = Typography;

const COLUMNS: ColumnsType<Session> = [
  {
    title:     'Session ID',
    dataIndex: 'session_id',
    key:       'session_id',
    render:    v => <Text code style={{ fontSize: 11 }}>{v}</Text>,
    ellipsis:  true,
  },
  { title: 'Agent', dataIndex: 'agent_id', key: 'agent_id', width: 140 },
  {
    title:     'First event',
    dataIndex: 'first_event_at',
    key:       'first_event_at',
    width:     160,
    render:    v => new Date(v).toLocaleString(),
  },
  {
    title:     'Last event',
    dataIndex: 'last_event_at',
    key:       'last_event_at',
    width:     160,
    render:    v => (v ? new Date(v).toLocaleString() : '—'),
  },
  {
    title:  'Flagged',
    key:    'flagged',
    width:  80,
    render: (_v, row) =>
      row.flagged ? <Tag color="red">Yes</Tag> : <Tag color="default">No</Tag>,
  },
];

export default function Sessions() {
  const navigate   = useNavigate();
  const { sessionId } = useParams<{ sessionId?: string }>();

  const fetchSessions = useCallback(() => api.sessions(100), []);
  const { data: sessions, loading, refetch } = useApi(fetchSessions);

  // Detail view placeholder — shown when a session is selected.
  if (sessionId) {
    return <SessionDetail sessionId={sessionId} onBack={() => navigate('/sessions')} />;
  }

  return (
    <div>
      <PageHeader
        title="Sessions"
        description="All recorded agent sessions."
        extra={
          <Button size="small" icon={<ReloadOutlined />} onClick={refetch}>
            Refresh
          </Button>
        }
      />
      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card size="small">
            <Table<Session>
              columns={COLUMNS}
              dataSource={sessions ?? []}
              rowKey="session_id"
              loading={loading}
              size="small"
              pagination={{ pageSize: 20, showSizeChanger: false }}
              locale={{ emptyText: <EmptyPlaceholder description="No sessions yet." /> }}
              onRow={row => ({
                style:   { cursor: 'pointer' },
                onClick: () => navigate(`/sessions/${row.session_id}`),
              })}
            />
          </Card>
        </Col>
      </Row>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Session detail panel — placeholder
// ---------------------------------------------------------------------------

function SessionDetail({ sessionId, onBack }: { sessionId: string; onBack: () => void }) {
  const fetchSession = useCallback(
    () => api.session(sessionId),
    [sessionId],
  );
  const { data: session, loading } = useApi(fetchSession);

  return (
    <div>
      <PageHeader
        title={`Session: ${sessionId.slice(0, 16)}…`}
        description="Requests and events within this session."
        extra={<Button size="small" onClick={onBack}>← Back to Sessions</Button>}
      />
      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card size="small" loading={loading}>
            {session ? (
              <pre style={{ fontSize: 12, margin: 0 }}>
                {JSON.stringify(session, null, 2)}
              </pre>
            ) : (
              <EmptyPlaceholder description="Session not found." />
            )}
          </Card>
        </Col>
      </Row>
    </div>
  );
}
