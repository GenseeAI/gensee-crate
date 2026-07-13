import { useState } from 'react';
import {
  Alert,
  Badge,
  Button,
  Card,
  Col,
  Row,
  Select,
  Space,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import { ClearOutlined, PauseCircleOutlined, PlayCircleOutlined } from '@ant-design/icons';
import { PageHeader }  from '@/components/PageHeader';
import { EmptyPlaceholder } from '@/components/EmptyPlaceholder';
import { useRealtime } from '@/hooks/useRealtime';
import { api }         from '@/api/client';
import type { AgentEvent } from '@/api/types';

const { Text } = Typography;

const EVENT_TYPE_COLORS: Record<string, string> = {
  PreToolUse:       'blue',
  PostToolUse:      'green',
  UserPromptSubmit: 'purple',
  Stop:             'default',
};

function EventRow({ event }: { event: AgentEvent }) {
  const color = EVENT_TYPE_COLORS[event.type] ?? 'default';
  return (
    <div
      style={{
        display:       'flex',
        gap:           12,
        padding:       '6px 0',
        borderBottom:  '1px solid rgba(128,128,128,0.12)',
        alignItems:    'flex-start',
      }}
    >
      <Text type="secondary" style={{ fontSize: 11, flexShrink: 0, width: 80 }}>
        {new Date(event.ts).toLocaleTimeString()}
      </Text>
      <Tag color={color} style={{ flexShrink: 0 }}>{event.type}</Tag>
      <Text style={{ fontSize: 12, flex: 1 }} ellipsis>
        {event.tool_name
          ? <><Text code style={{ fontSize: 11 }}>{event.tool_name}</Text>{' '}</>
          : null}
        <Text type="secondary">{event.cwd}</Text>
      </Text>
      <Text type="secondary" style={{ fontSize: 11, flexShrink: 0 }}>
        pid {event.pid}
      </Text>
    </div>
  );
}

export default function LiveFeed() {
  const [enabled, setEnabled]   = useState(true);
  const [typeFilter, setFilter] = useState<string | undefined>(undefined);

  const { events, connected, error, clear } = useRealtime(api.realtimeUrl(), enabled);

  const filtered = typeFilter
    ? events.filter(e => e.type === typeFilter)
    : events;

  const statusBadge = connected
    ? <Badge status="processing" color="green" text="Connected" />
    : <Badge status="error" text="Disconnected" />;

  return (
    <div>
      <PageHeader
        title="Live Feed"
        description="Real-time stream of agent hook events."
        extra={
          <Space>
            {statusBadge}
            <Select
              placeholder="Filter by type"
              allowClear
              style={{ width: 170 }}
              size="small"
              value={typeFilter}
              onChange={setFilter}
              options={[
                { value: 'PreToolUse',       label: 'PreToolUse'       },
                { value: 'PostToolUse',      label: 'PostToolUse'      },
                { value: 'UserPromptSubmit', label: 'UserPromptSubmit' },
                { value: 'Stop',             label: 'Stop'             },
              ]}
            />
            <Tooltip title={enabled ? 'Pause' : 'Resume'}>
              <Button
                size="small"
                icon={enabled ? <PauseCircleOutlined /> : <PlayCircleOutlined />}
                onClick={() => setEnabled(e => !e)}
              />
            </Tooltip>
            <Tooltip title="Clear">
              <Button size="small" icon={<ClearOutlined />} onClick={clear} />
            </Tooltip>
          </Space>
        }
      />

      {error && (
        <Alert
          message={error}
          type="warning"
          showIcon
          closable
          style={{ marginBottom: 16 }}
        />
      )}

      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card
            size="small"
            title={`Events (${filtered.length} / ${events.length} total)`}
            style={{ fontFamily: 'monospace' }}
          >
            {filtered.length === 0 ? (
              <EmptyPlaceholder
                description={
                  connected
                    ? 'Waiting for agent events…'
                    : 'Not connected — check that the API server is running.'
                }
              />
            ) : (
              filtered.map(e => <EventRow key={e.event_id} event={e} />)
            )}
          </Card>
        </Col>
      </Row>
    </div>
  );
}
