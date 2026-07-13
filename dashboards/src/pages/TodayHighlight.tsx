import { useEffect, useState } from 'react';
import { Button, Card, Col, Row, Space, Statistic, Table, Tag, Typography } from 'antd';
import {
  CodeOutlined,
  AlertOutlined,
  FileTextOutlined,
  GlobalOutlined,
  ThunderboltOutlined,
  TeamOutlined,
  ReadOutlined,
  EditOutlined,
  LeftOutlined,
  RightOutlined,
} from '@ant-design/icons';
import { PageHeader }    from '@/components/PageHeader';
import { SeverityBadge, ActionBadge } from '@/components/SeverityBadge';
import { api }           from '@/api/client';
import type { TodayMetrics } from '@/api/types';

const ACTION_ORDER   = ['block', 'ask', 'warn', 'allow'] as const;
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;

/** Format a Date as YYYY-MM-DD in local time. */
function toDateStr(d: Date): string {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function friendlyDate(d: Date): string {
  const todayStr = toDateStr(new Date());
  const dStr     = toDateStr(d);
  if (dStr === todayStr) return 'Today';
  const yesterday = new Date(); yesterday.setDate(yesterday.getDate() - 1);
  if (dStr === toDateStr(yesterday)) return 'Yesterday';
  return d.toLocaleDateString(undefined, { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
}

export default function TodayHighlight() {
  const [date, setDate] = useState(() => new Date());
  const [data, setData]     = useState<TodayMetrics | null>(null);
  const [loading, setLoading] = useState(true);

  const isToday = toDateStr(date) === toDateStr(new Date());

  // Re-fetch whenever the selected date changes.
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api.todayMetrics(toDateStr(date))
      .then(result => { if (!cancelled) setData(result); })
      .catch(() => { if (!cancelled) setData(null); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [date]);

  const stepDay = (delta: number) => {
    setDate(prev => {
      const next = new Date(prev);
      next.setDate(next.getDate() + delta);
      return next;
    });
  };

  const m = data;
  const totalAlerts = m
    ? Object.values(m.alerts_by_action).reduce((s, n) => s + n, 0)
    : 0;
  return (
    <div>
      <PageHeader
        title="Today's Highlight"
        description={friendlyDate(date)}
        extra={
          <Space>
            <Button size="small" icon={<LeftOutlined />} onClick={() => stepDay(-1)} />
            <Button size="small" disabled={isToday} onClick={() => setDate(new Date())}>
              Today
            </Button>
            <Button size="small" icon={<RightOutlined />} onClick={() => stepDay(1)} disabled={isToday} />
          </Space>
        }
      />

      {/* ── Row 1: Agent activity ── */}
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} md={6}>
          <Card size="small" loading={loading}>
            <Statistic
              title="Sessions"
              value={m?.sessions ?? 0}
              prefix={<TeamOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card size="small" loading={loading}>
            <Statistic
              title="Agent Turns"
              value={m?.requests ?? 0}
              prefix={<ThunderboltOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card size="small" loading={loading}>
            <Statistic
              title="Total Tool Calls"
              value={m?.tool_calls ?? 0}
              prefix={<CodeOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card size="small" loading={loading}>
            <Statistic
              title="Alerts"
              value={totalAlerts}
              prefix={<AlertOutlined />}
              valueStyle={totalAlerts > 0 ? { color: '#fa8c16' } : undefined}
            />
          </Card>
        </Col>
      </Row>

      {/* ── Row 2: File + network activity ── */}
      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} sm={12} md={6}>
          <Card size="small" loading={loading}>
            <Statistic
              title="Files Written / Edited"
              value={m?.files_written ?? 0}
              prefix={<EditOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card size="small" loading={loading}>
            <Statistic
              title="Files Read"
              value={m?.files_read ?? 0}
              prefix={<ReadOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card size="small" loading={loading}>
            <Statistic
              title="Web Searches"
              value={m?.web_searches ?? 0}
              prefix={<GlobalOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card size="small" loading={loading}>
            <Statistic
              title="URLs Fetched"
              value={m?.web_fetches ?? 0}
              prefix={<FileTextOutlined />}
            />
          </Card>
        </Col>
      </Row>

      {/* ── Row 3: Alert breakdown + top tools ── */}
      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        {/* Alert breakdown */}
        <Col xs={24} md={12}>
          <Card size="small" title="Alert breakdown" loading={loading}>
            <Row gutter={[8, 8]}>
              <Col span={12}>
                <Typography.Text type="secondary" style={{ fontSize: 12, display: 'block', marginBottom: 6 }}>
                  By action
                </Typography.Text>
                {ACTION_ORDER.map(action => {
                  const count = m?.alerts_by_action[action] ?? 0;
                  if (count === 0) return null;
                  return (
                    <div key={action} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                      <ActionBadge action={action} />
                      <Typography.Text style={{ fontSize: 13, fontWeight: 500 }}>{count}</Typography.Text>
                    </div>
                  );
                })}
                {totalAlerts === 0 && (
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>No alerts today</Typography.Text>
                )}
              </Col>
              <Col span={12}>
                <Typography.Text type="secondary" style={{ fontSize: 12, display: 'block', marginBottom: 6 }}>
                  By severity
                </Typography.Text>
                {SEVERITY_ORDER.map(sev => {
                  const count = m?.alerts_by_severity[sev] ?? 0;
                  if (count === 0) return null;
                  return (
                    <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                      <SeverityBadge severity={sev} />
                      <Typography.Text style={{ fontSize: 13, fontWeight: 500 }}>{count}</Typography.Text>
                    </div>
                  );
                })}
              </Col>
            </Row>
          </Card>
        </Col>

        {/* Top tools */}
        <Col xs={24} md={12}>
          <Card size="small" title="Tool usage" loading={loading}>
            {(m?.top_tools ?? []).length === 0 ? (
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                No tool calls recorded today.
              </Typography.Text>
            ) : (
              <Table
                size="small"
                pagination={false}
                dataSource={m?.top_tools ?? []}
                rowKey="tool_name"
                columns={[
                  {
                    title: 'Tool',
                    dataIndex: 'tool_name',
                    render: (name: string) => <Tag style={{ fontFamily: 'monospace' }}>{name}</Tag>,
                  },
                  {
                    title: 'Calls',
                    dataIndex: 'count',
                    align: 'right',
                    render: (n: number) => (
                      <Typography.Text strong>{n}</Typography.Text>
                    ),
                  },
                  {
                    title: 'Share',
                    dataIndex: 'count',
                    align: 'right',
                    render: (n: number) => {
                      const pct = m?.tool_calls ? Math.round((n / m.tool_calls) * 100) : 0;
                      return (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, justifyContent: 'flex-end' }}>
                          <div style={{ width: 60, height: 6, borderRadius: 3, background: 'rgba(128,128,128,0.15)', overflow: 'hidden' }}>
                            <div style={{ width: `${pct}%`, height: '100%', background: '#1677ff', borderRadius: 3 }} />
                          </div>
                          <Typography.Text type="secondary" style={{ fontSize: 11, width: 32 }}>{pct}%</Typography.Text>
                        </div>
                      );
                    },
                  },
                ]}
              />
            )}
          </Card>
        </Col>
      </Row>
    </div>
  );
}
