import { useCallback, useState } from 'react';
import { Card, Col, Row, Segmented, Table, Typography } from 'antd';
import {
  AlertOutlined,
  FileOutlined,
  TeamOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';
import { Area, Pie } from '@ant-design/plots';
import { PageHeader }              from '@/components/PageHeader';
import { StatCard }                from '@/components/StatCard';
import { SeverityBadge, ActionBadge } from '@/components/SeverityBadge';
import { AlertDetails }             from '@/components/AlertDetails';
import { useApi }                  from '@/hooks/useApi';
import { api }                     from '@/api/client';
import { useTheme }                from '@/hooks/useTheme';
import type { Alert, BucketCount, SeverityCount } from '@/api/types';

// ---------------------------------------------------------------------------
// Alert table columns
// ---------------------------------------------------------------------------

const ALERT_COLUMNS = [
  {
    title: 'Severity', dataIndex: 'severity', key: 'severity', width: 100,
    render: (v: string) => <SeverityBadge severity={v} />,
  },
  {
    title: 'Action', dataIndex: 'action', key: 'action', width: 80,
    render: (v: string) => <ActionBadge action={v} />,
  },
  {
    title: 'Rule', dataIndex: 'rule_id', key: 'rule_id', width: 220, ellipsis: true,
    render: (v: string) => <Typography.Text ellipsis={{ tooltip: v }} style={{ fontSize: 11 }}>{v}</Typography.Text>,
  },
  {
    title: 'Message', dataIndex: 'message', key: 'message', ellipsis: true,
    render: (v: string) => <Typography.Text ellipsis={{ tooltip: v }}>{v}</Typography.Text>,
  },
  {
    title: 'Time', dataIndex: 'created_at', key: 'created_at', width: 160,
    render: (v: number) => new Date(v).toLocaleString(),
  },
];

// ---------------------------------------------------------------------------
// Severity colours (mirrors SeverityBadge palette)
// ---------------------------------------------------------------------------

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#722ed1',
  high:     '#f5222d',
  medium:   '#fa8c16',
  low:      '#13c2c2',
  info:     '#8c8c8c',
};

// ---------------------------------------------------------------------------
// Helpers: zero-fill sparse bucket arrays
// ---------------------------------------------------------------------------

function fillBuckets(raw: BucketCount[], range: '24h' | '7d'): BucketCount[] {
  const bucketMs = range === '7d' ? 86_400_000 : 3_600_000;
  const slots    = range === '7d' ? 7 : 24;
  const now      = Date.now();
  const from     = Math.floor((now - slots * bucketMs) / bucketMs) * bucketMs;

  const map = new Map(raw.map(r => [r.bucket, r.count]));
  return Array.from({ length: slots }, (_, i) => {
    const bucket = from + i * bucketMs;
    return { bucket, count: map.get(bucket) ?? 0 };
  });
}

function bucketLabel(bucket: number, range: '24h' | '7d'): string {
  const d = new Date(bucket);
  return range === '7d'
    ? d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
    : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

// ---------------------------------------------------------------------------
// Activity area chart
// ---------------------------------------------------------------------------

type Metric = 'sessions' | 'agentEvents' | 'alerts';
const METRIC_OPTIONS = [
  { label: 'Sessions',     value: 'sessions'    },
  { label: 'Agent Events', value: 'agentEvents' },
  { label: 'Alerts',       value: 'alerts'      },
];
const METRIC_COLOR: Record<Metric, string> = {
  sessions:    '#1677ff',
  agentEvents: '#faad14',
  alerts:      '#f5222d',
};

function ActivityChart({ isDark }: { isDark: boolean }) {
  const [range,  setRange]  = useState<'24h' | '7d'>('24h');
  const [metric, setMetric] = useState<Metric>('sessions');

  const fetchActivity = useCallback(() => api.activityStats(range), [range]);
  const { data: stats, loading } = useApi(fetchActivity);

  const raw: BucketCount[] = stats ? stats[metric] : [];
  const filled = fillBuckets(raw, range);
  const chartData = filled.map(r => ({
    time:  bucketLabel(r.bucket, range),
    count: r.count,
  }));

  return (
    <Card
      title="Activity over time"
      size="small"
      extra={
        <Segmented
          size="small"
          value={range}
          onChange={v => setRange(v as '24h' | '7d')}
          options={[{ label: '24 h', value: '24h' }, { label: '7 d', value: '7d' }]}
        />
      }
    >
      <Segmented
        size="small"
        value={metric}
        onChange={v => setMetric(v as Metric)}
        options={METRIC_OPTIONS}
        style={{ marginBottom: 12 }}
      />
      {loading ? (
        <div style={{ height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Typography.Text type="secondary">Loading…</Typography.Text>
        </div>
      ) : (
        <Area
          data={chartData}
          xField="time"
          yField="count"
          height={200}
          style={{ fill: METRIC_COLOR[metric], fillOpacity: 0.15, stroke: METRIC_COLOR[metric] }}
          axis={{ y: { min: 0 } }}
          label={false}
          legend={{ itemMarkerFill: METRIC_COLOR[metric] }}
          theme={{ type: isDark ? 'dark' : 'light' }}
        />
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Severity donut chart
// ---------------------------------------------------------------------------

function SeverityDonut({ isDark }: { isDark: boolean }) {
  const { data: rows, loading } = useApi(api.severityStats);

  const ALL_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
  const map   = new Map((rows ?? []).map((r: SeverityCount) => [r.severity, r.count]));
  const data  = ALL_SEVERITIES.map(s => ({ severity: s, count: map.get(s) ?? 0 }));
  const total = data.reduce((s, r) => s + r.count, 0);

  return (
    <Card title="Alert severity breakdown" size="small">
      {loading ? (
        <div style={{ height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Typography.Text type="secondary">Loading…</Typography.Text>
        </div>
      ) : (
        <div style={{ position: 'relative' }}>
          <Pie
            data={data}
            angleField="count"
            colorField="severity"
            radius={0.85}
            innerRadius={0.62}
            height={200}
            scale={{ color: {
              domain: ALL_SEVERITIES,
              range:  ALL_SEVERITIES.map(s => SEVERITY_COLOR[s]),
            }}}
            label={false}
            legend={{ position: 'right' }}
            theme={{ type: isDark ? 'dark' : 'light' }}
          />
          {/* Center statistic overlay */}
          <div style={{
            position:  'absolute',
            top: '50%', left: '50%',
            transform: 'translate(-50%, -50%)',
            textAlign: 'center',
            pointerEvents: 'none',
            lineHeight: 1.3,
          }}>
            <div style={{ fontSize: 22, fontWeight: 600, color: isDark ? '#fff' : '#333' }}>
              {total}
            </div>
            <div style={{ fontSize: 11, color: isDark ? '#888' : '#666' }}>alerts</div>
          </div>
        </div>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Dashboard page
// ---------------------------------------------------------------------------

export default function Dashboard() {
  const { isDark } = useTheme();

  const { data: state, loading: stateLoading } = useApi(api.state);
  const fetchAlerts = useCallback(() => api.alerts({ limit: 10 }), []);
  const { data: recentAlerts, loading: alertsLoading } = useApi(fetchAlerts);

  const stats = [
    { title: 'Sessions',         value: state?.sessions_count     ?? '—', icon: <TeamOutlined />,      color: '#1677ff' },
    { title: 'Requests',         value: state?.requests_count     ?? '—', icon: <FileOutlined />,      color: '#52c41a' },
    { title: 'Agent Events',     value: state?.agent_events_count ?? '—', icon: <ThunderboltOutlined />, color: '#faad14' },
    { title: 'High Alerts (24 h)', value: state?.recent_high_alerts ?? '—', icon: <AlertOutlined />,   color: '#e53935' },
  ] satisfies Array<{ title: string; value: string | number; icon: React.ReactNode; color: string }>;

  return (
    <div>
      <PageHeader
        title="Dashboard"
        description="Overview of agent activity, security alerts, and system health."
      />

      {/* Stat cards */}
      <Row gutter={[16, 16]}>
        {stats.map(s => (
          <Col xs={24} sm={12} xl={6} key={s.title}>
            <StatCard {...s} loading={stateLoading} />
          </Col>
        ))}
      </Row>

      {/* Charts */}
      <Row gutter={[16, 16]} style={{ marginTop: 24 }}>
        <Col xs={24} lg={14}>
          <ActivityChart isDark={isDark} />
        </Col>
        <Col xs={24} lg={10}>
          <SeverityDonut isDark={isDark} />
        </Col>
      </Row>

      {/* Recent alerts */}
      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col span={24}>
          <Card title="Recent Alerts" size="small">
            <Table<Alert>
              columns={ALERT_COLUMNS}
              dataSource={recentAlerts ?? []}
              loading={alertsLoading}
              rowKey="alert_id"
              size="small"
              pagination={false}
              expandable={{
                expandedRowRender: alert => <AlertDetails alert={alert} />,
                rowExpandable: () => true,
              }}
              locale={{ emptyText: 'No recent alerts — all clear.' }}
            />
          </Card>
        </Col>
      </Row>
    </div>
  );
}
