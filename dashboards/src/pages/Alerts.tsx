import { useCallback, useState } from 'react';
import { Button, Card, Col, Row, Select, Space, Table, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { ReloadOutlined }    from '@ant-design/icons';
import { PageHeader }        from '@/components/PageHeader';
import { SeverityBadge, ActionBadge } from '@/components/SeverityBadge';
import { AlertDetails }      from '@/components/AlertDetails';
import { EmptyPlaceholder }  from '@/components/EmptyPlaceholder';
import { useApi }            from '@/hooks/useApi';
import { api }               from '@/api/client';
import type { Alert, AlertSeverity, AlertAction } from '@/api/types';

const { Text } = Typography;

const SEVERITY_OPTIONS: { value: AlertSeverity; label: string }[] = [
  { value: 'info',     label: 'Info'     },
  { value: 'low',      label: 'Low'      },
  { value: 'medium',   label: 'Medium'   },
  { value: 'high',     label: 'High'     },
  { value: 'critical', label: 'Critical' },
];

const ACTION_OPTIONS: { value: AlertAction; label: string }[] = [
  { value: 'allow', label: 'Allow' },
  { value: 'warn',  label: 'Warn'  },
  { value: 'ask',   label: 'Ask'   },
  { value: 'block', label: 'Block' },
];

const COLUMNS: ColumnsType<Alert> = [
  {
    title:     'Severity',
    dataIndex: 'severity',
    key:       'severity',
    width:     100,
    render:    v => <SeverityBadge severity={v} />,
  },
  {
    title:     'Action',
    dataIndex: 'action',
    key:       'action',
    width:     80,
    render:    v => <ActionBadge action={v} />,
  },
  {
    title: 'Rule', dataIndex: 'rule_id', key: 'rule_id', width: 220, ellipsis: true,
    render: (v: string) => <Text ellipsis={{ tooltip: v }} style={{ fontSize: 11 }}>{v}</Text>,
  },
  {
    title: 'Message', dataIndex: 'message', key: 'message', ellipsis: true,
    render: (v: string) => <Text ellipsis={{ tooltip: v }}>{v}</Text>,
  },
  { title: 'Path',    dataIndex: 'path',     key: 'path',     width: 200, ellipsis: true,
    render: v => v ? <Text code ellipsis={{ tooltip: v }} style={{ fontSize: 11 }}>{v}</Text> : '—' },
  {
    title:     'Time',
    dataIndex: 'created_at',
    key:       'created_at',
    width:     160,
    render:    v => new Date(v).toLocaleString(),
  },
];

export default function Alerts() {
  const [severity, setSeverity] = useState<AlertSeverity | undefined>(undefined);
  const [action,   setAction]   = useState<AlertAction   | undefined>(undefined);

  const fetchAlerts = useCallback(
    () => api.alerts({ severity, action, limit: 200 }),
    [severity, action],
  );
  const { data: alerts, loading, refetch } = useApi(fetchAlerts);

  return (
    <div>
      <PageHeader
        title="Alerts"
        description="Policy decisions and risk findings across all sessions."
        extra={
          <Space>
            <Select
              placeholder="Severity"
              allowClear
              style={{ width: 120 }}
              size="small"
              value={severity}
              onChange={setSeverity}
              options={SEVERITY_OPTIONS}
            />
            <Select
              placeholder="Action"
              allowClear
              style={{ width: 110 }}
              size="small"
              value={action}
              onChange={setAction}
              options={ACTION_OPTIONS}
            />
            <Button size="small" icon={<ReloadOutlined />} onClick={refetch}>
              Refresh
            </Button>
          </Space>
        }
      />

      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card size="small">
            <Table<Alert>
              columns={COLUMNS}
              dataSource={alerts ?? []}
              rowKey="alert_id"
              loading={loading}
              size="small"
              pagination={{ pageSize: 25, showSizeChanger: true }}
              expandable={{
                expandedRowRender: alert => <AlertDetails alert={alert} />,
                rowExpandable: () => true,
              }}
              locale={{ emptyText: <EmptyPlaceholder description="No alerts found." /> }}
            />
          </Card>
        </Col>
      </Row>
    </div>
  );
}
