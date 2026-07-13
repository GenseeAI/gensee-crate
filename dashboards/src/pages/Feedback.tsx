import { useCallback, useState } from 'react';
import {
  Button,
  Card,
  Col,
  Form,
  Input,
  Modal,
  Row,
  Select,
  Space,
  Table,
  Tag,
  Typography,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import { PageHeader }       from '@/components/PageHeader';
import { EmptyPlaceholder } from '@/components/EmptyPlaceholder';
import { useApi }           from '@/hooks/useApi';
import { api }              from '@/api/client';
import type { HumanFeedback } from '@/api/types';

const { Text } = Typography;

const VERDICT_COLORS: Record<string, string> = {
  agree: 'green',
  allow: 'blue',
  deny:  'red',
};

const LABEL_COLORS: Record<string, string> = {
  confirmed:       'green',
  false_positive:  'orange',
  false_negative:  'red',
  override:        'purple',
};

const COLUMNS: ColumnsType<HumanFeedback> = [
  {
    title:  'Verdict',
    dataIndex: 'human_verdict',
    key:    'human_verdict',
    width:  90,
    render: v => <Tag color={VERDICT_COLORS[v] ?? 'default'}>{v.toUpperCase()}</Tag>,
  },
  {
    title:  'Label',
    dataIndex: 'label',
    key:    'label',
    width:  130,
    render: v => v ? <Tag color={LABEL_COLORS[v] ?? 'default'}>{v}</Tag> : '—',
  },
  { title: 'Gensee action', dataIndex: 'gensee_action', key: 'gensee_action', width: 120,
    render: v => v ?? '—' },
  { title: 'Rule',          dataIndex: 'rule_id',        key: 'rule_id',       width: 180, ellipsis: true },
  { title: 'Path',          dataIndex: 'path',           key: 'path',          ellipsis: true,
    render: v => v ? <Text code style={{ fontSize: 11 }}>{v}</Text> : '—' },
  { title: 'Note',          dataIndex: 'note',           key: 'note',          ellipsis: true },
  {
    title:     'Time',
    dataIndex: 'created_at',
    key:       'created_at',
    width:     160,
    render:    v => new Date(v).toLocaleString(),
  },
];

export default function Feedback() {
  const [modalOpen, setModalOpen] = useState(false);

  const fetchFeedback = useCallback(() => api.feedback(100), []);
  const { data: feedback, loading, refetch } = useApi(fetchFeedback);

  return (
    <div>
      <PageHeader
        title="Feedback"
        description="Human review verdicts on shield decisions — used for policy tuning."
        extra={
          <Space>
            <Button
              type="primary"
              size="small"
              icon={<PlusOutlined />}
              onClick={() => setModalOpen(true)}
            >
              Record verdict
            </Button>
            <Button size="small" icon={<ReloadOutlined />} onClick={refetch} />
          </Space>
        }
      />

      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card size="small">
            <Table<HumanFeedback>
              columns={COLUMNS}
              dataSource={feedback ?? []}
              rowKey="feedback_id"
              loading={loading}
              size="small"
              pagination={{ pageSize: 25, showSizeChanger: true }}
              locale={{ emptyText: <EmptyPlaceholder description="No feedback recorded yet." /> }}
            />
          </Card>
        </Col>
      </Row>

      <RecordFeedbackModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        onSuccess={() => { setModalOpen(false); refetch(); }}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Record feedback modal — placeholder form
// ---------------------------------------------------------------------------

function RecordFeedbackModal({
  open,
  onClose,
  onSuccess,
}: {
  open: boolean;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [form] = Form.useForm();
  const [submitting, setSubmitting] = useState(false);

  async function onFinish(values: Partial<HumanFeedback>) {
    setSubmitting(true);
    try {
      await api.recordFeedback(values);
      form.resetFields();
      onSuccess();
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal
      title="Record verdict"
      open={open}
      onCancel={onClose}
      onOk={() => form.submit()}
      confirmLoading={submitting}
      okText="Save"
    >
      <Form form={form} layout="vertical" onFinish={onFinish} style={{ marginTop: 16 }}>
        <Form.Item
          name="human_verdict"
          label="Verdict"
          rules={[{ required: true }]}
        >
          <Select
            options={[
              { value: 'agree', label: 'Agree (confirmed)' },
              { value: 'allow', label: 'Allow (false positive)' },
              { value: 'deny',  label: 'Deny (false negative)' },
            ]}
          />
        </Form.Item>
        <Form.Item name="gensee_action" label="Gensee action">
          <Input placeholder="block / ask / allow / warn" />
        </Form.Item>
        <Form.Item name="rule_id" label="Rule ID">
          <Input placeholder="e.g. policy_secret_paths_protected" />
        </Form.Item>
        <Form.Item name="path" label="Path">
          <Input placeholder="/path/to/affected/file" />
        </Form.Item>
        <Form.Item name="note" label="Note">
          <Input.TextArea rows={2} placeholder="Optional free-text note" />
        </Form.Item>
      </Form>
    </Modal>
  );
}
