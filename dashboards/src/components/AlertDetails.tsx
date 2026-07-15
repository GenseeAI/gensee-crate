import { Descriptions, Typography } from 'antd';
import type { Alert } from '@/api/types';

const { Paragraph, Text } = Typography;

function FullValue({ value, code = false }: { value: string | null | undefined; code?: boolean }) {
  if (!value) return <Text type="secondary">—</Text>;
  return (
    <Paragraph
      copyable={{ text: value, tooltips: ['Copy full value', 'Copied'] }}
      code={code}
      style={{ margin: 0, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}
    >
      {value}
    </Paragraph>
  );
}

/** Expanded security context for an alert table row. */
export function AlertDetails({ alert }: { alert: Alert }) {
  const evidence = alert.evidence == null
    ? null
    : typeof alert.evidence === 'string'
      ? alert.evidence
      : JSON.stringify(alert.evidence, null, 2);

  return (
    <Descriptions size="small" column={1} bordered style={{ margin: '4px 0' }}>
      <Descriptions.Item label="Message">
        <FullValue value={alert.message} />
      </Descriptions.Item>
      <Descriptions.Item label="Path">
        <FullValue value={alert.path} code />
      </Descriptions.Item>
      <Descriptions.Item label="Rule ID">
        <FullValue value={alert.rule_id} code />
      </Descriptions.Item>
      {evidence && (
        <Descriptions.Item label="Evidence">
          <FullValue value={evidence} code />
        </Descriptions.Item>
      )}
    </Descriptions>
  );
}
