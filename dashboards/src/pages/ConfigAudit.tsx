import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Badge,
  Button,
  Card,
  Col,
  Collapse,
  Descriptions,
  Empty,
  Flex,
  Input,
  Row,
  Select,
  Space,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import {
  ApiOutlined,
  CodeOutlined,
  DatabaseOutlined,
  ExclamationCircleOutlined,
  FileSearchOutlined,
  FireOutlined,
  InfoCircleOutlined,
  PlayCircleOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  SearchOutlined,
  ToolOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import { PageHeader } from '@/components/PageHeader';
import { SeverityBadge } from '@/components/SeverityBadge';
import { StatCard } from '@/components/StatCard';
import { api } from '@/api/client';
import { useApi } from '@/hooks/useApi';
import type {
  AuditAssessment,
  AuditExtension,
  AuditFinding,
  AuditInventory,
  AuditManualCheck,
  AuditMcpServer,
  AuditSeverity,
  AuditSkill,
  AuditSource,
  ConfigAuditBundle,
  ConfigAuditReport,
} from '@/api/types';

const { Paragraph, Text, Title } = Typography;

type AuditQuery = Partial<{
  target: string;
  workspace: string;
  codexHome: string;
  codexProfile: string;
  vscodeUserData: string;
  vscodeProfile: string;
}>;

type DisplayFinding = AuditFinding & { audit_target?: string };

const SEVERITIES: AuditSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
const SEVERITY_COLORS: Record<AuditSeverity, string> = {
  critical: '#722ed1',
  high: '#e53935',
  medium: '#fa8c16',
  low: '#13c2c2',
  info: '#8c8c8c',
};

function displayName(value: string) {
  return value
    .split('_')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

function formatSecurityConfigValue(value: unknown) {
  if (value !== null && typeof value === 'object') {
    return JSON.stringify(value);
  }
  return String(value);
}

function AssessmentBadge({ assessment }: { assessment: AuditAssessment }) {
  const color = assessment === 'confirmed' ? 'red' : assessment === 'potential' ? 'orange' : 'default';
  return <Tag color={color}>{displayName(assessment).toUpperCase()}</Tag>;
}

function BooleanBadge({ value, yes = 'YES', no = 'NO' }: { value: boolean; yes?: string; no?: string }) {
  return <Tag color={value ? 'green' : 'default'}>{value ? yes : no}</Tag>;
}

function FindingDetails({ finding }: { finding: AuditFinding }) {
  return (
    <div style={{ padding: '8px 16px 16px' }}>
      <Paragraph style={{ maxWidth: 920 }}>{finding.description}</Paragraph>

      <Alert
        type="info"
        showIcon
        message="Recommended action"
        description={finding.remediation.summary}
        style={{ marginBottom: 16 }}
      />

      <Title level={5} style={{ fontSize: 13, marginTop: 0 }}>Evidence</Title>
      {finding.evidence?.length ? (
        <Space direction="vertical" size={8} style={{ width: '100%' }}>
          {finding.evidence.map((evidence, index) => (
            <Card key={`${evidence.source}-${evidence.key ?? index}`} size="small">
              <Flex vertical gap={4}>
                <Text code style={{ fontSize: 11, wordBreak: 'break-all' }}>{evidence.source}</Text>
                {evidence.key && (
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    {evidence.key}{evidence.value !== undefined ? ` = ${evidence.value}` : ''}
                  </Text>
                )}
              </Flex>
            </Card>
          ))}
        </Space>
      ) : (
        <Text type="secondary">No file-level evidence was emitted.</Text>
      )}

      {(finding.mappings?.length || finding.references?.length) && (
        <Flex wrap gap={8} align="center" style={{ marginTop: 16 }}>
          {finding.mappings?.map(mapping => <Tag key={mapping}>{mapping}</Tag>)}
          {finding.references?.map(reference => (
            <Typography.Link key={reference} href={reference} target="_blank" rel="noreferrer">
              Reference
            </Typography.Link>
          ))}
        </Flex>
      )}
    </div>
  );
}

function FindingsPanel({ report }: { report: ConfigAuditReport }) {
  const [severity, setSeverity] = useState<AuditSeverity | undefined>();
  const [category, setCategory] = useState<string | undefined>();
  const [query, setQuery] = useState('');

  const categories = useMemo(
    () => Array.from(new Set(report.findings.map(finding => finding.category))).sort(),
    [report.findings],
  );
  const findings = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return report.findings.filter(finding => {
      if (severity && finding.severity !== severity) return false;
      if (category && finding.category !== category) return false;
      if (!needle) return true;
      return [finding.rule_id, finding.title, finding.description, finding.category]
        .some(value => value.toLowerCase().includes(needle));
    });
  }, [category, query, report.findings, severity]);

  const columns: ColumnsType<AuditFinding> = [
    {
      title: 'Target',
      key: 'audit_target',
      width: 142,
      responsive: ['xl'],
      render: (_, finding) => {
        const target = (finding as DisplayFinding).audit_target;
        return target ? <Tag color="blue">{target}</Tag> : '—';
      },
    },
    {
      title: 'Severity',
      dataIndex: 'severity',
      width: 104,
      render: (value: string) => <SeverityBadge severity={value} />,
      sorter: (left, right) => SEVERITIES.indexOf(left.severity) - SEVERITIES.indexOf(right.severity),
    },
    {
      title: 'Assessment',
      dataIndex: 'assessment',
      width: 126,
      render: (value: AuditAssessment) => <AssessmentBadge assessment={value} />,
    },
    {
      title: 'Rule',
      dataIndex: 'rule_id',
      width: 126,
      render: (value: string) => <Text code style={{ fontSize: 11 }}>{value}</Text>,
    },
    {
      title: 'Category',
      dataIndex: 'category',
      width: 190,
      responsive: ['lg'],
      render: (value: string) => <Text type="secondary">{displayName(value)}</Text>,
    },
    {
      title: 'Finding',
      dataIndex: 'title',
      render: (value: string, finding) => (
        <Flex vertical gap={2}>
          <Text strong>{value}</Text>
          <Text type="secondary" ellipsis={{ tooltip: finding.description }} style={{ maxWidth: 620 }}>
            {finding.description}
          </Text>
        </Flex>
      ),
    },
  ];

  return (
    <Space direction="vertical" size={12} style={{ width: '100%' }}>
      <Flex gap={8} wrap>
        <Input
          allowClear
          prefix={<SearchOutlined />}
          placeholder="Search rule, title, or description"
          value={query}
          onChange={event => setQuery(event.target.value)}
          style={{ width: 320 }}
        />
        <Select
          allowClear
          placeholder="Severity"
          value={severity}
          onChange={setSeverity}
          style={{ width: 130 }}
          options={SEVERITIES.map(value => ({ value, label: displayName(value) }))}
        />
        <Select
          allowClear
          placeholder="Category"
          value={category}
          onChange={setCategory}
          style={{ minWidth: 220 }}
          options={categories.map(value => ({ value, label: displayName(value) }))}
        />
        <Text type="secondary" style={{ alignSelf: 'center', marginLeft: 'auto' }}>
          {findings.length} of {report.findings.length} findings
        </Text>
      </Flex>

      <Table<AuditFinding>
        columns={columns}
        dataSource={findings}
        rowKey="fingerprint"
        size="small"
        pagination={{ pageSize: 20, showSizeChanger: true }}
        expandable={{ expandedRowRender: finding => <FindingDetails finding={finding} /> }}
        locale={{ emptyText: <Empty description="No findings match these filters." /> }}
      />
    </Space>
  );
}

function InventoryPanel({ report }: { report: ConfigAuditReport }) {
  const inventory = report.inventory;
  const modelsInventoryState = report.target.provider === 'codex';
  const mcpColumns: ColumnsType<AuditMcpServer> = [
    { title: 'Server', dataIndex: 'id', render: value => <Text strong>{value}</Text> },
    { title: 'Transport', dataIndex: 'transport', width: 110, render: value => <Tag>{value.toUpperCase()}</Tag> },
    ...(modelsInventoryState ? [
      { title: 'Enabled', dataIndex: 'enabled', width: 100, render: (value: boolean) => <BooleanBadge value={value} /> },
      {
        title: 'Tool allowlist',
        dataIndex: 'has_tool_allowlist',
        width: 130,
        render: (value: boolean) => <BooleanBadge value={value} yes="SCOPED" no="UNSCOPED" />,
      },
    ] : []),
    {
      title: 'Endpoint',
      dataIndex: 'endpoint',
      ellipsis: true,
      render: value => value ? <Text code ellipsis={{ tooltip: value }}>{value}</Text> : 'Local process',
    },
  ];
  const skillColumns: ColumnsType<AuditSkill> = [
    { title: 'Skill', dataIndex: 'name', render: value => <Text strong>{value}</Text> },
    { title: 'Scope', dataIndex: 'scope', width: 130, render: value => <Tag>{displayName(value)}</Tag> },
    ...(modelsInventoryState ? [
      { title: 'Enabled', dataIndex: 'enabled', width: 100, render: (value: boolean) => <BooleanBadge value={value} /> },
    ] : []),
    { title: 'Scripts', dataIndex: 'has_scripts', width: 100, render: value => <BooleanBadge value={value} /> },
    ...(modelsInventoryState ? [
      { title: 'Review', dataIndex: 'review_state', width: 120, render: (value: string) => <Tag color={value === 'unknown' ? 'orange' : 'green'}>{value.toUpperCase()}</Tag> },
    ] : []),
    {
      title: 'Path',
      dataIndex: 'path',
      ellipsis: true,
      render: value => <Text code ellipsis={{ tooltip: value }} style={{ fontSize: 11 }}>{value}</Text>,
    },
  ];
  const extensionColumns: ColumnsType<AuditExtension> = [
    { title: 'Extension', dataIndex: 'id', render: value => <Text strong>{value}</Text> },
    { title: 'Version', dataIndex: 'version', width: 120, render: value => <Text code>{value}</Text> },
    { title: 'State', dataIndex: 'enabled_state', width: 120, render: value => <Tag>{displayName(value)}</Tag> },
    {
      title: 'Agent capabilities',
      dataIndex: 'capabilities',
      render: values => values?.length
        ? <Space size={[4, 4]} wrap>{values.map((value: string) => <Tag key={value}>{displayName(value)}</Tag>)}</Space>
        : <Text type="secondary">None declared</Text>,
    },
    {
      title: 'Path',
      dataIndex: 'path',
      ellipsis: true,
      render: value => <Text code ellipsis={{ tooltip: value }} style={{ fontSize: 11 }}>{value}</Text>,
    },
  ];

  const securityConfig = Object.entries(report.effective_security_config);
  const inventoryStats = [
    ['Sources', report.sources.length],
    ['MCP servers', inventory.mcp_servers.length],
    ['Skills', inventory.skills.length],
    ['Extensions', inventory.extensions?.length ?? 0],
    ['Custom agents', inventory.custom_agents ?? 0],
    ['Hook commands', inventory.hook_commands],
    ['Plugin manifests', inventory.plugin_manifests],
    ['Marketplaces', inventory.marketplace_files],
    ['Command rules', inventory.rule_files],
    ['Instruction files', inventory.instruction_files],
    ['Managed requirements', inventory.managed_requirement_files],
  ] as const;

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12 }}>
        {inventoryStats.map(([label, value]) => (
          <Card key={label} size="small">
            <Flex vertical>
              <Text type="secondary" style={{ fontSize: 12 }}>{label}</Text>
              <Text strong style={{ fontSize: 22 }}>{value}</Text>
            </Flex>
          </Card>
        ))}
      </div>

      <Card size="small" title="Effective security configuration">
        <Descriptions size="small" bordered column={{ xs: 1, md: 2, xl: 3 }}>
          {securityConfig.map(([key, value]) => (
            <Descriptions.Item key={key} label={displayName(key)}>
              <Text code>{formatSecurityConfigValue(value)}</Text>
            </Descriptions.Item>
          ))}
        </Descriptions>
      </Card>

      {!modelsInventoryState && (
        <Alert
          type="info"
          showIcon
          message="VS Code inventory state is not modeled"
          description="The audit discovered these resources, but VS Code enabled state, MCP tool allowlists, and skill review state cannot be determined statically. Those columns are omitted instead of presenting assumptions as facts."
        />
      )}

      <Card size="small" title={`MCP servers (${inventory.mcp_servers.length})`}>
        <Table<AuditMcpServer>
          columns={mcpColumns}
          dataSource={inventory.mcp_servers}
          rowKey="id"
          size="small"
          pagination={false}
          locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No MCP servers discovered." /> }}
        />
      </Card>

      <Card size="small" title={`Skills (${inventory.skills.length})`}>
        <Table<AuditSkill>
          columns={skillColumns}
          dataSource={inventory.skills}
          rowKey="path"
          size="small"
          pagination={{ pageSize: 15, showSizeChanger: true }}
          locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No skills discovered." /> }}
        />
      </Card>

      <Card size="small" title={`Installed extensions (${inventory.extensions?.length ?? 0})`}>
        <Table<AuditExtension>
          columns={extensionColumns}
          dataSource={inventory.extensions ?? []}
          rowKey="path"
          size="small"
          pagination={{ pageSize: 15, showSizeChanger: true }}
          locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No local extensions discovered." /> }}
        />
      </Card>
    </Space>
  );
}

function ManualCheckCard({ check }: { check: AuditManualCheck }) {
  return (
    <Card size="small">
      <Flex gap={12} align="flex-start">
        <WarningOutlined style={{ color: '#fa8c16', fontSize: 18, marginTop: 3 }} />
        <Flex vertical gap={6} style={{ flex: 1 }}>
          <Flex gap={8} wrap align="center">
            <Text strong>{check.title}</Text>
            <Tag color="orange">{check.priority.toUpperCase()}</Tag>
            <Text code style={{ fontSize: 11 }}>{check.check_id}</Text>
          </Flex>
          <Text type="secondary">{check.reason}</Text>
          <Text><strong>Action:</strong> {check.action}</Text>
          {check.references?.map(reference => (
            <Typography.Link key={reference} href={reference} target="_blank" rel="noreferrer">
              Open guidance
            </Typography.Link>
          ))}
        </Flex>
      </Flex>
    </Card>
  );
}

function ReviewContextPanel({ report }: { report: ConfigAuditReport }) {
  const sourceColumns: ColumnsType<AuditSource> = [
    { title: 'Source', dataIndex: 'kind', width: 180, render: value => <Tag>{displayName(value)}</Tag> },
    {
      title: 'Path',
      dataIndex: 'path',
      ellipsis: true,
      render: value => <Text code ellipsis={{ tooltip: value }} style={{ fontSize: 11 }}>{value}</Text>,
    },
    { title: 'Exists', dataIndex: 'exists', width: 82, render: value => <BooleanBadge value={value} /> },
    { title: 'Applied', dataIndex: 'applied', width: 88, render: value => <BooleanBadge value={value} /> },
    { title: 'Trusted', dataIndex: 'trusted', width: 88, render: value => <BooleanBadge value={value} /> },
    {
      title: 'Notes',
      width: 220,
      render: (_, source) => {
        const notes = [
          ...(source.ignored_keys?.map(key => `Ignored: ${key}`) ?? []),
          ...(source.errors ?? []),
        ];
        return notes.length ? (
          <Tooltip title={notes.join('\n')}><Tag color="orange">{notes.length} note{notes.length === 1 ? '' : 's'}</Tag></Tooltip>
        ) : '—';
      },
    },
  ];

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Alert
        type="warning"
        showIcon
        message="Account-side privacy checks cannot be proven from local files"
        description="These checks remain visible rather than being counted as passed. Review them against each authenticated model-provider account and organization."
      />
      <Space direction="vertical" size={10} style={{ width: '100%' }}>
        {report.manual_checks.map(check => <ManualCheckCard key={check.check_id} check={check} />)}
      </Space>

      <Card size="small" title={`Configuration sources (${report.sources.length})`}>
        <Table<AuditSource>
          columns={sourceColumns}
          dataSource={report.sources}
          rowKey={source => `${source.kind}:${source.path}`}
          size="small"
          pagination={{ pageSize: 15, showSizeChanger: true }}
        />
      </Card>

      <Card size="small" title="Audit limitations">
        <Space direction="vertical" size={8}>
          {report.limitations.map(limitation => (
            <Flex key={limitation} gap={8} align="flex-start">
              <InfoCircleOutlined style={{ color: '#1677ff', marginTop: 3 }} />
              <Text>{limitation}</Text>
            </Flex>
          ))}
        </Space>
      </Card>
    </Space>
  );
}

function RawReportPanel({ report }: { report: unknown }) {
  return (
    <Collapse
      defaultActiveKey={['json']}
      items={[{
        key: 'json',
        label: 'Versioned JSON report',
        children: (
          <pre style={{ margin: 0, maxHeight: 620, overflow: 'auto', fontSize: 11, lineHeight: 1.5 }}>
            {JSON.stringify(report, null, 2)}
          </pre>
        ),
      }]}
    />
  );
}

function mergeReports(bundle: ConfigAuditBundle): ConfigAuditReport | undefined {
  const selected = bundle.reports.filter(item => item.applicability !== 'not_detected');
  if (!selected.length) return undefined;
  if (selected.length === 1) return selected[0].report;

  const first = selected[0].report;
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const inventories = selected.map(item => item.report.inventory);
  const uniqueBy = <T,>(items: T[], key: (item: T) => string) =>
    Array.from(new Map(items.map(item => [key(item), item])).values());
  const sumInventoryCount = (count: (inventory: AuditInventory) => number) =>
    inventories.reduce((total, inventory) => total + count(inventory), 0);
  selected.forEach(item => {
    (Object.keys(counts) as AuditSeverity[]).forEach(severity => {
      counts[severity] += item.report.summary.counts[severity] ?? 0;
    });
  });
  const maxSeverity = SEVERITIES.find(severity => counts[severity] > 0);

  return {
    schema_version: 1,
    ruleset: { id: 'audit-bundle', version: '1' },
    target: {
      provider: bundle.requested_target,
      workspace: first.target.workspace,
      codex_home: selected.find(item => item.report.target.codex_home)?.report.target.codex_home,
      vscode_user_data: selected.find(item => item.report.target.vscode_user_data)?.report.target.vscode_user_data,
      surfaces: selected.flatMap(item => item.report.target.surfaces),
    },
    summary: {
      assessment: selected.some(item => item.applicability === 'partial' || item.report.summary.assessment === 'partial')
        ? 'partial'
        : 'complete',
      max_severity: maxSeverity,
      counts,
      manual_checks: selected.reduce((total, item) => total + item.report.manual_checks.length, 0),
    },
    sources: selected.flatMap(item => item.report.sources.map(source => ({
      ...source,
      kind: `${item.target}: ${source.kind}`,
    }))),
    effective_security_config: Object.fromEntries(selected.flatMap(item =>
      Object.entries(item.report.effective_security_config).map(([key, value]) => [
        `${item.target}.${key}`,
        value,
      ]),
    )),
    inventory: {
      skills: uniqueBy(inventories.flatMap(inventory => inventory.skills), skill => skill.path),
      mcp_servers: uniqueBy(
        inventories.flatMap(inventory => inventory.mcp_servers),
        server => `${server.id}:${server.transport}:${server.endpoint ?? ''}`,
      ),
      hook_commands: sumInventoryCount(inventory => inventory.hook_commands),
      plugin_manifests: sumInventoryCount(inventory => inventory.plugin_manifests),
      marketplace_files: sumInventoryCount(inventory => inventory.marketplace_files),
      rule_files: sumInventoryCount(inventory => inventory.rule_files),
      instruction_files: sumInventoryCount(inventory => inventory.instruction_files),
      managed_requirement_files: sumInventoryCount(inventory => inventory.managed_requirement_files),
      extensions: uniqueBy(
        inventories.flatMap(inventory => inventory.extensions ?? []),
        extension => extension.path,
      ),
      custom_agents: sumInventoryCount(inventory => inventory.custom_agents ?? 0),
    },
    findings: selected.flatMap(item => item.report.findings.map(finding => ({
      ...finding,
      fingerprint: `${item.target}:${finding.fingerprint}`,
      audit_target: item.target,
    }))),
    manual_checks: selected.flatMap(item => item.report.manual_checks.map(check => ({
      ...check,
      title: `[${item.target}] ${check.title}`,
    }))),
    limitations: selected.flatMap(item => item.report.limitations.map(limitation => `[${item.target}] ${limitation}`)),
  };
}

function ReportSummary({ report }: { report: ConfigAuditReport }) {
  const maxSeverity = report.summary.max_severity;
  const urgent = maxSeverity === 'critical' || maxSeverity === 'high';
  return (
    <>
      <Alert
        type={report.summary.assessment === 'partial' ? 'warning' : urgent ? 'error' : 'info'}
        showIcon
        icon={<SafetyCertificateOutlined />}
        message={
          <Flex gap={8} align="center" wrap>
            <Text strong>Local assessment: {report.summary.assessment.toUpperCase()}</Text>
            {maxSeverity && <SeverityBadge severity={maxSeverity} />}
            <Tag>{report.ruleset.id} · {report.ruleset.version}</Tag>
          </Flex>
        }
        description={
          urgent
            ? 'High-impact configuration findings need review. Counts are shown independently; the audit does not collapse risk into an aggregate score.'
            : 'Review findings and manual account checks together. A complete local assessment does not prove account-side privacy settings.'
        }
        style={{ marginBottom: 16 }}
      />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12, marginBottom: 16 }}>
        <StatCard title="Critical" value={report.summary.counts.critical} icon={<WarningOutlined />} color={SEVERITY_COLORS.critical} />
        <StatCard title="High" value={report.summary.counts.high} icon={<FireOutlined />} color={SEVERITY_COLORS.high} />
        <StatCard title="Medium" value={report.summary.counts.medium} icon={<ExclamationCircleOutlined />} color={SEVERITY_COLORS.medium} />
        <StatCard title="Low" value={report.summary.counts.low} icon={<InfoCircleOutlined />} color={SEVERITY_COLORS.low} />
        <StatCard title="Info" value={report.summary.counts.info} icon={<FileSearchOutlined />} color={SEVERITY_COLORS.info} />
      </div>
    </>
  );
}

export default function ConfigAudit() {
  const [fields, setFields] = useState({
    target: 'vscode',
    workspace: '',
    codexHome: '',
    codexProfile: '',
    vscodeUserData: '',
    vscodeProfile: '',
  });
  const [submitted, setSubmitted] = useState<AuditQuery>({ target: 'vscode' });
  const fetchAudit = useCallback(() => api.configAudit(submitted), [submitted]);
  const { data: bundle, loading, error, refetch } = useApi(fetchAudit);
  const visibleBundle = bundle?.requested_target === (submitted.target ?? 'vscode')
    ? bundle
    : undefined;
  const report = useMemo(
    () => visibleBundle ? mergeReports(visibleBundle) : undefined,
    [visibleBundle],
  );

  useEffect(() => {
    if (!visibleBundle?.reports.length) return;
    const first = visibleBundle.reports[0].report;
    setFields(current => {
      if (current.workspace) return current;
      return {
        ...current,
        workspace: first.target.workspace,
        codexHome: visibleBundle.reports.find(item => item.report.target.codex_home)?.report.target.codex_home ?? '',
        codexProfile: visibleBundle.reports.find(item => item.report.target.profile)?.report.target.profile ?? '',
        vscodeUserData: visibleBundle.reports.find(item => item.report.target.vscode_user_data)?.report.target.vscode_user_data ?? '',
        vscodeProfile: visibleBundle.reports.find(item => item.report.target.vscode_profile)?.report.target.vscode_profile ?? '',
      };
    });
  }, [visibleBundle]);

  function submitAudit(nextFields: typeof fields) {
    const next: AuditQuery = {};
    next.target = nextFields.target;
    if (nextFields.workspace.trim()) next.workspace = nextFields.workspace.trim();
    if (nextFields.target === 'codex') {
      if (nextFields.codexHome.trim()) next.codexHome = nextFields.codexHome.trim();
      if (nextFields.codexProfile.trim()) next.codexProfile = nextFields.codexProfile.trim();
    }
    if (nextFields.target === 'vscode') {
      if (nextFields.vscodeUserData.trim()) next.vscodeUserData = nextFields.vscodeUserData.trim();
      if (nextFields.vscodeProfile.trim()) next.vscodeProfile = nextFields.vscodeProfile.trim();
    }
    if (JSON.stringify(next) === JSON.stringify(submitted)) {
      refetch();
    } else {
      setSubmitted(next);
    }
  }

  function runAudit() {
    submitAudit(fields);
  }

  const tabs = report && visibleBundle ? [
    {
      key: 'findings',
      label: <Space size={6}>Findings <Badge count={report.findings.length} showZero /></Space>,
      children: <FindingsPanel report={report} />,
    },
    {
      key: 'inventory',
      label: <Space size={6}><DatabaseOutlined /> Inventory</Space>,
      children: <InventoryPanel report={report} />,
    },
    {
      key: 'review',
      label: <Space size={6}>Manual checks <Badge count={report.manual_checks.length} color="#fa8c16" /></Space>,
      children: <ReviewContextPanel report={report} />,
    },
    {
      key: 'json',
      label: <Space size={6}><CodeOutlined /> Raw JSON</Space>,
      children: <RawReportPanel report={visibleBundle} />,
    },
  ] : [];

  return (
    <div>
      <PageHeader
        title="Coding-Agent Config Audit"
        description="Static, read-only review of Codex CLI, GitHub Copilot, and VS Code permissions, privacy, extensions, and trust boundaries."
        extra={visibleBundle && (
          <Space>
            <Tag color="blue">{visibleBundle.requested_target.toUpperCase()}</Tag>
            <Tag>{visibleBundle.resolved_targets.join(' + ')}</Tag>
          </Space>
        )}
      />

      <Card size="small" style={{ marginBottom: 16 }}>
        <Row gutter={[12, 12]} align="bottom">
          <Col xs={24} md={8} xl={4}>
            <Text strong style={{ display: 'block', marginBottom: 6 }}>Audit target</Text>
            <Select
              value={fields.target}
              onChange={target => {
                const nextFields = { ...fields, target };
                setFields(nextFields);
                submitAudit(nextFields);
              }}
              style={{ width: '100%' }}
              options={[
                { value: 'vscode', label: 'VS Code' },
                { value: 'codex', label: 'Codex' },
              ]}
            />
          </Col>
          <Col xs={24} md={16} xl={8}>
            <Text strong style={{ display: 'block', marginBottom: 6 }}>Workspace</Text>
            <Input
              value={fields.workspace}
              onChange={event => setFields(current => ({ ...current, workspace: event.target.value }))}
              onPressEnter={runAudit}
              placeholder="Current process workspace"
              prefix={<ToolOutlined />}
            />
          </Col>
          {fields.target === 'codex' && (
            <>
              <Col xs={24} md={12} xl={6}>
                <Text strong style={{ display: 'block', marginBottom: 6 }}>Codex home</Text>
                <Input
                  value={fields.codexHome}
                  onChange={event => setFields(current => ({ ...current, codexHome: event.target.value }))}
                  onPressEnter={runAudit}
                  placeholder="CODEX_HOME or ~/.codex"
                  prefix={<DatabaseOutlined />}
                />
              </Col>
              <Col xs={24} md={7} xl={3}>
                <Text strong style={{ display: 'block', marginBottom: 6 }}>Codex profile</Text>
                <Input
                  value={fields.codexProfile}
                  onChange={event => setFields(current => ({ ...current, codexProfile: event.target.value }))}
                  onPressEnter={runAudit}
                  placeholder="Optional"
                  prefix={<ApiOutlined />}
                />
              </Col>
            </>
          )}
          <Col xs={24} md={5} xl={3}>
            <Button
              type="primary"
              block
              icon={loading ? <ReloadOutlined spin /> : <PlayCircleOutlined />}
              loading={loading}
              onClick={runAudit}
            >
              Run audit
            </Button>
          </Col>
        </Row>
        {fields.target === 'vscode' && (
          <Row gutter={[12, 12]} style={{ marginTop: 12 }}>
            <Col xs={24} md={16} xl={12}>
              <Text strong style={{ display: 'block', marginBottom: 6 }}>VS Code user data</Text>
              <Input
                value={fields.vscodeUserData}
                onChange={event => setFields(current => ({ ...current, vscodeUserData: event.target.value }))}
                onPressEnter={runAudit}
                placeholder="Platform default Code/User directory"
                prefix={<DatabaseOutlined />}
              />
            </Col>
            <Col xs={24} md={8} xl={5}>
              <Text strong style={{ display: 'block', marginBottom: 6 }}>VS Code profile ID</Text>
              <Input
                value={fields.vscodeProfile}
                onChange={event => setFields(current => ({ ...current, vscodeProfile: event.target.value }))}
                onPressEnter={runAudit}
                placeholder="Optional"
                prefix={<ApiOutlined />}
              />
            </Col>
          </Row>
        )}
        <Text type="secondary" style={{ display: 'block', fontSize: 11, marginTop: 10 }}>
          The dashboard reads configuration files directly. It does not start agents or execute MCP servers, hooks, skills, plugins, extensions, or command rules.
        </Text>
      </Card>

      {error && (
        <Alert
          type="error"
          showIcon
          closable
          message="Configuration audit failed"
          description={error}
          action={<Button size="small" icon={<ReloadOutlined />} onClick={refetch}>Retry</Button>}
          style={{ marginBottom: 16 }}
        />
      )}

      {!visibleBundle && !error && <Card loading style={{ minHeight: 280 }} />}

      {visibleBundle && !report && (
        <Alert
          type="info"
          showIcon
          message="The requested audit target was not detected"
          description={visibleBundle.reports.map(item => item.applicability_reason).filter(Boolean).join(' ')}
        />
      )}

      {visibleBundle && report && (
        <>
          <Card size="small" style={{ marginBottom: 16 }}>
            <Flex gap={8} align="center" wrap>
              <Text strong>Coverage:</Text>
              {visibleBundle.reports.map(item => (
                <Tooltip key={item.target} title={item.applicability_reason}>
                  <Tag color={item.applicability === 'applicable' ? 'green' : item.applicability === 'partial' ? 'orange' : 'default'}>
                    {item.target}: {displayName(item.applicability)}
                  </Tag>
                </Tooltip>
              ))}
            </Flex>
          </Card>
          <ReportSummary report={report} />
          <Card size="small">
            <Tabs items={tabs} destroyInactiveTabPane={false} />
          </Card>
        </>
      )}
    </div>
  );
}
