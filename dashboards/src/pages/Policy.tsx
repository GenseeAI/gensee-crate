import { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Collapse,
  InputNumber,
  Row,
  Select,
  Space,
  Switch,
  Tabs,
  Tag,
  Typography,
  Input,
} from 'antd';
import { SaveOutlined, ReloadOutlined } from '@ant-design/icons';
import { PageHeader } from '@/components/PageHeader';
import { useApi }     from '@/hooks/useApi';
import { api }        from '@/api/client';

const { TextArea } = Input;
const { Text }     = Typography;

// ---------------------------------------------------------------------------
// Policy settings schema (ported from original dashboard)
// ---------------------------------------------------------------------------

type SettingType = 'bool' | 'int' | 'float' | 'string' | 'list';
interface SettingItem { key: string; type: SettingType; label: string; help: string }
interface SettingGroup { group: string; hint: string; items: SettingItem[] }

const POLICY_SETTINGS: SettingGroup[] = [
  {
    group: 'Resource governance',
    hint:  'Per-tool and per-session quotas. 0 / blank leaves the built-in default.',
    items: [
      { key: 'resource_governance.max_read_bytes',                type: 'int',   label: 'Max read bytes',               help: 'Largest single file read the shield allows.'            },
      { key: 'resource_governance.max_file_subjects_per_tool',    type: 'int',   label: 'Max file subjects / tool',     help: 'File paths a single tool call may touch.'               },
      { key: 'resource_governance.max_shell_segments_per_tool',   type: 'int',   label: 'Max shell segments / tool',    help: 'Chained commands (|, &&, ;) per Bash call.'             },
      { key: 'resource_governance.max_tool_calls_per_session',    type: 'int',   label: 'Max tool calls / session',     help: 'Total tool calls before the session is throttled.'      },
      { key: 'resource_governance.max_network_egress_per_session',type: 'int',   label: 'Max network egress / session', help: 'Outbound network operations per session.'               },
      { key: 'resource_governance.max_file_accessed_rate_per_min',type: 'float', label: 'Max file access rate / min',   help: 'File operations per minute before flagging.'            },
      { key: 'resource_governance.max_network_rate_per_min',      type: 'float', label: 'Max network rate / min',       help: 'Network operations per minute before flagging.'         },
    ],
  },
  {
    group: 'Network egress',
    hint:  'Where the agent may reach out, and whether it must go through a proxy.',
    items: [
      { key: 'egress.allow_hosts',   type: 'list',   label: 'Allowed hosts', help: 'Hosts the agent may connect to. Everything else is denied.' },
      { key: 'egress.proxy_url',     type: 'string', label: 'Proxy URL',     help: 'Egress proxy to route outbound traffic through.'           },
      { key: 'egress.require_proxy', type: 'bool',   label: 'Require proxy', help: 'Deny direct egress that bypasses the proxy.'               },
    ],
  },
  {
    group: 'Runtime',
    hint:  '',
    items: [
      { key: 'runtime.max_runtime_seconds', type: 'int', label: 'Max runtime (seconds)', help: 'Wall-clock cap for a guarded run.' },
    ],
  },
  {
    group: 'Enforcement',
    hint:  '',
    items: [
      { key: 'enforcement.noninteractive', type: 'bool', label: 'Non-interactive fail-closed', help: 'When no human can answer, escalate medium+ asks to deny instead of allowing.' },
    ],
  },
  {
    group: 'Allowlisted paths',
    hint:  'Path prefixes that are always trusted (e.g. shared template dirs).',
    items: [
      { key: 'allow_path_prefixes', type: 'list', label: 'Allowed path prefixes', help: 'Absolute path prefixes exempt from secret/sensitive checks.' },
    ],
  },
];

const ARTIFACT_DEFS = [
  { key: 'executable',    title: 'Executable artifacts',       help: 'Treated as runnable (scripts, skills, plugins, git hooks).' },
  { key: 'memory',        title: 'Memory files',               help: 'Agent memory the shield tracks for poisoning across turns/sessions.' },
  { key: 'skill',         title: 'Skill / plugin locations',   help: 'Where skill and plugin definitions live.' },
  { key: 'control_plane', title: 'Control-plane files',        help: "Gensee's own files (shield DB, policy) — writes here are blocked." },
];

const MATCHER_FIELDS = [
  { key: 'segments',          label: 'Path segments (directory names)' },
  { key: 'filenames',         label: 'Exact filenames'                  },
  { key: 'filename_prefixes', label: 'Filename prefixes'               },
  { key: 'filename_suffixes', label: 'Filename suffixes / extensions'  },
  { key: 'filename_contains', label: 'Filename contains'               },
  { key: 'path_suffixes',     label: 'Path ends with'                  },
  { key: 'path_contains',     label: 'Path contains'                   },
];

const ACTION_OPTIONS = [
  { value: 'block', label: 'Deny',  color: 'red'    },
  { value: 'ask',   label: 'Ask',   color: 'orange' },
  { value: 'warn',  label: 'Warn',  color: 'gold'   },
  { value: 'allow', label: 'Allow', color: 'green'  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getDotted(obj: Record<string, unknown>, key: string): unknown {
  return key.split('.').reduce<unknown>((cur, part) =>
    cur != null && typeof cur === 'object' ? (cur as Record<string, unknown>)[part] : undefined, obj);
}

function setDotted(obj: Record<string, unknown>, key: string, value: unknown): Record<string, unknown> {
  const parts  = key.split('.');
  const result = { ...obj };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let cur: any = result;
  for (let i = 0; i < parts.length - 1; i++) {
    cur[parts[i]] = cur[parts[i]] != null ? { ...cur[parts[i]] } : {};
    cur = cur[parts[i]];
  }
  cur[parts[parts.length - 1]] = value;
  return result;
}

function summarizeMatchers(node: Record<string, unknown>): string {
  const FIELDS = ['patterns','commands','bare_commands','hosts','url_substrings',
    'segments','filenames','filename_suffixes','path_contains','exact_paths'];
  const parts: string[] = [];
  for (const f of FIELDS) if (Array.isArray(node[f])) parts.push(...(node[f] as string[]));
  if (!parts.length) return (node.message as string) || '';
  const shown = parts.slice(0, 4).join(', ');
  return parts.length > 4 ? `${shown} … (+${parts.length - 4})` : shown;
}

interface RuleEntry { node: Record<string, unknown>; name: string; rule_id?: string }
interface RuleGroup  { group: string; rules: RuleEntry[] }

function collectRuleGroups(doc: Record<string, unknown>): RuleGroup[] {
  const fileRules: RuleEntry[] = [];
  const sp = doc.secret_paths as Record<string, unknown> | undefined;
  if (sp?.protected) fileRules.push({ node: sp.protected as Record<string, unknown>, name: 'Protected secrets', rule_id: sp.rule_id as string });
  const pw = doc.persistence_writes as Record<string, unknown> | undefined;
  if (pw) fileRules.push({ node: pw, name: 'Persistence / startup writes', rule_id: pw.rule_id as string });
  for (const [key, node] of Object.entries(doc.categories ?? {}))
    fileRules.push({ node: node as Record<string, unknown>, name: key.replace(/_/g, ' '), rule_id: (node as Record<string, unknown>).rule_id as string });

  const contentRules = ((doc.content_rules ?? []) as Record<string, unknown>[]).map(n => ({
    node: n, name: (n.id ?? n.rule_id) as string,
    rule_id: `applies to: ${((n.applies_to ?? ['any']) as string[]).join(', ')}`,
  }));
  const commandRules = ((doc.command_rules ?? []) as Record<string, unknown>[]).map(n => ({
    node: n, name: (n.id ?? n.rule_id) as string, rule_id: n.rule_id as string,
  }));
  const urlRules = ((doc.url_rules ?? []) as Record<string, unknown>[]).map((n, i) => ({
    node: n, name: (n.id ?? n.rule_id ?? `URL rule ${i + 1}`) as string, rule_id: n.rule_id as string,
  }));

  return [
    { group: 'File access rules',        rules: fileRules     },
    { group: 'Command rules',            rules: commandRules  },
    { group: 'Executable-content rules', rules: contentRules  },
    { group: 'Network / URL rules',      rules: urlRules      },
  ].filter(g => g.rules.length);
}

// ---------------------------------------------------------------------------
// Settings tab
// ---------------------------------------------------------------------------

function SettingsTab({ doc, onChange }: { doc: Record<string, unknown>; onChange(key: string, val: unknown): void }) {
  return (
    <div>
      {POLICY_SETTINGS.map(group => (
        <Card key={group.group} size="small" title={group.group} style={{ marginBottom: 16 }}
          extra={group.hint ? <Text type="secondary" style={{ fontSize: 11 }}>{group.hint}</Text> : null}>
          {group.items.map(item => {
            const val = getDotted(doc, item.key);
            return (
              <Row key={item.key} style={{ marginBottom: 10, flexWrap: 'nowrap' }}>
                <div style={{ width: 260, flexShrink: 0 }}>
                  <Text strong style={{ fontSize: 12 }}>{item.label}</Text><br />
                  <Text type="secondary" style={{ fontSize: 11 }}>{item.help}</Text>
                </div>
                <div style={{ flex: 1, paddingLeft: 16 }}>
                  {item.type === 'bool' && (
                    <Switch checked={Boolean(val)} onChange={v => onChange(item.key, v)} />
                  )}
                  {(item.type === 'int' || item.type === 'float') && (
                    <InputNumber value={val as number | null} style={{ width: 160 }}
                      step={item.type === 'float' ? 0.1 : 1}
                      precision={item.type === 'float' ? 2 : 0}
                      onChange={v => onChange(item.key, v)} />
                  )}
                  {item.type === 'string' && (
                    <Input value={(val ?? '') as string} style={{ width: 280 }}
                      onChange={e => onChange(item.key, e.target.value)} />
                  )}
                  {item.type === 'list' && (
                    <Select mode="tags" value={Array.isArray(val) ? val as string[] : []}
                      onChange={v => onChange(item.key, v)}
                      style={{ width: '100%', maxWidth: 500 }}
                      tokenSeparators={[',']} placeholder="Type and press Enter to add…" />
                  )}
                </div>
              </Row>
            );
          })}
        </Card>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Rules inventory tab
// ---------------------------------------------------------------------------

function RulesTab({ doc, onChange }: { doc: Record<string, unknown>; onChange(d: Record<string, unknown>): void }) {
  const groups = collectRuleGroups(doc);
  if (!groups.length) return <Text type="secondary">No decision rules found in this policy.</Text>;
  return (
    <div>
      <Text type="secondary" style={{ display: 'block', marginBottom: 12, fontSize: 12 }}>
        Each rule's action — <b>Deny</b> blocks, <b>Ask</b> prompts the user, <b>Allow</b>/<b>Warn</b> lets it through.
      </Text>
      {groups.map(g => (
        <Card key={g.group} size="small" title={`${g.group} (${g.rules.length})`} style={{ marginBottom: 12 }}>
          {g.rules.map((rule, ri) => (
            <Row key={ri} style={{ padding: '6px 0', borderBottom: '1px solid rgba(128,128,128,0.1)', flexWrap: 'nowrap', alignItems: 'center' }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <Text strong style={{ fontSize: 12 }}>{rule.name}</Text>
                {rule.rule_id && <Text type="secondary" style={{ fontSize: 11, display: 'block' }}>{rule.rule_id}</Text>}
                {summarizeMatchers(rule.node) && (
                  <Text code style={{ fontSize: 11 }}>{summarizeMatchers(rule.node)}</Text>
                )}
              </div>
              <Select size="small" value={(rule.node.action as string) || 'allow'} style={{ width: 100, flexShrink: 0 }}
                onChange={v => { rule.node.action = v; onChange({ ...doc }); }}
                options={ACTION_OPTIONS.map(o => ({
                  value: o.value,
                  label: <Tag color={o.color} style={{ margin: 0 }}>{o.label}</Tag>,
                }))} />
            </Row>
          ))}
        </Card>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Artifact definitions tab
// ---------------------------------------------------------------------------

function ArtifactDefsTab({ doc, onChange }: { doc: Record<string, unknown>; onChange(d: Record<string, unknown>): void }) {
  const registries = doc.artifact_registries as Record<string, Record<string, string[]>> | undefined;
  if (!registries) return <Text type="secondary">No artifact_registries section in this policy.</Text>;
  return (
    <div>
      <Text type="secondary" style={{ display: 'block', marginBottom: 12, fontSize: 12 }}>
        What the shield treats as executable, memory, skill, or control-plane files.
      </Text>
      <Collapse size="small">
        {ARTIFACT_DEFS.map(def => {
          const reg = registries[def.key];
          if (!reg) return null;
          return (
            <Collapse.Panel key={def.key} header={<><b>{def.title}</b><Text type="secondary" style={{ fontSize: 11 }}> — {def.help}</Text></>}>
              {MATCHER_FIELDS.map(field => (
                <Row key={field.key} style={{ marginBottom: 8, flexWrap: 'nowrap', alignItems: 'center' }}>
                  <Text style={{ width: 220, flexShrink: 0, fontSize: 12 }}>{field.label}</Text>
                  <Select mode="tags" size="small"
                    value={Array.isArray(reg[field.key]) ? reg[field.key] : []}
                    onChange={vals => { reg[field.key] = vals; onChange({ ...doc }); }}
                    style={{ flex: 1 }} tokenSeparators={[',']} placeholder="Type and press Enter…" />
                </Row>
              ))}
            </Collapse.Panel>
          );
        })}
      </Collapse>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Policy page
// ---------------------------------------------------------------------------

export default function Policy() {
  const fetchPolicy = useCallback(() => api.policy(), []);
  const { data: loaded, loading, refetch } = useApi(fetchPolicy);

  const [doc,    setDoc]    = useState<Record<string, unknown> | null>(null);
  const [raw,    setRaw]    = useState('');
  const [tab,    setTab]    = useState('settings');
  const [saving, setSaving] = useState(false);
  const [msg,    setMsg]    = useState<{ ok: boolean; text: string } | null>(null);
  const [dirty,  setDirty]  = useState(false);

  useEffect(() => {
    if (loaded == null) return;
    const parsed = loaded as Record<string, unknown>;
    setDoc(parsed);
    setRaw(JSON.stringify(parsed, null, 2));
    setDirty(false);
  }, [loaded]);

  function handleTabChange(key: string) {
    if (key === 'advanced' && doc) setRaw(JSON.stringify(doc, null, 2));
    setTab(key);
  }

  function handleChange(key: string, value: unknown) {
    if (!doc) return;
    setDoc(setDotted(doc, key, value));
    setDirty(true);
  }

  function handleDocChange(newDoc: Record<string, unknown>) {
    setDoc(newDoc);
    setDirty(true);
  }

  function handleRawChange(text: string) {
    setRaw(text);
    setDirty(true);
    try { setDoc(JSON.parse(text)); } catch { /* wait for valid JSON */ }
  }

  async function handleSave() {
    if (!doc) return;
    setSaving(true);
    setMsg(null);
    try {
      await api.savePolicy(doc);
      setMsg({ ok: true, text: 'Policy saved and validated.' });
      setDirty(false);
      refetch();
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : String(err) });
    } finally {
      setSaving(false);
    }
  }

  const tabItems = [
    { key: 'settings',  label: 'Settings',              children: doc ? <SettingsTab    doc={doc} onChange={handleChange}    /> : null },
    { key: 'rules',     label: 'Decision Rules',        children: doc ? <RulesTab       doc={doc} onChange={handleDocChange} /> : null },
    { key: 'artifacts', label: 'Artifact Definitions',  children: doc ? <ArtifactDefsTab doc={doc} onChange={handleDocChange}/> : null },
    { key: 'advanced',  label: 'Advanced (JSON)',        children: (
        <TextArea value={raw} onChange={e => handleRawChange(e.target.value)}
          autoSize={{ minRows: 20 }} spellCheck={false}
          style={{ fontFamily: 'monospace', fontSize: 12 }} />
      ),
    },
  ];

  return (
    <div>
      <PageHeader title="Policy" description="Configure the active Gensee security policy."
        extra={
          <Space>
            <Button size="small" icon={<ReloadOutlined />}
              onClick={() => { setDoc(null); setMsg(null); setDirty(false); refetch(); }}>
              Reload
            </Button>
            <Button type="primary" size="small" icon={<SaveOutlined />}
              loading={saving} onClick={handleSave} disabled={!dirty}>
              Save & Validate
            </Button>
          </Space>
        }
      />

      {msg && (
        <Alert message={msg.text} type={msg.ok ? 'success' : 'error'}
          showIcon closable onClose={() => setMsg(null)} style={{ marginBottom: 16 }} />
      )}

      <Card size="small" loading={loading}>
        <Tabs activeKey={tab} onChange={handleTabChange} items={tabItems} />
      </Card>
    </div>
  );
}
