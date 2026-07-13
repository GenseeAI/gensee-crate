import { Tag } from 'antd';
import type { AlertSeverity, AlertAction } from '@/api/types';

const SEVERITY_COLORS: Record<AlertSeverity, string> = {
  info:     'default',
  low:      'cyan',
  medium:   'orange',
  high:     'red',
  critical: 'purple',
};

const ACTION_COLORS: Record<AlertAction, string> = {
  allow: 'green',
  warn:  'gold',
  ask:   'blue',
  block: 'red',
};

export function SeverityBadge({ severity }: { severity: string }) {
  const color = SEVERITY_COLORS[severity as AlertSeverity] ?? 'default';
  return <Tag color={color}>{severity.toUpperCase()}</Tag>;
}

export function ActionBadge({ action }: { action: string }) {
  const color = ACTION_COLORS[action as AlertAction] ?? 'default';
  return <Tag color={color}>{action.toUpperCase()}</Tag>;
}
