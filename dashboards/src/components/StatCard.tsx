import React from 'react';
import { Card, Statistic } from 'antd';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: React.ReactNode;
  /** Accent colour for the icon. Defaults to Gensee brand red. */
  color?: string;
  suffix?: string;
  loading?: boolean;
}

/**
 * A compact summary metric card used on the Dashboard page.
 */
export function StatCard({
  title,
  value,
  icon,
  color = '#e53935',
  suffix,
  loading = false,
}: StatCardProps) {
  return (
    <Card size="small" loading={loading} style={{ height: '100%' }}>
      <Statistic
        title={title}
        value={value}
        prefix={<span style={{ color }}>{icon}</span>}
        suffix={suffix}
        valueStyle={{ fontSize: 24 }}
      />
    </Card>
  );
}
