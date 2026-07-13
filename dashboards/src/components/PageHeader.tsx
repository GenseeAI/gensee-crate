import React from 'react';
import { Flex, Typography } from 'antd';

const { Title, Text } = Typography;

interface PageHeaderProps {
  title: string;
  description?: string;
  /** Action buttons / controls placed on the right side. */
  extra?: React.ReactNode;
}

/**
 * Consistent page title bar used at the top of every page.
 */
export function PageHeader({ title, description, extra }: PageHeaderProps) {
  return (
    <Flex justify="space-between" align="flex-start" style={{ marginBottom: 24 }}>
      <div>
        <Title level={4} style={{ marginBottom: description ? 4 : 0 }}>
          {title}
        </Title>
        {description && <Text type="secondary">{description}</Text>}
      </div>
      {extra && <div style={{ flexShrink: 0 }}>{extra}</div>}
    </Flex>
  );
}
