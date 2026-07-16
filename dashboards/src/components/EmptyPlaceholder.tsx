import React from 'react';
import { Empty } from 'antd';

interface EmptyPlaceholderProps {
  description?: string;
  image?: React.ReactNode;
}

/**
 * Empty state shown inside cards and tables with no data.
 */
export function EmptyPlaceholder({
  description = 'No data yet.',
  image,
}: EmptyPlaceholderProps) {
  return (
    <Empty
      image={image ?? Empty.PRESENTED_IMAGE_SIMPLE}
      description={description}
      style={{ padding: '40px 0' }}
    />
  );
}
