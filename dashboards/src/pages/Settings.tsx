import { Card, Col, Divider, Form, Input, Row, Switch, Typography } from 'antd';
import { PageHeader } from '@/components/PageHeader';
import { useTheme }   from '@/hooks/useTheme';

const { Text } = Typography;

export default function Settings() {
  const { isDark, toggle } = useTheme();

  return (
    <div>
      <PageHeader
        title="Settings"
        description="Connection, appearance, and advanced configuration."
      />

      <Row gutter={[16, 16]}>
        {/* Connection settings */}
        <Col xs={24} lg={12}>
          <Card size="small" title="Connection">
            <Form layout="vertical">
              <Form.Item
                label="GENSEE_HOME"
                help="Directory containing gensee.db and policy.json."
              >
                <Input
                  placeholder="~/.gensee"
                  // TODO: read from /api/v1/state or a dedicated /api/v1/config endpoint.
                />
              </Form.Item>
              <Form.Item
                label="API server URL"
                help="Base URL for the versioned API (overrides VITE_API_BASE_URL)."
              >
                <Input placeholder="http://127.0.0.1:3001/api/v1" />
              </Form.Item>
              <Form.Item label="GENSEE_BIN path" help="Path to the gensee binary for policy validation.">
                <Input placeholder="Auto-detect" />
              </Form.Item>
            </Form>
          </Card>
        </Col>

        {/* Appearance */}
        <Col xs={24} lg={12}>
          <Card size="small" title="Appearance">
            <Form layout="vertical">
              <Form.Item label="Dark mode">
                <Switch
                  checked={isDark}
                  onChange={toggle}
                  checkedChildren="Dark"
                  unCheckedChildren="Light"
                />
              </Form.Item>
            </Form>

            <Divider style={{ margin: '12px 0' }} />
            <Text type="secondary" style={{ fontSize: 12 }}>
              The theme preference is persisted in <code>localStorage</code> and
              falls back to the OS system preference.
            </Text>
          </Card>
        </Col>

        {/* About / version placeholder */}
        <Col xs={24} lg={12}>
          <Card size="small" title="About">
            <Text type="secondary" style={{ fontSize: 12 }}>
              <strong>gensee-ui</strong> v0.1.0
              <br />
              Built with Tauri v2, React 18, Ant Design 5.
              <br /><br />
              {/* TODO: show version from the gensee binary */}
              Gensee binary version: <em>— run `gensee --version` to check</em>
            </Text>
          </Card>
        </Col>
      </Row>
    </div>
  );
}
