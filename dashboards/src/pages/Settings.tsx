import { Alert, Card, Col, Divider, Form, Input, Row, Switch, Tag, Typography } from 'antd';
import { PageHeader } from '@/components/PageHeader';
import { useTheme }   from '@/hooks/useTheme';
import { useApi }     from '@/hooks/useApi';
import { api }        from '@/api/client';

const { Text } = Typography;

export default function Settings() {
  const { isDark, toggle } = useTheme();
  const { data: storeSecurity, loading: storeSecurityLoading } = useApi(api.storeSecurity);
  const plaintextStore = storeSecurity?.database_exists && !storeSecurity.encrypted_at_rest;

  return (
    <div>
      <PageHeader
        title="Settings"
        description="Local-store security, appearance, and advanced configuration."
      />

      {plaintextStore && (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message="Plaintext local database detected"
          description={
            <span>
              This dashboard can read the store, but telemetry is not encrypted at rest. To enable
              encryption safely, create or migrate to a new Gensee home with encryption enabled, then
              set <code>GENSEE_HOME</code> to that directory before launching Gensee. Automatic in-place
              encryption is intentionally not offered because it could corrupt the active security store.
            </span>
          }
        />
      )}

      <Row gutter={[16, 16]}>
        {/* Local store settings */}
        <Col xs={24} lg={12}>
          <Card size="small" title="Local Store">
            <Form layout="vertical">
              <Form.Item
                label="Local database"
                help="GENSEE_HOME contains gensee.db, gensee.key, and policy.json."
              >
                <Input
                  value={storeSecurity?.db_path ?? '~/.gensee/gensee.db'}
                  readOnly
                />
              </Form.Item>
              <Form.Item label="Encryption at rest" help="SQLCipher encryption for gensee.db.">
                {storeSecurityLoading ? (
                  <Tag>Checking…</Tag>
                ) : storeSecurity?.database_exists ? (
                  storeSecurity.encrypted_at_rest
                    ? <Tag color="green">ENCRYPTED</Tag>
                    : <Tag color="orange">PLAINTEXT — ACTION REQUIRED</Tag>
                ) : (
                  <Tag color="default">NO DATABASE</Tag>
                )}
              </Form.Item>
              <Form.Item label="Backend transport" help="No local HTTP API server is started.">
                <Tag color="blue">TAURI IPC</Tag>
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
              <strong>gensee-ui</strong> v0.2.0
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
