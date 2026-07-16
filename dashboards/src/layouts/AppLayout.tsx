import {
  Avatar,
  Badge,
  Button,
  Dropdown,
  Input,
  Layout,
  Menu,
  Space,
  Typography,
} from 'antd';
import type { MenuProps } from 'antd';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  AlertOutlined,
  ApartmentOutlined,
  BellOutlined,
  ClockCircleOutlined,
  DashboardOutlined,
  FileProtectOutlined,
  LikeOutlined,
  LogoutOutlined,
  MoonOutlined,
  QuestionCircleOutlined,
  SearchOutlined,
  SettingOutlined,
  StarOutlined,
  SunOutlined,
  ThunderboltOutlined,
  UserOutlined,
} from '@ant-design/icons';
import { useTheme } from '@/hooks/useTheme';

const { Header, Sider, Content } = Layout;
const { Text } = Typography;

// ---------------------------------------------------------------------------
// Navigation tree
// ---------------------------------------------------------------------------

type MenuItem = NonNullable<MenuProps['items']>[number];

const NAV_ITEMS: MenuItem[] = [
  {
    type: 'group',
    label: 'OVERVIEW',
    children: [
      { key: '/dashboard', icon: <DashboardOutlined />, label: 'Dashboard' },
    ],
  },
  { type: 'divider' },
  {
    type: 'group',
    label: 'ACTIVITY',
    children: [
      { key: '/live-feed', icon: <ThunderboltOutlined />, label: "Live Feed"        },
      { key: '/today',     icon: <StarOutlined />,        label: "Today's Highlight" },
      { key: '/timeline',  icon: <ClockCircleOutlined />, label: 'Timeline'          },
    ],
  },
  { type: 'divider' },
  {
    type: 'group',
    label: 'SECURITY',
    children: [
      { key: '/alerts',   icon: <AlertOutlined />,    label: 'Alerts'        },
      { key: '/lineage',  icon: <ApartmentOutlined />, label: 'Lineage Graph' },
      { key: '/feedback', icon: <LikeOutlined />,      label: 'Feedback'      },
    ],
  },
  { type: 'divider' },
  {
    type: 'group',
    label: 'CONFIGURATION',
    children: [
      { key: '/policy',   icon: <FileProtectOutlined />, label: 'Policy'   },
      { key: '/settings', icon: <SettingOutlined />,     label: 'Settings' },
    ],
  },
];

const USER_MENU_ITEMS: MenuProps['items'] = [
  { key: 'profile', icon: <UserOutlined />,  label: 'Profile'   },
  { type: 'divider' },
  { key: 'logout',  icon: <LogoutOutlined />, label: 'Sign out', danger: true },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

const TOP_BAR_HEIGHT = 56;
const SIDEBAR_WIDTH  = 220;

export default function AppLayout() {
  const navigate  = useNavigate();
  const location  = useLocation();
  const { isDark, toggle } = useTheme();

  // Derive the active menu key from the first path segment.
  const selectedKey = '/' + (location.pathname.split('/')[1] ?? '');

  const borderColor = isDark ? '#21262d' : '#e8e8e8';

  return (
    <Layout style={{ minHeight: '100vh' }}>
      {/* ------------------------------------------------------------------ */}
      {/* Top bar                                                              */}
      {/* ------------------------------------------------------------------ */}
      <Header
        style={{
          display:      'flex',
          alignItems:   'center',
          padding:      '0 16px',
          height:       TOP_BAR_HEIGHT,
          borderBottom: `1px solid ${borderColor}`,
          position:     'sticky',
          top:          0,
          zIndex:       200,
          gap:          16,
        }}
      >
        {/* Logo — matches the original dashboards/web brand mark */}
        <Space size={10} align="center" style={{ marginRight: 24, flexShrink: 0 }}>
          <img src="/eye-only.png" alt="Gensee" style={{ width: 28, height: 28, display: 'block' }} />
          <div style={{ lineHeight: 1.2 }}>
            <div style={{ fontSize: 9, letterSpacing: 2, textTransform: 'uppercase', opacity: 0.55 }}>GenseeAI</div>
            <div style={{ fontSize: 14, fontWeight: 700, letterSpacing: 0.5 }}>Gensee Crate</div>
          </div>
        </Space>

        {/* Global search */}
        <Input
          prefix={<SearchOutlined style={{ color: '#8c8c8c' }} />}
          placeholder="Search sessions, alerts, artifacts…"
          style={{ maxWidth: 360, flex: 1 }}
          variant="filled"
          size="small"
        />

        {/* Right-side actions */}
        <Space size={2} style={{ marginLeft: 'auto', flexShrink: 0 }}>
          {/* Notifications */}
          <Badge count={0} size="small">
            <Button type="text" icon={<BellOutlined />} title="Alerts" />
          </Badge>

          {/* Help */}
          <Button type="text" icon={<QuestionCircleOutlined />} title="Help" />

          {/* Theme toggle */}
          <Button
            type="text"
            icon={isDark ? <SunOutlined /> : <MoonOutlined />}
            onClick={toggle}
            title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
          />

          {/* User menu */}
          <Dropdown
            menu={{ items: USER_MENU_ITEMS }}
            placement="bottomRight"
            trigger={['click']}
          >
            <Space size={6} style={{ cursor: 'pointer', padding: '0 8px' }}>
              <Avatar
                size={28}
                icon={<UserOutlined />}
                style={{ background: '#e53935', flexShrink: 0 }}
              />
              <Text style={{ fontSize: 13 }}>Admin</Text>
            </Space>
          </Dropdown>
        </Space>
      </Header>

      {/* ------------------------------------------------------------------ */}
      {/* Body: sidebar + content                                              */}
      {/* ------------------------------------------------------------------ */}
      <Layout>
        <Sider
          width={SIDEBAR_WIDTH}
          style={{
            borderRight:  `1px solid ${borderColor}`,
            overflow:     'auto',
            height:       `calc(100vh - ${TOP_BAR_HEIGHT}px)`,
            position:     'sticky',
            top:          TOP_BAR_HEIGHT,
            flexShrink:   0,
          }}
        >
          <Menu
            mode="inline"
            selectedKeys={[selectedKey]}
            items={NAV_ITEMS}
            onClick={({ key }) => navigate(key)}
            style={{ border: 'none', height: '100%', paddingTop: 8 }}
          />
        </Sider>

        <Content
          style={{
            padding:   24,
            overflowY: 'auto',
            height:    `calc(100vh - ${TOP_BAR_HEIGHT}px)`,
          }}
        >
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  );
}
