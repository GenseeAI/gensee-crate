import { App as AntApp, ConfigProvider } from 'antd';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { ThemeProvider, useTheme } from '@/hooks/useTheme';
import { darkTheme, lightTheme } from '@/theme';
import AppLayout from '@/layouts/AppLayout';

// Pages
import Dashboard   from '@/pages/Dashboard';
import TodayHighlight from '@/pages/TodayHighlight';
import LiveFeed    from '@/pages/LiveFeed';
import Timeline    from '@/pages/Timeline';
import Sessions    from '@/pages/Sessions';
import Alerts      from '@/pages/Alerts';
import LineageGraph from '@/pages/LineageGraph';
import Feedback    from '@/pages/Feedback';
import Policy      from '@/pages/Policy';
import Settings    from '@/pages/Settings';

// ---------------------------------------------------------------------------
// ThemedApp is a separate component so it can read from ThemeContext.
// ---------------------------------------------------------------------------
function ThemedApp() {
  const { isDark } = useTheme();

  return (
    <ConfigProvider theme={isDark ? darkTheme : lightTheme}>
      <AntApp>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<AppLayout />}>
              <Route index element={<Navigate to="/dashboard" replace />} />
              <Route path="dashboard"  element={<Dashboard />}    />
              <Route path="today"      element={<TodayHighlight />} />
              <Route path="live-feed"  element={<LiveFeed />}     />
              <Route path="timeline"   element={<Timeline />}     />
              <Route path="sessions"   element={<Sessions />}     />
              <Route path="sessions/:sessionId" element={<Sessions />} />
              <Route path="alerts"     element={<Alerts />}       />
              <Route path="lineage"    element={<LineageGraph />} />
              <Route path="feedback"   element={<Feedback />}     />
              <Route path="policy"     element={<Policy />}       />
              <Route path="settings"   element={<Settings />}     />
            </Route>
          </Routes>
        </BrowserRouter>
      </AntApp>
    </ConfigProvider>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <ThemedApp />
    </ThemeProvider>
  );
}
