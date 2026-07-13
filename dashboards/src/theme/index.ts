import type { ThemeConfig } from 'antd';
import { theme } from 'antd';

/** Gensee brand colour — a strong, security-tool red. */
export const BRAND_RED = '#e53935';

const baseTokens = {
  colorPrimary: BRAND_RED,
  borderRadius: 6,
  fontFamily:
    '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
};

export const lightTheme: ThemeConfig = {
  algorithm: theme.defaultAlgorithm,
  token: {
    ...baseTokens,
    colorBgLayout: '#f0f2f5',
    colorBgContainer: '#ffffff',
    colorBorder: '#e8e8e8',
  },
  components: {
    Layout: {
      headerBg: '#ffffff',
      siderBg: '#ffffff',
      bodyBg: '#f0f2f5',
    },
    Menu: {
      itemBg: 'transparent',
      subMenuItemBg: 'transparent',
    },
  },
};

export const darkTheme: ThemeConfig = {
  algorithm: theme.darkAlgorithm,
  token: {
    ...baseTokens,
    colorBgLayout: '#0d1117',
    colorBgContainer: '#161b22',
    colorBorder: '#21262d',
  },
  components: {
    Layout: {
      headerBg: '#0d1117',
      siderBg: '#0d1117',
      bodyBg: '#0d1117',
    },
    Menu: {
      itemBg: 'transparent',
      subMenuItemBg: 'transparent',
    },
  },
};
