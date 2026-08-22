import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Gensee Crate',
  description: 'Control agent work on developer laptops and self-hosted Linux environments.',
  lang: 'en-US',
  cleanUrls: true,
  lastUpdated: true,
  ignoreDeadLinks: [/^https?:\/\//],
  head: [
    ['meta', { name: 'theme-color', content: '#f7f4ed' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:title', content: 'Gensee Crate Docs' }],
    [
      'meta',
      {
        property: 'og:description',
        content: 'Control agent work on developer laptops and self-hosted Linux environments.'
      }
    ]
  ],
  markdown: {
    theme: {
      light: 'github-light',
      dark: 'github-dark'
    }
  },
  themeConfig: {
    siteTitle: 'Gensee Crate',
    search: {
      provider: 'local'
    },
    nav: [
      { text: 'Personal', link: '/personal' },
      { text: 'Team', link: '/team' },
      { text: 'Architecture', link: '/architecture' },
      { text: 'GitHub', link: 'https://github.com/GenseeAI/gensee-crate' },
      { text: 'GenseeAI', link: 'https://www.gensee.ai' }
    ],
    sidebar: [
      {
        text: 'Start',
        items: [
          { text: 'Overview', link: '/' },
          { text: 'Gensee Crate Personal', link: '/personal' },
          { text: 'Gensee Crate Team', link: '/team' },
          { text: 'Architecture', link: '/architecture' },
          { text: 'Roadmap', link: '/roadmap' }
        ]
      },
      {
        text: 'Personal',
        items: [
          { text: 'macOS App', link: '/macos-app' },
          { text: 'Config Audit', link: '/config-audit' },
          { text: 'Safety Policy', link: '/policy' },
          { text: 'gensee watch', link: '/watch' },
          { text: 'gensee run', link: '/run-and-sandbox' }
        ]
      },
      {
        text: 'Team',
        items: [
          { text: 'Tclone Runtime', link: '/tclone' },
          { text: 'Capability Broker', link: '/capability-broker' },
          { text: 'Linux Host Support', link: '/linux' },
          { text: 'Managed Run Modes', link: '/run-and-sandbox' },
          { text: 'Policy CLI', link: '/gensee-policy' }
        ]
      },
      {
        text: 'Agent Integrations',
        items: [
          { text: 'Claude Code Hooks', link: '/claude-code-hooks' },
          { text: 'Codex Hooks', link: '/codex-support' },
          { text: 'Antigravity Support', link: '/antigravity-support' },
          { text: 'VS Code / GitHub Copilot', link: '/vscode-support' },
          { text: 'Cursor Hooks', link: '/cursor-support' }
        ]
      },
      {
        text: 'Evidence And Operations',
        items: [
          { text: 'Dashboard', link: '/dashboard' },
          { text: 'SQLite Lineage Graph', link: '/lineage-graph' },
          { text: 'Endpoint Security', link: '/endpoint-security' }
        ]
      }
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/GenseeAI/gensee-crate' }
    ],
    footer: {
      message: 'Released under the Apache 2.0 License.',
      copyright: 'Copyright © GenseeAI'
    },
    editLink: {
      pattern: 'https://github.com/GenseeAI/gensee-crate/edit/main/docs/:path',
      text: 'Edit this page on GitHub'
    }
  }
})
