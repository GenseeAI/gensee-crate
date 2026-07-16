import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Gensee Crate',
  description: 'Local-first runtime security for AI coding agents.',
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
        content: 'Local-first runtime security for AI coding agents.'
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
      { text: 'Guide', link: '/architecture' },
      { text: 'Policy', link: '/policy' },
      { text: 'GitHub', link: 'https://github.com/GenseeAI/gensee-crate' },
      { text: 'GenseeAI', link: 'https://www.gensee.ai' }
    ],
    sidebar: [
      {
        text: 'Start',
        items: [
          { text: 'Overview', link: '/' },
          { text: 'Architecture', link: '/architecture' }
        ]
      },
      {
        text: 'Protect A Run',
        items: [
          { text: 'gensee watch', link: '/watch' },
          { text: 'gensee run', link: '/run-and-sandbox' },
          { text: 'Linux Host Support', link: '/linux' },
          { text: 'Policy CLI', link: '/gensee-policy' },
          { text: 'Safety Policy', link: '/policy' }
        ]
      },
      {
        text: 'Agent Integrations',
        items: [
          { text: 'Claude Code Hooks', link: '/claude-code-hooks' },
          { text: 'Codex Hooks', link: '/codex-support' },
          { text: 'Antigravity Support', link: '/antigravity-support' },
          { text: 'VS Code / GitHub Copilot', link: '/vscode-support' }
        ]
      },
      {
        text: 'Data And Lineage',
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
