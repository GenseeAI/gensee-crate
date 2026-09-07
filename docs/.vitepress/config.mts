import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Gensee Crate',
  description: 'Operation-bound protection, long-horizon understanding, and cross-layer detection for autonomous AI agents.',
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
        content: 'Operation-bound protection, long-horizon understanding, and cross-layer detection for autonomous AI agents.'
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
          { text: 'What’s New', link: '/whats-new' },
          { text: 'Roadmap', link: '/roadmap' }
        ]
      },
      {
        text: 'Personal',
        items: [
          { text: 'macOS App', link: '/macos-app' },
          { text: 'Review Queue & Approvals', link: '/review-queue-approvals' },
          { text: 'Feedback & Read Exceptions', link: '/scoped-feedback-triage' },
          { text: 'Config Audit', link: '/config-audit' },
          { text: 'Safety Policy', link: '/policy' },
          { text: 'gensee watch', link: '/watch' },
          { text: 'gensee run', link: '/run-and-sandbox' }
        ]
      },
      {
        text: 'Operation-bound Protection',
        items: [
          { text: 'Operation Boundary', link: '/operation-boundary' },
          { text: 'End-to-end Demo', link: '/generic-end-to-end-demo' },
          { text: 'Contract Catalogs', link: '/contract-catalog' },
          { text: 'Operation Supervisor', link: '/operation-supervisor' },
          { text: 'Network Boundary', link: '/operation-network-boundary' },
          { text: 'Capability Providers', link: '/generic-capability-providers' },
          { text: 'Capability Faults', link: '/capability-faults' },
          { text: 'Distributed Operation Context', link: '/operation-context' },
          { text: 'Semantic Verification', link: '/semantic-verifier' },
          { text: 'Transactional Promotion', link: '/transactional-promotion' },
          { text: 'Boundary Extension Authoring', link: '/boundary-extension-authoring' },
          { text: 'Boundary Conformance Proof', link: '/generic-boundary-proof' }
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
          { text: 'Claude Cowork', link: '/claude-cowork' },
          { text: 'Codex Hooks', link: '/codex-support' },
          { text: 'Antigravity Support', link: '/antigravity-support' },
          { text: 'VS Code / GitHub Copilot', link: '/vscode-support' },
          { text: 'Cursor Hooks', link: '/cursor-support' }
        ]
      },
      {
        text: 'Evidence And Operations',
        items: [
          { text: 'Long-horizon Understanding', link: '/long-horizon-understanding' },
          { text: 'Cross-platform Dashboard', link: '/dashboard' },
          { text: 'Authenticated Replay', link: '/replay' },
          { text: 'Security Traces & Evaluation', link: '/security-traces' },
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
