import { defineConfig } from 'vitepress'
import { guideLinks } from './guide-links.mts'

const guidePages: Record<string, string> = {
  'README.md': 'docs/',
  'walkthroughs/one-real-run.md': 'docs/walkthrough',
  'code-map.md': 'docs/code-map',
  'modules/cloud-oauth-and-relay.md': 'docs/contracts#cloud-oauth-relay',
  'modules/local-approval-and-replay.md': 'docs/contracts#local-approval-replay',
  'modules/container-sandbox-and-file-policy.md': 'docs/contracts#container-sandbox-policy',
  'glossary.md': 'docs/architecture#glossary-index',
  'references/source-evidence.md': 'docs/architecture#evidence-and-boundaries',
  'references/quality-review.md': 'docs/architecture#evidence-and-boundaries',
  'change-log.md': 'docs/architecture#security-adrs-migration',
}

export default defineConfig({
  cleanUrls: true,
  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/brand/loomward-icon.svg' }],
    ['link', { rel: 'icon', type: 'image/png', sizes: '32x32', href: '/brand/icon-32.png' }],
  ],
  markdown: {
    config: guideLinks(guidePages),
  },
  locales: {
    root: {
      label: '简体中文',
      lang: 'zh-CN',
      title: 'LoomWard · 织盾 文档',
      description: '基于 Cordis 4 微内核的综合本地 Agent 安全管控平台，融合 Cloudflare Workers OAuth 2.1 中继、跨平台本机审批、只读 Linux Docker 沙箱、防泄漏护栏与决策台账。',
      themeConfig: {
        siteTitle: 'LoomWard · 织盾',
        nav: [
          { text: '首页', link: '/' },
          { text: '起步与部署', link: '/docs/' },
          { text: '契约与边界', link: '/docs/contracts' },
          { text: 'API 与组件', link: '/api-reference/' },
          { text: '原理与导览', link: '/docs/architecture' },
        ],
        socialLinks: [
          { icon: 'github', link: 'https://github.com/CyberNova2333/agentdock-worker-remote' },
        ],
        sidebar: [
          {
            text: '起步与配置部署',
            items: [
              { text: '项目定位与部署流程', link: '/docs/' },
              { text: '配置矩阵与运维脚本', link: '/docs/configuration' },
              { text: '部署与运行排错 FAQ', link: '/docs/faq' },
            ],
          },
          {
            text: '接口与扩展契约',
            items: [
              { text: 'OAuth、工具、批准与沙箱契约', link: '/docs/contracts' },
              { text: 'API 与组件参考', link: '/api-reference/' },
            ],
          },
          {
            text: '原理与源码导览',
            items: [
              { text: '架构全景与安全决策', link: '/docs/architecture' },
              { text: '一次请求端到端走查', link: '/docs/walkthrough' },
              { text: '源码目录与测试地图', link: '/docs/code-map' },
            ],
          },
        ],
        outline: { level: [2, 3], label: '本页目录' },
        docFooter: { prev: '上一页', next: '下一页' },
      },
    },
    en: {
      label: 'English',
      lang: 'en-US',
      link: '/en/',
      title: 'LoomWard Documentation',
      description: 'Cordis 4 local Agent security & control plane unifying Cloudflare Workers OAuth 2.1 relay, cross-platform local approval, read-only Linux Docker sandboxes, anti-leak guardrails, and a decision ledger.',
      themeConfig: {
        siteTitle: 'LoomWard',
        nav: [
          { text: 'Home', link: '/en/' },
          { text: 'Getting Started', link: '/en/docs/' },
          { text: 'Contracts', link: '/en/docs/contracts' },
          { text: 'API & Tools', link: '/en/api-reference/' },
          { text: 'Architecture', link: '/en/docs/architecture' },
        ],
        socialLinks: [
          { icon: 'github', link: 'https://github.com/CyberNova2333/agentdock-worker-remote' },
        ],
        sidebar: [
          {
            text: 'Getting Started & Deployment',
            items: [
              { text: 'Overview & Setup Workflow', link: '/en/docs/' },
              { text: 'Configuration & Scripts Matrix', link: '/en/docs/configuration' },
              { text: 'Deployment & Runtime FAQ', link: '/en/docs/faq' },
            ],
          },
          {
            text: 'Contracts & Boundaries',
            items: [
              { text: 'OAuth, Tools, Approval & Sandbox', link: '/en/docs/contracts' },
              { text: 'API & Component Reference', link: '/en/api-reference/' },
            ],
          },
          {
            text: 'Internals & Code Map',
            items: [
              { text: 'Architecture & Security ADRs', link: '/en/docs/architecture' },
              { text: 'End-to-End Request Walkthrough', link: '/en/docs/walkthrough' },
              { text: 'Source & Test Code Map', link: '/en/docs/code-map' },
            ],
          },
        ],
        outline: { level: [2, 3], label: 'On this page' },
        docFooter: { prev: 'Previous page', next: 'Next page' },
      },
    },
  },
  themeConfig: {
    logo: '/brand/loomward-icon.svg',
    search: { provider: 'local' },
  },
})
