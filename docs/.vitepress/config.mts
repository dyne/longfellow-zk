import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Longfellow-ZK',
  titleTemplate: ':title — Longfellow-ZK',
  description: 'Privacy-preserving proofs for identity, signatures, and portable applications — maintained by Dyne.org.',
  lang: 'en-US',
  base: process.env.BASE_PATH ?? '/',
  appearance: true,
  lastUpdated: true,
  head: [
    ['meta', { name: 'theme-color', content: '#cb743b' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:title', content: 'Longfellow-ZK by Dyne.org' }],
    ['meta', { property: 'og:description', content: 'Zero-knowledge proofs for existing identity and signature systems.' }]
  ],
  themeConfig: {
    nav: [
      { text: 'Start here', link: '/guide' },
      { text: 'Use cases', link: '/use-cases' },
      { text: 'Reference projects', link: '/projects/' },
      { text: 'Technical reference', link: '/architecture' },
      { text: 'About Dyne.org', link: 'https://dyne.org' }
    ],
    search: {
      provider: 'local',
      options: {
        miniSearch: {
          searchOptions: { fuzzy: 0.2, prefix: true }
        }
      }
    },
    socialLinks: [
      { icon: 'github', link: 'https://github.com/dyne/longfellow-zk' }
    ],
    editLink: {
      pattern: 'https://github.com/dyne/longfellow-zk/edit/main/docs/:path',
      text: 'Improve this page on GitHub'
    },
    outline: {
      level: [2, 3],
      label: 'On this page'
    },
    lastUpdated: {
      text: 'Last updated'
    },
    docFooter: {
      prev: 'Previous',
      next: 'Next'
    },
    sidebar: [
      {
        text: 'Understand',
        items: [
          { text: 'Home', link: '/' },
          { text: 'Start here', link: '/guide' },
          { text: 'Zero-knowledge, gently', link: '/zero-knowledge' },
          { text: 'Present & future uses', link: '/use-cases' },
          { text: 'About this implementation', link: '/about' }
        ]
      },
      {
        text: 'Reference projects',
        items: [
          { text: 'Projects overview', link: '/projects/' },
          { text: 'mdoc', link: '/projects/mdoc' },
          { text: 'ECDSA', link: '/projects/ecdsa' },
          { text: 'BIP340', link: '/projects/bip340' }
        ]
      },
      {
        text: 'Build & integrate',
        items: [
          { text: 'Getting started', link: '/getting-started' },
          { text: 'Architecture', link: '/architecture' },
          { text: 'API & ABI', link: '/api' },
          { text: 'Packaging', link: '/packaging' },
          { text: 'Interoperability', link: '/interoperability' }
        ]
      },
      {
        text: 'Protocol & assurance',
        items: [
          { text: 'Specifications map', link: '/specifications/' },
          { text: 'libzk draft mirror', link: '/specifications/libzk' },
          { text: 'Ligero', link: '/specifications/ligero' },
          { text: 'Sumcheck', link: '/specifications/sumcheck' },
          { text: 'Test vectors', link: '/specifications/test-vectors' },
          { text: 'LFC2 storage', link: '/lfc2' },
          { text: 'Security & qualification', link: '/security' },
          { text: 'Research & standards', link: '/research' }
        ]
      },
      {
        text: 'Maintainer reference',
        collapsed: true,
        items: [
          { text: '0.x ABI policy', link: '/abi' },
          { text: 'Library boundary', link: '/liblongfellow-zk-boundary' },
          { text: 'Compiler ownership', link: '/compiler-ownership' },
          { text: 'Merkle membership contract', link: '/merkle-membership-contract' },
          { text: 'Artifact baseline', link: '/liblongfellow-zk-artifact-baseline' },
          { text: 'C++20 measurements', link: '/cpp20_migration_metrics' },
          { text: 'Production qualification', link: '/production-qualification' }
        ]
      }
    ]
  }
})
