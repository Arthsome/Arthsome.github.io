// Centralized portfolio data — edit everything here.
export const PORTFOLIO_DATA = {
  identity: {
    availability: 'OPEN FOR SELECT COMMISSIONS',
    role: 'INDEPENDENT SECURITY RESEARCHER',
    headlineHTML: `Finding <em class="serif-italic">what breaks</em><br />before it does.`,
    bio: 'Independent security researcher. Penetration testing, bug bounty and vulnerability research — root cause first, write-ups and detections published after the patch.',
    email: 'vancxe@aster.cx',
    stats: [
      ['10.0', '', 'TOP CVSS'],
      ['01', '', 'CVE + DETECTIONS'],
      ['06', '', 'DISCIPLINES']
    ]
  },

  projects: [
    {
      id: 'cve-2025-20281', index: '01',
      title: 'Unauthenticated RCE in Cisco ISE',
      scope: 'Vulnerability / CVSS 10.0', year: '2026',
      role: 'Security researcher', stack: 'C · Python · Detection',
      link: './posts/cve-2025-20281/index.html',
      summary: 'Root-cause analysis of a critical pre-auth remote code execution: the broken invariant, the exact code path, why the patch holds, and detections defenders can deploy on day one.',
      highlights: [
        'Full root-cause chain from unauthenticated request to code execution.',
        'Patch analysis explaining why the fix closes the invariant.',
        'Detection logic shipped alongside the write-up for day-one coverage.'
      ]
    },
    {
      id: 'wht-obfuscation', index: '02',
      title: 'Walsh–Hadamard payload obfuscation',
      scope: 'Reverse engineering / MITRE T1027', year: '2026',
      role: 'Researcher', stack: 'Python · Signal analysis',
      link: './posts/wht-shellcode-obfuscation/index.html',
      summary: 'How a Walsh–Hadamard transform hides shellcode from static analysis, with spectral analysis, key sensitivity and a working obfuscation pipeline.',
      highlights: [
        'Spectral signature of the transform and why naive scanners miss it.',
        'Key-sensitivity analysis across transformed payload variants.',
        'Reproducible pipeline with detection ideas for defenders.'
      ]
    },
    {
      id: 'bug-bounty', index: '03',
      title: 'Bug bounty hunting',
      scope: 'HackerOne / Bugcrowd', year: '2026',
      role: 'Independent hunter', stack: 'Web · Mobile · AI · Web3',
      link: 'https://github.com/Vance',
      summary: 'Continuous independent testing across web, mobile, AI and Web3 targets. Findings stay private until the vendor ships the fix; the work is the proof.',
      highlights: [
        'Clear impact statements with working proof of concept.',
        'Private until fixed — responsible disclosure by default.',
        'Findings written so an engineer can reproduce and verify.'
      ]
    },
    {
      id: 'oh-my-pi', index: '04',
      title: 'oh-my-pi',
      scope: 'Tooling / Coding agent', year: '2025',
      role: 'Author', stack: 'TypeScript · IDE integration',
      link: 'https://github.com/Vance/oh-my-pi',
      summary: 'A coding agent with the IDE wired in — a practical experiment in tool-driven engineering and agent–editor workflows.',
      highlights: [
        'IDE-native agent loop with direct editor state access.',
        'Open source, built for real development workflows.'
      ]
    }
  ],

  capabilities: [
    { index: '01', tag: 'OFFENSIVE', title: 'Penetration testing',
      body: 'Scoped, manual testing of web apps, APIs and mobile apps. You get reproducible findings with a fix path, not scanner output.',
      tags: ['Web / API', 'Mobile', 'Manual'] },
    { index: '02', tag: 'RESEARCH', title: 'Vulnerability analysis',
      body: 'Root-cause write-ups for disclosed CVEs: what broke, where in the code, and why the patch works.',
      tags: ['CVE', 'Root cause', 'Patch analysis'] },
    { index: '03', tag: 'RE / DETECTION', title: 'Reverse engineering & detections',
      body: 'Disassembly and behavioural analysis of binaries and obfuscation, paired with Sigma, Suricata and SIEM queries shipped alongside every report.',
      tags: ['Binary', 'Obfuscation', 'Sigma / Suricata'] },
    { index: '04', tag: 'BOUNTY', title: 'Bug bounty',
      body: 'Independent hunting on HackerOne and Bugcrowd, reported with clear impact and working proof.',
      tags: ['HackerOne', 'Bugcrowd', 'Disclosure'] }
  ],

  ledger: [
    { code: 'CORE // ANALYSIS', title: 'Research & reverse',
      items: [['C / Python', 'PRIMARY'], ['Disassembly', 'MANUAL'], ['Binary instrumentation', 'PRACTICAL'], ['Signal analysis', 'APPLIED']] },
    { code: 'CORE // WEB', title: 'Offensive web',
      items: [['Web / API testing', 'MANUAL'], ['HTTP internals', 'DEEP'], ['Auth & session logic', 'FOCUS'], ['Mobile apps', 'SUPPORTED']] },
    { code: 'CORE // OUTPUT', title: 'Evidence & detection',
      items: [['Root-cause write-ups', 'PUBLISHED'], ['Repro steps', 'EVERY FINDING'], ['Sigma / Suricata', 'SHIPPED'], ['Responsible disclosure', 'DEFAULT']] }
  ],

  disciplines: ['Penetration testing', 'Bug bounty', 'Vulnerability analysis', 'Reverse engineering', 'Detection engineering', 'Incident response'],

  socials: [
    { label: 'GitHub ↗', url: 'https://github.com/Vance' },
    { label: 'X ↗', url: 'https://x.com/vancxef' },
    { label: 'Instagram ↗', url: 'https://instagram.com/thepersonarya' }
  ]
};
