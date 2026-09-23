/**
 * Offline Cybersecurity Knowledge Retrieval Engine
 * Operates 100% offline with zero external network connectivity.
 * Implements lexical BM25/TF-IDF scored term matching over MITRE ATT&CK, NIST guidelines,
 * and security engineering attack patterns.
 * (Dense vector embeddings and vector DB require external PyTorch/HuggingFace dependencies).
 */

const KNOWLEDGE_BASE = [
  {
    id: 'T1036',
    title: 'MITRE ATT&CK T1036: Masquerading & File Extension Spoofing',
    category: 'defense_evasion',
    keywords: ['extension', 'mismatch', 'magic bytes', 'mime', 'double extension', 'renamed'],
    summary: 'Adversaries may disguise malicious files by matching filename extensions or embedding misleading icons/MIMEs to bypass static inspection.',
    recommendation: 'Verify header magic bytes and container chunk tables rather than trusting file extensions or user-provided content-types.'
  },
  {
    id: 'T1027.003',
    title: 'MITRE ATT&CK T1027.003: Steganography in Digital Media',
    category: 'obfuscation',
    keywords: ['steganography', 'lsb', 'entropy', 'hidden payload', 'trailing data', 'noise'],
    summary: 'Payrolls, shellcode, or C2 configuration hidden inside image pixel LSBs or audio sample buffers.',
    recommendation: 'Analyze local entropy variance, pixel noise distributions, and slice trailing bytes after file EOF markers.'
  },
  {
    id: 'POLYGLOT-01',
    title: 'Polyglot File Execution Pattern (Zip/PE/JPEG Hybrid)',
    category: 'polyglot',
    keywords: ['polyglot', 'pe header', 'mz', 'zip', 'carving', 'trailing', 'dual interpretation'],
    summary: 'A polyglot file is valid under multiple parser formats simultaneously, such as a valid JPEG image that also functions as an executable PE or ZIP archive.',
    recommendation: 'Scan all byte offsets for secondary container signatures and extract trailing payloads for quarantine.'
  },
  {
    id: 'PHISH-TYPO-01',
    title: 'IDN Homograph & Typosquatting Brand Impersonation',
    category: 'phishing',
    keywords: ['punycode', 'homograph', 'typosquatting', 'brand', 'lookalike', 'subdomain'],
    summary: 'Attackers register lookalike domains using character substitution (e.g. paypa1, micros0ft) or Punycode (xn--) to trick victims into credential submission.',
    recommendation: 'Inspect decoded punycode strings and compute Levenshtein distance against known high-value financial and technology domains.'
  },
  {
    id: 'PHISH-SOCENG-01',
    title: 'Social Engineering & High Urgency Call to Action',
    category: 'phishing',
    keywords: ['urgent', 'suspended', 'verify', 'unlock', 'banking', 'immediate', 'alert'],
    summary: 'Phishing lures deploy manufactured panic (account termination in 24h, unauthorized transaction) to force rash user actions.',
    recommendation: 'Flag high-density urgency lexicon and isolate any input forms requesting authentication tokens.'
  },
  {
    id: 'EMBEDDED-SCRIPT-01',
    title: 'Active Content Injection in Static Documents & Vectors',
    category: 'code_execution',
    keywords: ['svg', 'xml', 'script', 'eval', 'powershell', 'wscript', 'onload'],
    summary: 'Embedding JavaScript inside SVG graphics or macros inside Office/PDF formats to achieve client-side code execution upon rendering.',
    recommendation: 'Sanitize vector documents by stripping all script tags, external entities, and event handlers before display.'
  },
  {
    id: 'DGA-01',
    title: 'Domain Generation Algorithm (DGA) & High-Entropy Hostnames',
    category: 'command_and_control',
    keywords: ['dga', 'entropy', 'random', 'algorithm', 'c2', 'shannon'],
    summary: 'Malware families use automated pseudo-random domain generation algorithms to establish resilient command and control backchannels.',
    recommendation: 'Calculate Shannon character entropy on domain labels and flag values exceeding statistical English baseline (>3.8).'
  }
];

/**
 * BM25-inspired term frequency knowledge retriever
 */
function searchKnowledge(queryTerms) {
  if (!Array.isArray(queryTerms) || queryTerms.length === 0) return [];
  const normalized = queryTerms
    .map(t => String(t).toLowerCase().trim())
    .filter(t => t.length > 1);

  const scored = KNOWLEDGE_BASE.map(entry => {
    let score = 0;
    for (const term of normalized) {
      for (const kw of entry.keywords) {
        if (term === kw) {
          score += 3.0; // exact match
        } else if (term.includes(kw) || kw.includes(term)) {
          score += 1.5; // partial match
        }
      }
      if (entry.title.toLowerCase().includes(term)) {
        score += 2.0;
      }
      if (entry.summary.toLowerCase().includes(term)) {
        score += 1.0;
      }
    }
    return { entry, score };
  });

  return scored
    .filter(item => item.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 3)
    .map(item => ({
      ...item.entry,
      retrievalScore: Number(item.score.toFixed(2)),
      retrievalEngine: 'Offline BM25 Lexical Term Matcher'
    }));
}

module.exports = {
  KNOWLEDGE_BASE,
  searchKnowledge
};
