const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Signature Database ───────────────────────────────────────────────────────
const MALWARE_HASHES = new Set([
  '44d88612fea8a8f36de82e1278abb02f'
]);

const SUSPICIOUS_EXTENSIONS = new Set(['.exe', '.bat', '.vbs', '.scr', '.ps1', '.cmd', '.msi', '.com', '.pif']);

const SAFE_EXTENSIONS = new Set([
  'txt','pdf','jpg','jpeg','png','gif','webp',
  'doc','docx','xls','xlsx','ppt','pptx',
  'mp4','mkv','avi','mp3','wav','zip','rar','7z'
]);

// ─── URL Blacklist Database ───────────────────────────────────────────────────
const BLACKLISTED_DOMAINS = new Set([
  'paypa1.com','faceb00k-login.com','secure-update-bank.com',
  'verify-account-now.com','free-bitcoin-generator.com',
  'wallet-verify.net','account-suspended-notice.com',
  'apple-id-suspended.com','microsoft-support-alert.com'
]);

const SUSPICIOUS_TLDS = ['.tk','.xyz','.top','.gq','.ml','.cf','.pw','.ga','.work','.click'];

const PHISHING_KEYWORDS = [
  'login','verify','secure','update','account','banking',
  'signin','free','bonus','gift','suspended','confirm',
  'unlock','recovery','alert','urgent','limited'
];

// ─── Risk Engine ──────────────────────────────────────────────────────────────
function calculateRisk(score) {
  if (score < 20) return 'SAFE';
  if (score < 40) return 'SLIGHTLY_RISKY';
  if (score < 70) return 'MODERATE';
  return 'DANGEROUS';
}

function getRiskLabel(level) {
  const map = {
    'SAFE': 'Safe',
    'SLIGHTLY_RISKY': 'Slightly Risky',
    'MODERATE': 'Moderate Risk',
    'DANGEROUS': 'Dangerous'
  };
  return map[level] || level;
}

// ─── Heuristic Engine ─────────────────────────────────────────────────────────
function analyzeHeuristics(content) {
  const lower = content.toLowerCase();
  let score = 0;
  const flags = [];

  if (lower.includes('powershell'))       { score += 30; flags.push('PowerShell command detected'); }
  if (lower.includes('cmd.exe'))          { score += 30; flags.push('CMD execution pattern'); }
  if (lower.includes('eval('))            { score += 25; flags.push('eval() code execution'); }
  if (lower.includes('base64_decode'))    { score += 25; flags.push('Base64 decode pattern'); }
  if (lower.includes('wget ') || lower.includes('curl ')) { score += 20; flags.push('Network download command'); }
  if (lower.includes('system('))          { score += 30; flags.push('System call detected'); }
  if (lower.includes('shell_exec'))       { score += 30; flags.push('Shell execution'); }
  if (lower.includes('createobject'))     { score += 20; flags.push('COM object creation'); }
  if (lower.includes('wscript'))          { score += 25; flags.push('Windows Script Host'); }
  if (lower.includes('regwrite'))         { score += 25; flags.push('Registry write attempt'); }

  return { score, flags };
}

// ─── Binary Analyzer ─────────────────────────────────────────────────────────
function analyzeBinary(buffer) {
  let score = 0;
  const flags = [];

  if (buffer.length < 2) return { score, flags };

  // Windows PE executable (MZ header)
  if (buffer[0] === 0x4D && buffer[1] === 0x5A) {
    score += 40;
    flags.push('Windows PE executable header (MZ)');
  }

  // ELF Linux executable
  if (buffer[0] === 0x7F && buffer[1] === 0x45 && buffer[2] === 0x4C && buffer[3] === 0x46) {
    score += 40;
    flags.push('Linux ELF executable header');
  }

  // Mach-O macOS executable
  if ((buffer[0] === 0xFE && buffer[1] === 0xED && buffer[2] === 0xFA) ||
      (buffer[0] === 0xCE && buffer[1] === 0xFA && buffer[2] === 0xED)) {
    score += 35;
    flags.push('macOS Mach-O executable header');
  }

  return { score, flags };
}

// ─── SHA256 Hash ──────────────────────────────────────────────────────────────
function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

// ─── /api/scan-file ───────────────────────────────────────────────────────────
app.post('/api/scan-file', upload.single('file'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const buffer = req.file.buffer;
    const fileName = req.file.originalname || '';
    const ext = fileName.includes('.') ? '.' + fileName.split('.').pop().toLowerCase() : '';
    const content = buffer.toString('latin1');

    let riskScore = 0;
    const findings = [];

    // 1. Hash check
    const hash = sha256(buffer);
    if (MALWARE_HASHES.has(hash)) {
      riskScore += 90;
      findings.push('Known malware hash match');
    }

    // 2. Extension check
    if (SUSPICIOUS_EXTENSIONS.has(ext)) {
      riskScore += 40;
      findings.push(`Suspicious file extension: ${ext}`);
    } else if (!SAFE_EXTENSIONS.has(ext.replace('.', ''))) {
      riskScore += 10;
      findings.push(`Unknown file type: ${ext || 'none'}`);
    }

    // 3. Binary analysis
    const binary = analyzeBinary(buffer);
    riskScore += binary.score;
    findings.push(...binary.flags);

    // 4. Heuristic analysis
    const heuristic = analyzeHeuristics(content);
    riskScore += heuristic.score;
    findings.push(...heuristic.flags);

    const riskLevel = calculateRisk(riskScore);

    res.json({
      status: riskLevel === 'SAFE' ? 'SAFE' : 'WARNING',
      message: 'Advanced hybrid file analysis completed',
      riskLevel,
      riskLabel: getRiskLabel(riskLevel),
      riskScore,
      findings: findings.length ? findings : ['No threats detected'],
      fileName,
      fileSize: buffer.length,
      sha256: hash
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Scan failed', message: err.message });
  }
});

// ─── /api/scan (URL) ──────────────────────────────────────────────────────────
app.get('/api/scan', (req, res) => {
  const urlString = req.query.url;
  if (!urlString) return res.status(400).json({ error: 'URL required' });

  let riskScore = 0;
  const findings = [];

  try {
    const url = new URL(urlString);
    const host = url.hostname.toLowerCase();
    const fullUrl = urlString.toLowerCase();

    // 1. Blacklist check
    if (BLACKLISTED_DOMAINS.has(host)) {
      riskScore += 80;
      findings.push('Domain found in threat blacklist');
    }

    // 2. HTTPS check
    if (!urlString.startsWith('https')) {
      riskScore += 20;
      findings.push('No HTTPS — unencrypted connection');
    }

    // 3. Suspicious TLD
    for (const tld of SUSPICIOUS_TLDS) {
      if (host.endsWith(tld)) {
        riskScore += 25;
        findings.push(`High-risk TLD detected: ${tld}`);
        break;
      }
    }

    // 4. Phishing keywords
    const matchedKeywords = PHISHING_KEYWORDS.filter(k => host.includes(k));
    if (matchedKeywords.length > 0) {
      riskScore += Math.min(matchedKeywords.length * 20, 60);
      findings.push(`Phishing keywords in domain: ${matchedKeywords.join(', ')}`);
    }

    // 5. IP address instead of domain
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      riskScore += 40;
      findings.push('Raw IP address used instead of domain name');
    }

    // 6. Excessively long subdomain
    if (host.length > 30) {
      riskScore += 20;
      findings.push('Unusually long domain (possible obfuscation)');
    }

    // 7. @ symbol attack pattern
    if (urlString.includes('@')) {
      riskScore += 50;
      findings.push('@ symbol in URL — possible redirect attack');
    }

    // 8. Multiple subdomains
    const parts = host.split('.');
    if (parts.length > 4) {
      riskScore += 15;
      findings.push('Excessive subdomain depth');
    }

    // 9. URL shortener
    const shorteners = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','rb.gy','is.gd'];
    if (shorteners.includes(host)) {
      riskScore += 15;
      findings.push('URL shortener detected — destination unknown');
    }

    // 10. Suspicious path keywords
    const suspiciousPath = ['phish','hack','malware','virus','trojan','exploit','payload'];
    for (const kw of suspiciousPath) {
      if (fullUrl.includes(kw)) {
        riskScore += 30;
        findings.push(`Suspicious path keyword: ${kw}`);
        break;
      }
    }

  } catch (e) {
    riskScore += 70;
    findings.push('Invalid or malformed URL');
  }

  const riskLevel = calculateRisk(riskScore);

  res.json({
    status: riskLevel === 'SAFE' ? 'SAFE' : 'WARNING',
    message: 'Advanced URL threat intelligence analysis completed',
    riskLevel,
    riskLabel: getRiskLabel(riskLevel),
    riskScore,
    findings: findings.length ? findings : ['No threats detected'],
    url: urlString
  });
});

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ─── Serve frontend ───────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Safety Downloader running on http://localhost:${PORT}`));
