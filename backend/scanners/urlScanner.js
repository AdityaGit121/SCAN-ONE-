const { searchKnowledge } = require('./localRag');

// Blacklisted malicious domains
const BLACKLISTED_DOMAINS = new Set([
  'paypa1.com',
  'faceb00k-login.com',
  'secure-update-bank.com',
  'verify-account-now.com',
  'free-bitcoin-generator.com',
  'wallet-verify.net',
  'account-suspended-notice.com',
  'apple-id-suspended.com',
  'microsoft-support-alert.com',
  'chase-verify-login.com',
  'wellsfargo-security-alert.net',
  'metamask-restore-seed.org'
]);

// High-value targets for brand impersonation detection
const KNOWN_BRANDS = [
  'paypal', 'google', 'apple', 'microsoft', 'netflix', 'amazon',
  'facebook', 'instagram', 'whatsapp', 'binance', 'coinbase', 'chase',
  'wellsfargo', 'bankofamerica', 'dropbox', 'github', 'discord'
];

const SUSPICIOUS_TLDS = new Set([
  '.tk', '.xyz', '.top', '.gq', '.ml', '.cf', '.pw', '.ga', '.work',
  '.click', '.cc', '.buzz', '.icu', '.monster', '.loan', '.fit'
]);

const PHISHING_KEYWORDS = [
  'login', 'verify', 'secure', 'update', 'account', 'banking',
  'signin', 'free', 'bonus', 'gift', 'suspended', 'confirm',
  'unlock', 'recovery', 'alert', 'urgent', 'limited', 'billing',
  'credential', 'wallet', 'password', 'validate', 'kyc', 'reactivate'
];

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'rb.gy', 'is.gd', 'cutt.ly', 'shorte.st'
]);

/**
 * Calculate Shannon Entropy of a string to detect randomized/algorithmically generated domains (DGA).
 */
function calculateEntropy(str) {
  if (!str) return 0;
  const len = str.length;
  const frequencies = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

/**
 * Scan a URL using offline heuristics and deterministic rules.
 */
function analyzeUrlOffline(urlString) {
  const findings = [];
  const evidence = [];
  let score = 0;
  let parsedUrl = null;

  try {
    parsedUrl = new URL(urlString);
  } catch (err) {
    return {
      success: false,
      error: 'Invalid or malformed URL syntax',
      verdict: 'MALICIOUS',
      riskScore: 85,
      confidence: 0.9,
      findings: ['Malformed URL structure cannot be safely parsed']
    };
  }

  const host = parsedUrl.hostname.toLowerCase();
  const pathname = parsedUrl.pathname.toLowerCase();
  const search = parsedUrl.search.toLowerCase();
  const full = urlString.toLowerCase();

  // 1. Blacklist check
  if (BLACKLISTED_DOMAINS.has(host)) {
    score += 85;
    const desc = `Domain '${host}' is registered in the offline threat blacklist.`;
    findings.push(desc);
    evidence.push({ type: 'blacklist', severity: 'high', description: desc });
  }

  // 2. Encryption / HTTPS
  const isHttps = parsedUrl.protocol === 'https:';
  if (!isHttps) {
    score += 15;
    const desc = 'Non-HTTPS plaintext connection (http://)';
    findings.push(desc);
    evidence.push({ type: 'encryption', severity: 'medium', description: desc });
  }

  // 3. Raw IP Host
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
  if (isIp) {
    score += 40;
    const desc = `Raw IP address used as hostname (${host}) instead of domain name.`;
    findings.push(desc);
    evidence.push({ type: 'ip_host', severity: 'high', description: desc });
  }

  // 4. Punycode / Internationalized Domain Name (IDN homograph attack)
  if (host.includes('xn--')) {
    score += 45;
    const desc = `Punycode (IDN) detected: '${host}' (potential homograph character spoofing).`;
    findings.push(desc);
    evidence.push({ type: 'homograph', severity: 'high', description: desc });
  }

  // 5. High-risk TLD
  for (const tld of SUSPICIOUS_TLDS) {
    if (host.endsWith(tld)) {
      score += 20;
      const desc = `High-abuse TLD registered: ${tld}`;
      findings.push(desc);
      evidence.push({ type: 'tld', severity: 'medium', description: desc });
      break;
    }
  }

  // 6. Brand impersonation / Typosquatting in domain
  let isOfficialBrandDomain = false;
  for (const brand of KNOWN_BRANDS) {
    if (host.includes(brand)) {
      // Check if it's the genuine brand domain
      const isGenuine = host === `${brand}.com` || host.endsWith(`.${brand}.com`) || host === `${brand}.org` || host.endsWith(`.${brand}.org`);
      if (isGenuine) {
        isOfficialBrandDomain = true;
      } else {
        score += 35;
        const desc = `Brand name '${brand}' found in suspicious non-official domain '${host}'.`;
        findings.push(desc);
        evidence.push({ type: 'typosquatting', severity: 'high', description: desc });
      }
    }
  }

  // 7. Phishing keywords in domain and path
  const matchedDomainKeywords = PHISHING_KEYWORDS.filter(kw => host.includes(kw));
  if (matchedDomainKeywords.length > 0) {
    const inc = Math.min(matchedDomainKeywords.length * 15, 45);
    score += inc;
    const desc = `Phishing trigger words in domain: ${matchedDomainKeywords.join(', ')}`;
    findings.push(desc);
    evidence.push({ type: 'social_engineering', severity: 'medium', description: desc });
  }

  const matchedPathKeywords = PHISHING_KEYWORDS.filter(kw => pathname.includes(kw) || search.includes(kw));
  if (matchedPathKeywords.length > 0 && (!isOfficialBrandDomain || !isHttps)) {
    const inc = Math.min(matchedPathKeywords.length * 10, 30);
    score += inc;
    const desc = `Security/credential keywords in path or query: ${matchedPathKeywords.join(', ')}`;
    findings.push(desc);
    evidence.push({ type: 'credential_harvest', severity: 'medium', description: desc });
  }

  // 8. @ symbol attack pattern
  if (urlString.includes('@')) {
    score += 50;
    const desc = '@ character present in URL — potential credential spoofing or URL redirection attack.';
    findings.push(desc);
    evidence.push({ type: 'syntax_abuse', severity: 'high', description: desc });
  }

  // 9. Excessive subdomains
  const subdomains = host.split('.');
  if (subdomains.length > 4) {
    score += 20;
    const desc = `Excessive subdomain depth (${subdomains.length} labels) used to obscure target domain.`;
    findings.push(desc);
    evidence.push({ type: 'subdomain_depth', severity: 'medium', description: desc });
  }

  // 10. URL Shortener
  if (URL_SHORTENERS.has(host)) {
    score += 15;
    const desc = `Known URL shortener service (${host}) masks ultimate destination.`;
    findings.push(desc);
    evidence.push({ type: 'redirection_mask', severity: 'low', description: desc });
  }

  // 11. Domain Entropy (DGA detection)
  const mainDomain = subdomains.slice(-2).join('.');
  const entropy = calculateEntropy(mainDomain.split('.')[0] || host);
  if (entropy > 3.8 && mainDomain.length > 10) {
    score += 25;
    const desc = `High Shannon entropy (${entropy}) indicates potential Algorithmically Generated Domain (DGA).`;
    findings.push(desc);
    evidence.push({ type: 'dga_entropy', severity: 'medium', description: desc });
  }

  // 12. Suspicious ports
  if (parsedUrl.port && !['80', '443', '8080', '8443'].includes(parsedUrl.port)) {
    score += 20;
    const desc = `Non-standard web port targeted: :${parsedUrl.port}`;
    findings.push(desc);
    evidence.push({ type: 'port_anomaly', severity: 'medium', description: desc });
  }

  // Calculate final offline risk
  const normalizedScore = Math.min(score, 100);
  let verdict = 'SAFE';
  if (normalizedScore >= 70) verdict = 'MALICIOUS';
  else if (normalizedScore >= 45) verdict = 'HIGH_RISK';
  else if (normalizedScore >= 25) verdict = 'SUSPICIOUS';
  else if (normalizedScore >= 10) verdict = 'LOW_RISK';

  // Retrieve matching offline knowledge base articles
  const searchTerms = [...matchedDomainKeywords, ...matchedPathKeywords];
  if (isIp) searchTerms.push('ip');
  if (host.includes('xn--')) searchTerms.push('punycode', 'homograph');
  const ragMatches = searchKnowledge(searchTerms);

  return {
    success: true,
    url: urlString,
    parsed: {
      protocol: parsedUrl.protocol,
      host,
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? '443' : '80'),
      pathname,
      search,
      entropy
    },
    verdict,
    riskScore: normalizedScore,
    confidence: findings.length === 0 ? 0.95 : 0.88,
    findings: findings.length > 0 ? findings : ['No anomalous indicators detected by offline heuristics'],
    evidence,
    ragMatches,
    offlineNotice: 'Offline analysis completed without external network transmission. Live domain reputation is unverified.'
  };
}

module.exports = {
  analyzeUrlOffline,
  calculateEntropy,
  BLACKLISTED_DOMAINS,
  KNOWN_BRANDS
};
