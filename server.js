const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');

// Security & Scanning Modules
const { validateUrlForSafeFetch } = require('./backend/security/ssrfGuard');
const { analyzeUrlOffline } = require('./backend/scanners/urlScanner');
const { analyzeMediaFileOffline } = require('./backend/scanners/mediaScanner');
const { analyzeStegoSignals } = require('./backend/scanners/stegoScanner');
const { classifySample } = require('./backend/scanners/mlClassifier');
const { sandboxEngine } = require('./backend/scanners/sandboxAdapter');
const { getThreatIntelligenceGraph } = require('./backend/scanners/threatIntel');
const { KNOWLEDGE_BASE } = require('./backend/scanners/localRag');
const { fuseEvidence } = require('./backend/evidence/fusionEngine');
const {
  DEFAULT_MODEL,
  testGeminiConnection,
  analyzeUrlWithGemini,
  analyzeMediaWithGemini
} = require('./backend/ai/geminiService');
const { generatePdfReport } = require('./backend/reports/pdfGenerator');
const { scanJobManager } = require('./backend/scanners/scanJobManager');

const app = express();

// Secure file upload config: in-memory, strict 20MB limit
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 }
});

app.use(express.json({ limit: '4mb' }));
app.use(express.urlencoded({ extended: true, limit: '4mb' }));

// Security Headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Serve frontend assets
app.use(express.static(path.join(__dirname, 'public')));

// In-Memory Scan History (Max 100 entries, no sensitive keys stored)
const scanHistory = [];
const fullScanResults = new Map();

function recordHistory(entry, fullResult) {
  scanHistory.unshift({
    id: entry.id || crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    ...entry
  });
  if (fullResult) {
    fullScanResults.set(entry.id || fullResult.scanId, fullResult);
  }
  if (scanHistory.length > 100) {
    const popped = scanHistory.pop();
    if (popped && popped.id) fullScanResults.delete(popped.id);
  }
}

// ── Real-Time Scan Progress API (Polling & Server-Sent Events) ────────────────
app.get('/api/scan/progress/:jobId', (req, res) => {
  const job = scanJobManager.getJob(req.params.jobId);
  if (!job) {
    return res.status(404).json({ success: false, error: 'Job not found' });
  }
  res.json({ success: true, job });
});

app.get('/api/scan/stream/:jobId', (req, res) => {
  const { jobId } = req.params;
  const job = scanJobManager.getJob(jobId);

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  // Send initial state
  if (job) {
    res.write(`data: ${JSON.stringify(job)}\n\n`);
  }

  const onUpdate = (updatedJob) => {
    res.write(`data: ${JSON.stringify(updatedJob)}\n\n`);
    if (updatedJob.status === 'COMPLETE' || updatedJob.status === 'FAILED') {
      scanJobManager.removeListener(`update:${jobId}`, onUpdate);
      res.end();
    }
  };

  scanJobManager.on(`update:${jobId}`, onUpdate);

  req.on('close', () => {
    scanJobManager.removeListener(`update:${jobId}`, onUpdate);
  });
});

// ── PDF Report Generation Endpoint ───────────────────────────────────────────
app.post('/api/report/pdf', async (req, res) => {
  try {
    let scanResult = req.body.scanResult;
    const scanId = req.body.scanId;

    if (!scanResult && scanId) {
      scanResult = fullScanResults.get(scanId);
    }

    if (!scanResult) {
      return res.status(400).json({ success: false, error: 'Valid scanResult or scanId is required' });
    }

    const pdfBuffer = await generatePdfReport(scanResult);
    const safeTarget = (scanResult.target || 'target').replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 30);
    
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="Safety_Report_${safeTarget}_${Date.now()}.pdf"`);
    res.setHeader('Content-Length', pdfBuffer.length);
    res.send(pdfBuffer);
  } catch (err) {
    console.error('[PDF Generation Error]:', err);
    res.status(500).json({ success: false, error: 'Failed to generate PDF report', details: err.message });
  }
});

app.get('/api/report/pdf/:scanId', async (req, res) => {
  try {
    const scanResult = fullScanResults.get(req.params.scanId);
    if (!scanResult) {
      return res.status(404).send('Report not found for this scan ID');
    }

    const pdfBuffer = await generatePdfReport(scanResult);
    const safeTarget = (scanResult.target || 'target').replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 30);
    
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="Safety_Report_${safeTarget}.pdf"`);
    res.setHeader('Content-Length', pdfBuffer.length);
    res.send(pdfBuffer);
  } catch (err) {
    res.status(500).send(`PDF Generation failed: ${err.message}`);
  }
});

// ── Dual-Mode URL Scan Endpoint with Real-Time Pipeline Hooks ─────────────────
app.post('/api/scan/url', async (req, res) => {
  const { url, mode = 'offline', apiKey, model = DEFAULT_MODEL, jobId } = req.body;
  
  if (!url) {
    return res.status(400).json({ success: false, error: 'URL is required' });
  }

  const activeJobId = jobId || crypto.randomUUID();
  scanJobManager.createJob(activeJobId, { target: url, type: 'url', mode });

  try {
    const scanMode = mode === 'online' ? 'online' : 'offline';

    // Stage 1: Hash & Signatures / SSRF Check
    scanJobManager.updateStage(activeJobId, 'HASH_SIGNATURES', 'Validating protocol syntax and checking SSRF safety guards...');
    if (scanMode === 'online') {
      const ssrfCheck = await validateUrlForSafeFetch(url);
      if (!ssrfCheck.safe) {
        scanJobManager.failJob(activeJobId, `URL blocked by SSRF Security Policy: ${ssrfCheck.reason}`);
        return res.status(400).json({
          success: false,
          error: `URL blocked by SSRF Security Policy: ${ssrfCheck.reason}`
        });
      }
    }
    scanJobManager.updateStage(activeJobId, 'HASH_SIGNATURES', 'SSRF and initial protocol checks passed', true);

    // Stage 2: Structural Analysis & DNS Graph
    scanJobManager.updateStage(activeJobId, 'STRUCTURAL_ANALYSIS', 'Parsing URL structure, domain labels, and resolving DNS records...');
    const staticResult = analyzeUrlOffline(url);
    const threatIntelResult = await getThreatIntelligenceGraph(url, scanMode);
    scanJobManager.updateStage(activeJobId, 'STRUCTURAL_ANALYSIS', 'Structural heuristics and threat relationships resolved', true);

    // Stage 3: Steganography / Shannon Entropy
    scanJobManager.updateStage(activeJobId, 'STEGO_ENTROPY', 'Calculating Shannon entropy and algorithmic randomness (DGA)...');
    const urlBuffer = Buffer.from(url, 'utf-8');
    const mlResult = classifySample(urlBuffer, 'url');
    scanJobManager.updateStage(activeJobId, 'STEGO_ENTROPY', `Calculated Shannon entropy: ${staticResult.parsed?.entropy ?? 0}`, true);

    // Stage 4: Behavioral Sandbox Emulation
    scanJobManager.updateStage(activeJobId, 'BEHAVIORAL_SANDBOX', 'Trace behavioral emulation for credential harvesting hooks...');
    const sandboxResult = await sandboxEngine.runAnalysis({
      detectedType: 'URL',
      structuralFindings: staticResult.findings,
      bufferText: url
    });
    scanJobManager.updateStage(activeJobId, 'BEHAVIORAL_SANDBOX', 'Behavioral trace analysis complete', true);

    // Stage 5: Gemini AI Reasoning (Online Only)
    let geminiResult = null;
    if (scanMode === 'online') {
      scanJobManager.updateStage(activeJobId, 'AI_REASONING', `Querying Google Gemini (${model}) for threat reasoning...`);
      geminiResult = await analyzeUrlWithGemini({
        url,
        heuristics: staticResult,
        customApiKey: apiKey,
        model
      });
      scanJobManager.updateStage(activeJobId, 'AI_REASONING', geminiResult.available ? 'Gemini structured analysis completed' : 'Fallback to local rule evidence', true);
    } else {
      scanJobManager.updateStage(activeJobId, 'AI_REASONING', 'Offline Mode: Cloud AI bypassed for 100% air-gapped isolation', true);
    }

    // Stage 6: Evidence Fusion
    scanJobManager.updateStage(activeJobId, 'EVIDENCE_FUSION', 'Aggregating telemetry scores across all inspection layers...');
    const fusion = fuseEvidence({
      mode: scanMode,
      targetType: 'url',
      staticResult,
      mlResult,
      sandboxResult,
      threatIntelResult,
      geminiResult
    });

    const responsePayload = {
      success: true,
      scanId: activeJobId,
      jobId: activeJobId,
      timestamp: new Date().toISOString(),
      target: url,
      targetType: 'url',
      mode: scanMode,
      verdict: fusion.verdict,
      riskScore: fusion.riskScore,
      confidence: fusion.confidence,
      recommendation: fusion.recommendation,
      layerScores: fusion.layerScores,
      layers: fusion.layers,
      findings: staticResult.findings,
      evidence: fusion.consolidatedEvidence,
      graph: threatIntelResult.graph,
      dns: threatIntelResult.dnsRecords,
      ragMatches: staticResult.ragMatches || [],
      aiAnalysis: geminiResult,
      parsed: staticResult.parsed
    };

    scanJobManager.completeJob(activeJobId, responsePayload);

    recordHistory({
      id: activeJobId,
      target: url,
      targetType: 'url',
      mode: scanMode,
      verdict: fusion.verdict,
      riskScore: fusion.riskScore,
      findingsCount: staticResult.findings.length
    }, responsePayload);

    res.json(responsePayload);
  } catch (err) {
    console.error('[URL Scan Error]:', err);
    scanJobManager.failJob(activeJobId, err.message);
    res.status(500).json({ success: false, error: 'Internal scan failure', message: err.message });
  }
});

// ── Dual-Mode File / Media Scan Endpoint with Real-Time Pipeline Hooks ────────
app.post('/api/scan/file', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, error: 'No file uploaded' });
  }

  const { buffer, originalname, size, mimetype } = req.file;
  const mode = req.body.mode === 'online' ? 'online' : 'offline';
  const apiKey = req.body.apiKey;
  const model = req.body.model || DEFAULT_MODEL;
  const activeJobId = req.body.jobId || crypto.randomUUID();

  scanJobManager.createJob(activeJobId, { target: originalname, type: 'file', mode });

  try {
    // Stage 1: Hashes, Magic Bytes & Signatures
    scanJobManager.updateStage(activeJobId, 'HASH_SIGNATURES', 'Computing SHA-256 and validating magic byte headers...');
    const staticResult = analyzeMediaFileOffline(buffer, originalname);
    scanJobManager.updateStage(activeJobId, 'HASH_SIGNATURES', `Detected magic format: ${staticResult.detectedType}`, true);

    // Stage 2: Structural Chunks & Polyglots
    scanJobManager.updateStage(activeJobId, 'STRUCTURAL_ANALYSIS', 'Walking chunk tables, checking EOI terminators & polyglot offsets...');
    scanJobManager.updateStage(activeJobId, 'STRUCTURAL_ANALYSIS', `Found ${staticResult.structureTree?.length || 0} chunks, ${staticResult.polyglotFindings?.length || 0} polyglot markers`, true);

    // Stage 3: Stego & Entropy
    scanJobManager.updateStage(activeJobId, 'STEGO_ENTROPY', 'Inspecting LSB distribution and payload high-frequency entropy...');
    const stegoResult = analyzeStegoSignals(buffer, mimetype);
    const mlResult = classifySample(buffer, 'file');
    scanJobManager.updateStage(activeJobId, 'STEGO_ENTROPY', `LSB Ratio: ${stegoResult.lsbRatio} · Local Entropy: ${stegoResult.localEntropy}`, true);

    // Stage 4: Behavioral Sandbox Emulation
    scanJobManager.updateStage(activeJobId, 'BEHAVIORAL_SANDBOX', 'Trace static behavioral telemetry for persistence and injection...');
    const sandboxResult = await sandboxEngine.runAnalysis({
      detectedType: staticResult.detectedType,
      structuralFindings: staticResult.findings,
      bufferText: buffer.slice(0, 16384).toString('latin1')
    });
    scanJobManager.updateStage(activeJobId, 'BEHAVIORAL_SANDBOX', `Sandbox Emulation status: ${sandboxResult.verdict}`, true);

    // Stage 5: Gemini AI Reasoning (Online Only)
    let geminiResult = null;
    if (mode === 'online') {
      scanJobManager.updateStage(activeJobId, 'AI_REASONING', `Engaging Gemini (${model}) for reverse-engineering assessment...`);
      geminiResult = await analyzeMediaWithGemini({
        fileName: originalname,
        fileSize: size,
        sha256: staticResult.sha256,
        staticFindings: staticResult.findings,
        structureTree: staticResult.structureTree,
        polyglotFindings: staticResult.polyglotFindings,
        customApiKey: apiKey,
        model
      });
      scanJobManager.updateStage(activeJobId, 'AI_REASONING', geminiResult.available ? 'Gemini structural evaluation completed' : 'Fallback to local rule evidence', true);
    } else {
      scanJobManager.updateStage(activeJobId, 'AI_REASONING', 'Offline Mode: Air-gapped isolation maintained', true);
    }

    // Stage 6: Evidence Fusion
    scanJobManager.updateStage(activeJobId, 'EVIDENCE_FUSION', 'Aggregating static, ML, sandbox, and AI telemetry...');
    const fusion = fuseEvidence({
      mode,
      targetType: 'file',
      staticResult,
      mlResult,
      sandboxResult,
      threatIntelResult: { status: 'MEDIA_CONTAINER_ISOLATED' },
      geminiResult
    });

    const responsePayload = {
      success: true,
      scanId: activeJobId,
      jobId: activeJobId,
      timestamp: new Date().toISOString(),
      target: originalname,
      targetType: 'file',
      mode,
      fileSize: size,
      sha256: staticResult.sha256,
      md5: staticResult.md5,
      entropy: staticResult.entropy,
      detectedType: staticResult.detectedType,
      matchedMime: staticResult.matchedMime,
      verdict: fusion.verdict,
      riskScore: fusion.riskScore,
      confidence: fusion.confidence,
      recommendation: fusion.recommendation,
      layerScores: fusion.layerScores,
      layers: fusion.layers,
      findings: staticResult.findings,
      evidence: fusion.consolidatedEvidence,
      structureTree: staticResult.structureTree,
      offsetTimeline: staticResult.offsetTimeline,
      polyglotFindings: staticResult.polyglotFindings,
      stego: stegoResult,
      sandbox: sandboxResult,
      ragMatches: staticResult.ragMatches || [],
      aiAnalysis: geminiResult
    };

    scanJobManager.completeJob(activeJobId, responsePayload);

    recordHistory({
      id: activeJobId,
      target: originalname,
      targetType: 'file',
      mode,
      verdict: fusion.verdict,
      riskScore: fusion.riskScore,
      sha256: staticResult.sha256,
      findingsCount: staticResult.findings.length
    }, responsePayload);

    res.json(responsePayload);
  } catch (err) {
    console.error('[File Scan Error]:', err);
    scanJobManager.failJob(activeJobId, err.message);
    res.status(500).json({ success: false, error: 'File scan failure', message: err.message });
  }
});

// ── Gemini Connection Test ───────────────────────────────────────────────────
app.post('/api/gemini/test', async (req, res) => {
  const { apiKey, model } = req.body;
  const result = await testGeminiConnection(apiKey, model);
  res.json(result);
});

// ── System Diagnostics ───────────────────────────────────────────────────────
app.get('/api/system/diagnostics', (req, res) => {
  res.json({
    system: 'Safety Downloader AI Platform',
    version: '2.4.0',
    modeSupported: ['ONLINE_AI', 'OFFLINE_LOCAL'],
    features: {
      pdfReporting: 'ACTIVE',
      realtimePipeline: 'ACTIVE_SSE_AND_POLLING',
      activeJobsTracked: scanJobManager.jobs.size
    },
    offlineEngine: {
      status: 'OPERATIONAL',
      knowledgeBaseEntries: KNOWLEDGE_BASE.length,
      structuralParsers: ['JPEG', 'PNG', 'WEBP', 'GIF', 'MP4', 'SVG', 'PDF'],
      polyglotCarvers: ['PE_MZ', 'ELF', 'ZIP_PK'],
      stegoEngine: 'LSB_Variance_Entropy_v2'
    },
    sandbox: {
      status: 'ISOLATED_EMULATION_ACTIVE',
      adapter: 'Static Behavioral Emulation Engine'
    },
    geminiAi: {
      configuredInEnv: !!process.env.GEMINI_API_KEY,
      defaultModel: DEFAULT_MODEL
    },
    memoryUsage: process.memoryUsage()
  });
});

// ── Scan History Management ──────────────────────────────────────────────────
app.get('/api/history', (req, res) => {
  res.json({ history: scanHistory });
});

app.delete('/api/history', (req, res) => {
  scanHistory.length = 0;
  fullScanResults.clear();
  res.json({ success: true, message: 'History cleared' });
});

app.delete('/api/history/:id', (req, res) => {
  const index = scanHistory.findIndex(h => h.id === req.params.id);
  if (index !== -1) {
    scanHistory.splice(index, 1);
  }
  fullScanResults.delete(req.params.id);
  res.json({ success: true });
});

// ── Backward Compatibility: Prototype Endpoints ──────────────────────────────
app.get('/api/scan', (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: 'URL required' });
  const result = analyzeUrlOffline(url);
  res.json({
    status: result.verdict === 'SAFE' ? 'SAFE' : 'WARNING',
    message: 'Advanced URL threat intelligence analysis completed',
    riskLevel: result.verdict,
    riskLabel: result.verdict,
    riskScore: result.riskScore,
    findings: result.findings,
    url
  });
});

app.post('/api/scan-file', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const result = analyzeMediaFileOffline(req.file.buffer, req.file.originalname);
  res.json({
    status: result.verdict === 'SAFE' ? 'SAFE' : 'WARNING',
    message: 'Advanced hybrid file analysis completed',
    riskLevel: result.verdict,
    riskLabel: result.verdict,
    riskScore: result.riskScore,
    findings: result.findings,
    fileName: req.file.originalname,
    fileSize: req.file.size,
    sha256: result.sha256
  });
});

// ── Health Check ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    platform: 'Safety Downloader AI Platform',
    onlineScanEnabled: true,
    offlineScanEnabled: true,
    pdfExportReady: true,
    realtimePipeline: true
  });
});

// ── Fallback SPA ─────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;

if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Safety Downloader] Security Platform running on http://0.0.0.0:${PORT}`);
  });
}

module.exports = app;

