/**
 * Evidence Fusion Engine
 * Synthesizes multi-layer telemetry into an explainable, defensible cybersecurity verdict.
 * States: SAFE | LOW_RISK | SUSPICIOUS | HIGH_RISK | MALICIOUS | UNKNOWN
 */

function fuseEvidence({
  mode = 'offline',
  targetType = 'url',
  staticResult = {},
  mlResult = {},
  sandboxResult = {},
  threatIntelResult = {},
  geminiResult = null
}) {
  // If static result indicates UNKNOWN (e.g. empty buffer or invalid input)
  if (staticResult.verdict === 'UNKNOWN') {
    return {
      verdict: 'UNKNOWN',
      riskScore: 0,
      confidence: 0,
      layerScores: { staticScore: 0, mlScore: 0, behaviorScore: 0, threatIntelScore: 0, aiAssessment: null },
      layers: {
        traditional: { active: true, status: 'INSUFFICIENT_DATA' },
        structural: { active: true, status: 'INSUFFICIENT_DATA' },
        ml: { active: false, score: 0 },
        threatIntel: { active: false, status: 'INSUFFICIENT_DATA' },
        sandbox: { active: false, status: 'INSUFFICIENT_DATA' },
        gemini: { active: false, available: false }
      },
      consolidatedEvidence: [],
      recommendation: 'Insufficient data or empty sample provided. Cannot render a definitive security verdict.'
    };
  }

  const staticScore = staticResult.riskScore || 0;
  const mlScore = mlResult.anomalyScore || 0;
  const behaviorScore = sandboxResult.behaviorScore || 0;
  const threatIntelScore = threatIntelResult.status === 'ONLINE_INTELLIGENCE_RESOLVED' ? 15 : 0;
  const aiScore = (geminiResult && geminiResult.available && typeof geminiResult.risk_score === 'number')
    ? geminiResult.risk_score
    : null;

  // Layer weights
  let weightedTotal = 0;
  let weightsSum = 0;

  // Static analysis (Heuristics, Signatures, Structure, Polyglot)
  weightedTotal += staticScore * 0.45;
  weightsSum += 0.45;

  // ML Feature Anomaly Score (Statistical)
  weightedTotal += mlScore * 0.15;
  weightsSum += 0.15;

  // Sandbox Disassembly Pattern Telemetry
  if (sandboxResult && (sandboxResult.status === 'STATIC_PATTERN_ANALYSIS_COMPLETE' || sandboxResult.status === 'EMULATED_TELEMETRY_COMPLETE')) {
    weightedTotal += behaviorScore * 0.20;
    weightsSum += 0.20;
  }

  // Gemini AI reasoning if present and valid
  if (aiScore !== null) {
    weightedTotal += aiScore * 0.20;
    weightsSum += 0.20;
  }

  const compositeRiskScore = Math.round(weightedTotal / weightsSum);

  // Consolidated Evidence with explicit provenance: Finding, Source, Evidence, Confidence
  const consolidatedEvidence = [];

  if (staticResult.evidence && Array.isArray(staticResult.evidence)) {
    consolidatedEvidence.push(...staticResult.evidence.map(e => ({
      source: 'Deterministic Static Heuristics',
      type: e.type || 'static_rule',
      severity: e.severity || 'medium',
      description: e.description || e,
      confidence: 0.95
    })));
  }

  if (staticResult.polyglotFindings && staticResult.polyglotFindings.length > 0) {
    consolidatedEvidence.push(...staticResult.polyglotFindings.map(p => ({
      source: 'Deep Structural & Offset Carver',
      type: 'polyglot',
      severity: 'critical',
      description: p.description,
      confidence: 0.98
    })));
  }

  if (sandboxResult.findings && sandboxResult.behaviorScore > 30) {
    consolidatedEvidence.push(...sandboxResult.findings.map(f => ({
      source: sandboxResult.adapterUsed || 'Static Disassembly Analyzer',
      type: 'behavioral_pattern',
      severity: 'high',
      description: f,
      confidence: 0.90
    })));
  }

  if (geminiResult && geminiResult.evidence && Array.isArray(geminiResult.evidence)) {
    consolidatedEvidence.push(...geminiResult.evidence.map(e => ({
      source: `Gemini AI (${geminiResult.model || 'gemini-3.6-flash'})`,
      type: e.type || 'ai_threat_indicator',
      severity: e.severity || 'medium',
      description: e.description || JSON.stringify(e),
      confidence: Number(geminiResult.confidence || 0.85)
    })));
  }

  // Hard override: If known malware hash or confirmed PE execution inside image, never classify as safe!
  let verdict = 'SAFE';
  if (staticScore >= 80 || behaviorScore >= 80 || (aiScore !== null && aiScore >= 85)) {
    verdict = 'MALICIOUS';
  } else if (compositeRiskScore >= 60) {
    verdict = 'HIGH_RISK';
  } else if (compositeRiskScore >= 35) {
    verdict = 'SUSPICIOUS';
  } else if (compositeRiskScore >= 15) {
    verdict = 'LOW_RISK';
  } else if (consolidatedEvidence.length === 0 && staticScore === 0) {
    verdict = 'SAFE';
  }

  // Calculate confidence
  let confidence = 0.88;
  if (mode === 'online' && aiScore !== null) confidence = 0.94;
  if (staticScore >= 85) confidence = 0.98;
  if (staticResult.findings && staticResult.findings.length === 0) confidence = 0.95;

  // Recommendation
  let recommendation = 'No critical threats identified. Standard caution advised.';
  if (verdict === 'MALICIOUS') {
    recommendation = 'IMMEDIATE ACTION: Do not open, execute, or transmit credentials. Quarantine or delete immediately.';
  } else if (verdict === 'HIGH_RISK') {
    recommendation = 'HIGH CAUTION: Significant threat indicators detected. Avoid visiting or opening this file.';
  } else if (verdict === 'SUSPICIOUS') {
    recommendation = 'ELEVATED RISK: Anomaly signatures detected. Verify sender origin through an independent channel.';
  } else if (verdict === 'LOW_RISK') {
    recommendation = 'Minor indicators observed (e.g. non-HTTPS or standard keyword). Proceed with vigilance.';
  }

  return {
    verdict,
    riskScore: Math.min(Math.max(compositeRiskScore, 0), 100),
    confidence,
    layerScores: {
      staticScore,
      mlScore,
      behaviorScore,
      threatIntelScore,
      aiAssessment: aiScore
    },
    layers: {
      traditional: { active: true, status: staticScore > 0 ? 'FINDINGS' : 'CLEAN' },
      structural: { active: targetType === 'file' || targetType === 'media', status: 'INSPECTED' },
      ml: { active: true, score: mlScore },
      threatIntel: { active: mode === 'online', status: threatIntelResult.status || 'OFFLINE' },
      sandbox: { active: true, status: sandboxResult.status || 'COMPLETE' },
      gemini: { active: mode === 'online', available: aiScore !== null }
    },
    consolidatedEvidence,
    recommendation
  };
}

module.exports = {
  fuseEvidence
};
