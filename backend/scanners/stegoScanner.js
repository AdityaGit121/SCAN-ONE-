/**
 * Steganography & Visual Anomaly Detector
 * Accurately labeled: Statistical Least Significant Bit (LSB) variance, high-frequency byte distribution,
 * and trailing boundary Shannon entropy analysis. Deep CNN steganalysis models are not installed.
 */

function analyzeStegoSignals(buffer, mimeType) {
  if (!buffer || buffer.length < 128) {
    return {
      score: 0,
      stegoRisk: 'LOW',
      findings: ['Sample size too small for statistical stego analysis'],
      lsbRatio: 0,
      localEntropy: 0,
      method: 'STATISTICAL_LSB_AND_SHANNON_ENTROPY_ANALYSIS',
      deepCnnSteganalysis: 'NOT_INSTALLED'
    };
  }

  const findings = [];
  let score = 0;

  // Extract LSB stream from data bytes (avoiding initial file magic header)
  const sampleStart = Math.min(64, buffer.length);
  const sampleEnd = Math.min(sampleStart + 2048, buffer.length);
  const sampleLength = sampleEnd - sampleStart;

  let lsbOnes = 0;
  for (let i = sampleStart; i < sampleEnd; i++) {
    if ((buffer[i] & 0x01) === 1) {
      lsbOnes++;
    }
  }

  // Purely natural images usually have an LSB distribution differing slightly from perfect 0.5000
  // Perfectly uniform LSBs (0.500) across random chunks often indicate pseudo-random encrypted payload injection
  const lsbRatio = sampleLength > 0 ? lsbOnes / sampleLength : 0.5;
  const lsbDeviation = Math.abs(lsbRatio - 0.5);

  // High byte entropy inside image data
  let freq = new Uint32Array(256);
  for (let i = sampleStart; i < sampleEnd; i++) {
    freq[buffer[i]]++;
  }
  let localEntropy = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      const p = freq[i] / sampleLength;
      localEntropy -= p * Math.log2(p);
    }
  }

  // Check for suspicious LSB packing patterns
  if (localEntropy > 7.85 && lsbDeviation < 0.015) {
    score += 45;
    findings.push('LSB statistical distribution exhibits extreme high uniformity consistent with encrypted steganographic carrier payload.');
  }

  // Check if tail section has abnormal entropy jump compared to head
  if (buffer.length > 50000) {
    const tailStart = buffer.length - 1024;
    let tailFreq = new Uint32Array(256);
    for (let i = tailStart; i < buffer.length; i++) {
      tailFreq[buffer[i]]++;
    }
    let tailEntropy = 0;
    for (let i = 0; i < 256; i++) {
      if (tailFreq[i] > 0) {
        const p = tailFreq[i] / 1024;
        tailEntropy -= p * Math.log2(p);
      }
    }

    if (tailEntropy > 7.75) {
      score += 35;
      findings.push(`Tail entropy jump (${tailEntropy.toFixed(2)}/8.00) indicates packed/encrypted append anomaly.`);
    }
  }

  let stegoRisk = 'SAFE';
  if (score >= 60) stegoRisk = 'HIGH';
  else if (score >= 30) stegoRisk = 'SUSPICIOUS';

  return {
    score,
    stegoRisk,
    lsbRatio: Number(lsbRatio.toFixed(4)),
    localEntropy: Number(localEntropy.toFixed(3)),
    findings: findings.length > 0 ? findings : ['No anomalous LSB or high-frequency pixel deviations observed'],
    method: 'STATISTICAL_LSB_AND_SHANNON_ENTROPY_ANALYSIS',
    deepCnnSteganalysis: 'NOT_INSTALLED'
  };
}

module.exports = {
  analyzeStegoSignals
};
