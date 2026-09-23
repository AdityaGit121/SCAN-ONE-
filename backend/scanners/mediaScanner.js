const crypto = require('crypto');
const { searchKnowledge } = require('./localRag');

// Known malicious SHA256 / MD5 signatures
const KNOWN_MALWARE_HASHES = new Set([
  // EICAR standard test antivirus string hash
  '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
  // Historical sample hash from prototype
  '44d88612fea8a8f36de82e1278abb02f'
]);

/**
 * Calculate Shannon Entropy of a buffer
 */
function calculateBufferEntropy(buffer) {
  if (!buffer || buffer.length === 0) return 0;
  const frequencies = new Uint32Array(256);
  for (let i = 0; i < buffer.length; i++) {
    frequencies[buffer[i]]++;
  }
  let entropy = 0;
  const len = buffer.length;
  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const p = frequencies[i] / len;
      entropy -= p * Math.log2(p);
    }
  }
  return Number(entropy.toFixed(3));
}

/**
 * Detect Magic Bytes & container format from buffer
 */
function detectMagicBytes(buffer) {
  if (!buffer || buffer.length === 0) {
    return { detectedType: 'EMPTY_BUFFER', matchedMime: 'application/octet-stream', expectedExt: '' };
  }

  // JPEG
  if (buffer.length >= 3 && buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
    return { detectedType: 'JPEG Image', matchedMime: 'image/jpeg', expectedExt: '.jpg', isExecutable: false };
  }
  // PNG
  if (buffer.length >= 8 && buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
    return { detectedType: 'PNG Image', matchedMime: 'image/png', expectedExt: '.png', isExecutable: false };
  }
  // GIF
  if (buffer.length >= 4 && buffer[0] === 0x47 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x38) {
    return { detectedType: 'GIF Image', matchedMime: 'image/gif', expectedExt: '.gif', isExecutable: false };
  }
  // WEBP (RIFF....WEBP)
  if (buffer.length >= 12 && buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WEBP') {
    return { detectedType: 'WEBP Image', matchedMime: 'image/webp', expectedExt: '.webp', isExecutable: false };
  }
  // WAV Audio (RIFF....WAVE)
  if (buffer.length >= 12 && buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WAVE') {
    return { detectedType: 'WAV Audio', matchedMime: 'audio/wav', expectedExt: '.wav', isExecutable: false };
  }
  // MP3 with ID3
  if (buffer.length >= 3 && buffer[0] === 0x49 && buffer[1] === 0x44 && buffer[2] === 0x33) {
    return { detectedType: 'MP3 Audio', matchedMime: 'audio/mpeg', expectedExt: '.mp3', isExecutable: false };
  }
  // PDF
  if (buffer.length >= 4 && buffer.toString('ascii', 0, 4) === '%PDF') {
    return { detectedType: 'PDF Document', matchedMime: 'application/pdf', expectedExt: '.pdf', isExecutable: false };
  }
  // MP4
  if (buffer.length >= 8 && buffer.toString('ascii', 4, 8) === 'ftyp') {
    return { detectedType: 'MP4 Video', matchedMime: 'video/mp4', expectedExt: '.mp4', isExecutable: false };
  }
  // ZIP Archive / Office Open XML
  if (buffer.length >= 4 && buffer[0] === 0x50 && buffer[1] === 0x4B && buffer[2] === 0x03 && buffer[3] === 0x04) {
    return { detectedType: 'ZIP Archive', matchedMime: 'application/zip', expectedExt: '.zip', isExecutable: false };
  }
  // Windows PE (MZ)
  if (buffer.length >= 2 && buffer[0] === 0x4D && buffer[1] === 0x5A) {
    return { detectedType: 'Windows PE Executable (MZ)', matchedMime: 'application/x-msdownload', expectedExt: '.exe', isExecutable: true };
  }
  // Linux ELF
  if (buffer.length >= 4 && buffer[0] === 0x7F && buffer[1] === 0x45 && buffer[2] === 0x4C && buffer[3] === 0x46) {
    return { detectedType: 'Linux ELF Binary', matchedMime: 'application/x-elf', expectedExt: '.elf', isExecutable: true };
  }
  // Mach-O Universal / 64-bit
  if (buffer.length >= 4 && (
    (buffer[0] === 0xFE && buffer[1] === 0xED && buffer[2] === 0xFA && (buffer[3] === 0xCE || buffer[3] === 0xCF)) ||
    (buffer[0] === 0xCF && buffer[1] === 0xFA && buffer[2] === 0xED && buffer[3] === 0xFE)
  )) {
    return { detectedType: 'macOS Mach-O Binary', matchedMime: 'application/x-mach-binary', expectedExt: '.bin', isExecutable: true };
  }

  // Inspect text / markup / script headers
  const headSample = buffer.slice(0, Math.min(buffer.length, 512)).toString('utf-8').trim();

  // SVG text
  if (headSample.toLowerCase().includes('<svg') || (headSample.toLowerCase().includes('<?xml') && headSample.toLowerCase().includes('<svg'))) {
    return { detectedType: 'SVG Vector Image', matchedMime: 'image/svg+xml', expectedExt: '.svg', isExecutable: false };
  }

  // XML Document
  if (headSample.startsWith('<?xml')) {
    return { detectedType: 'XML Document', matchedMime: 'application/xml', expectedExt: '.xml', isExecutable: false };
  }

  // JSON Document
  if ((headSample.startsWith('{') && headSample.endsWith('}')) || headSample.startsWith('[') || (headSample.startsWith('{') && headSample.length > 2)) {
    try {
      JSON.parse(buffer.toString('utf-8'));
      return { detectedType: 'JSON Document', matchedMime: 'application/json', expectedExt: '.json', isExecutable: false };
    } catch (_) {
      // Partial JSON header
      if (headSample.startsWith('{') || headSample.startsWith('[')) {
        return { detectedType: 'JSON Document', matchedMime: 'application/json', expectedExt: '.json', isExecutable: false };
      }
    }
  }

  // Plain Text / Script check
  let printableCount = 0;
  const sampleLen = Math.min(buffer.length, 1024);
  for (let i = 0; i < sampleLen; i++) {
    const c = buffer[i];
    if ((c >= 32 && c <= 126) || c === 9 || c === 10 || c === 13) {
      printableCount++;
    }
  }
  if (sampleLen > 0 && (printableCount / sampleLen) > 0.92) {
    return { detectedType: 'Plain Text Document', matchedMime: 'text/plain', expectedExt: '.txt', isExecutable: false };
  }

  return { detectedType: 'Generic Binary Data', matchedMime: 'application/octet-stream', expectedExt: '.bin', isExecutable: false };
}

/**
 * Scan for Polyglot signatures embedded in media at non-zero offsets
 */
function scanPolyglotOffsets(buffer) {
  const polyglotFindings = [];
  const offsetTimeline = [];

  if (!buffer || buffer.length < 64) {
    return { polyglotFindings, offsetTimeline };
  }

  // 1. Scan for secondary PE MZ header after offset 64
  let mzIdx = buffer.indexOf(Buffer.from([0x4D, 0x5A]), 64);
  while (mzIdx !== -1 && mzIdx < buffer.length - 64) {
    const peOffsetPtr = buffer.readUInt32LE ? buffer.readUInt32LE(Math.min(mzIdx + 0x3C, buffer.length - 4)) : 0;
    if (peOffsetPtr > 0 && peOffsetPtr < 1024 && (mzIdx + peOffsetPtr + 4) <= buffer.length) {
      const peSig = buffer.toString('ascii', mzIdx + peOffsetPtr, mzIdx + peOffsetPtr + 4);
      if (peSig === 'PE\0\0') {
        polyglotFindings.push({
          type: 'embedded_pe',
          offset: `0x${mzIdx.toString(16).toUpperCase()}`,
          severity: 'CRITICAL',
          description: `Embedded Windows PE Executable found at offset 0x${mzIdx.toString(16).toUpperCase()}`
        });
        offsetTimeline.push({ offset: `0x${mzIdx.toString(16).toUpperCase()}`, label: 'Embedded PE Executable Signature' });
        break;
      }
    }
    mzIdx = buffer.indexOf(Buffer.from([0x4D, 0x5A]), mzIdx + 2);
  }

  // 2. Scan for secondary ZIP / PK archive after offset 64
  let zipIdx = buffer.indexOf(Buffer.from([0x50, 0x4B, 0x03, 0x04]), 64);
  if (zipIdx !== -1) {
    polyglotFindings.push({
      type: 'embedded_zip',
      offset: `0x${zipIdx.toString(16).toUpperCase()}`,
      severity: 'HIGH',
      description: `Embedded ZIP/Archive structure carved at offset 0x${zipIdx.toString(16).toUpperCase()}`
    });
    offsetTimeline.push({ offset: `0x${zipIdx.toString(16).toUpperCase()}`, label: 'Embedded PK/ZIP Archive Marker' });
  }

  // 3. Scan for Linux ELF header after offset 64
  let elfIdx = buffer.indexOf(Buffer.from([0x7F, 0x45, 0x4C, 0x46]), 64);
  if (elfIdx !== -1) {
    polyglotFindings.push({
      type: 'embedded_elf',
      offset: `0x${elfIdx.toString(16).toUpperCase()}`,
      severity: 'CRITICAL',
      description: `Embedded Linux ELF Binary header discovered at offset 0x${elfIdx.toString(16).toUpperCase()}`
    });
    offsetTimeline.push({ offset: `0x${elfIdx.toString(16).toUpperCase()}`, label: 'Embedded ELF Binary' });
  }

  return { polyglotFindings, offsetTimeline };
}

/**
 * Deep structural analysis of media containers (JPEG, PNG, MP4, SVG)
 */
function analyzeMediaStructure(buffer, originalFileName) {
  const structureTree = [];
  const findings = [];
  let structuralScore = 0;
  const fileName = originalFileName || 'unknown_file';
  const ext = fileName.includes('.') ? '.' + fileName.split('.').pop().toLowerCase() : '';

  const { detectedType, matchedMime, expectedExt, isExecutable } = detectMagicBytes(buffer);

  structureTree.push({
    title: 'Container Header',
    status: 'parsed',
    details: `Magic bytes correspond to: ${detectedType} (${matchedMime})`
  });

  // Check for extension vs magic bytes mismatch
  // Only penalize severely if the file is an executable masquerading as a non-executable (e.g. .jpg but is .exe)
  if (isExecutable && ext && !['.exe', '.dll', '.bin', '.elf', '.so'].includes(ext)) {
    structuralScore += 90;
    findings.push(`CRITICAL: File renamed as '${ext}', but actual container format is an executable binary (${detectedType})!`);
  } else if (expectedExt && ext && ext !== expectedExt) {
    // Normal benign format variations (e.g. .jpeg vs .jpg, or text/json/markdown)
    const benignEquivalents = {
      '.jpg': ['.jpeg', '.jfif'],
      '.jpeg': ['.jpg'],
      '.txt': ['.json', '.csv', '.md', '.log', '.js', '.ts', '.css', '.html'],
      '.bin': ['.dat', '.raw']
    };
    const isBenignVar = (benignEquivalents[expectedExt] && benignEquivalents[expectedExt].includes(ext)) ||
      (benignEquivalents[ext] && benignEquivalents[ext].includes(expectedExt));

    if (!isBenignVar && expectedExt !== '.bin') {
      structuralScore += 25;
      findings.push(`Extension mismatch: Filename claims '${ext}', but container signature indicates '${expectedExt}'.`);
    }
  }

  // PNG Structural Chunk Parser
  if (buffer.length >= 8 && buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
    let offset = 8;
    let foundIEND = false;
    const chunks = [];

    while (offset + 8 <= buffer.length) {
      const length = buffer.readUInt32BE(offset);
      const chunkType = buffer.toString('ascii', offset + 4, offset + 8);
      chunks.push({ type: chunkType, length, offset: `0x${offset.toString(16)}` });

      if (chunkType === 'IEND') {
        foundIEND = true;
        const eofExpected = offset + 12;
        if (eofExpected < buffer.length) {
          const trailingBytes = buffer.length - eofExpected;
          structuralScore += 45;
          findings.push(`Anomalous trailing data detected after PNG IEND chunk: ${trailingBytes} unexpected bytes.`);
          structureTree.push({
            title: 'Trailing Payload',
            status: 'anomaly',
            details: `${trailingBytes} bytes appended beyond PNG standard terminator.`
          });
        }
        break;
      }
      offset += 12 + length; // 4 len + 4 type + data + 4 crc
    }

    structureTree.push({
      title: 'PNG Chunks',
      status: 'valid',
      details: chunks.map(c => `${c.type} (${c.length}b)`).join(' → ')
    });
  }

  // JPEG Structural Marker Parser
  if (buffer.length >= 2 && buffer[0] === 0xFF && buffer[1] === 0xD8) {
    let offset = 2;
    let foundEOI = false;

    while (offset < buffer.length - 1) {
      if (buffer[offset] === 0xFF) {
        const marker = buffer[offset + 1];
        if (marker === 0xD9) { // EOI (End of Image)
          foundEOI = true;
          const trailing = buffer.length - (offset + 2);
          if (trailing > 32) {
            structuralScore += 40;
            findings.push(`Suspicious trailing overlay after JPEG EOI marker: ${trailing} bytes.`);
            structureTree.push({
              title: 'JPEG Trailing Overlay',
              status: 'anomaly',
              details: `${trailing} bytes appended past JPEG End-Of-Image marker 0xFFD9.`
            });
          }
          break;
        }
      }
      offset++;
    }

    structureTree.push({
      title: 'JPEG Stream Marker Inspection',
      status: foundEOI ? 'terminated' : 'unterminated',
      details: foundEOI ? 'Valid Start-of-Image (SOI) and End-of-Image (EOI) detected' : 'Warning: Missing standard EOI marker'
    });
  }

  // SVG Script / XSS inspection
  if (detectedType.includes('SVG') || ext === '.svg') {
    const content = buffer.toString('utf-8').toLowerCase();
    if (content.includes('<script') || content.includes('onload=') || content.includes('onerror=') || content.includes('javascript:')) {
      structuralScore += 75;
      findings.push('Active JavaScript executable payload detected embedded inside SVG markup.');
      structureTree.push({
        title: 'Embedded Script Engine',
        status: 'critical',
        details: 'Malicious DOM script injection tags detected in SVG vector.'
      });
    }
  }

  // Text/Script Heuristics on entire Latin1 buffer (only check for weaponized script strings if not benign source files)
  const isCodeSourceFile = ['.js', '.ts', '.py', '.sh', '.json', '.html'].includes(ext);
  if (!isCodeSourceFile) {
    const latinContent = buffer.toString('latin1').toLowerCase();
    const suspiciousTokens = [
      { token: 'powershell', label: 'PowerShell script invocation', weight: 35 },
      { token: 'cmd.exe', label: 'Command prompt execution hook', weight: 30 },
      { token: 'wscript.shell', label: 'Windows Script Host activation', weight: 35 },
      { token: 'reg add', label: 'Windows Registry persistence modification', weight: 35 }
    ];

    for (const item of suspiciousTokens) {
      if (latinContent.includes(item.token)) {
        structuralScore += item.weight;
        findings.push(`Embedded suspicious script token in media container: ${item.label}`);
      }
    }
  }

  // Polyglot scan
  const { polyglotFindings, offsetTimeline } = scanPolyglotOffsets(buffer);
  if (polyglotFindings.length > 0) {
    structuralScore += 50;
    findings.push(...polyglotFindings.map(f => f.description));
  }

  return {
    detectedType,
    matchedMime,
    expectedExt,
    structuralScore: Math.min(structuralScore, 100),
    structureTree,
    polyglotFindings,
    offsetTimeline,
    structuralFindings: findings
  };
}

/**
 * Complete media scanner combining hash check, structure, entropy, and knowledge retrieval.
 */
function analyzeMediaFileOffline(buffer, originalFileName) {
  if (!buffer || buffer.length === 0) {
    return {
      success: false,
      fileName: originalFileName || 'empty',
      fileSize: 0,
      verdict: 'UNKNOWN',
      riskScore: 0,
      confidence: 0,
      detectedType: 'EMPTY_FILE',
      findings: ['File contains zero bytes. Insufficient evidence for analysis.'],
      offlineNotice: 'Zero-byte input.'
    };
  }

  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  const md5 = crypto.createHash('md5').update(buffer).digest('hex');
  const entropy = calculateBufferEntropy(buffer);

  let hashScore = 0;
  const hashFindings = [];

  // Check known hashes
  if (KNOWN_MALWARE_HASHES.has(sha256) || KNOWN_MALWARE_HASHES.has(md5)) {
    hashScore = 100;
    hashFindings.push('MATCH: Sample hash corresponds to confirmed malware in offline signature database.');
  }

  // Structural and polyglot scan
  const structure = analyzeMediaStructure(buffer, originalFileName);

  const combinedScore = Math.min(Math.max(hashScore, structure.structuralScore), 100);
  let verdict = 'SAFE';
  if (combinedScore >= 75) verdict = 'MALICIOUS';
  else if (combinedScore >= 45) verdict = 'HIGH_RISK';
  else if (combinedScore >= 25) verdict = 'SUSPICIOUS';
  else if (combinedScore >= 10) verdict = 'LOW_RISK';

  const allFindings = [...hashFindings, ...structure.structuralFindings];
  // Flag high entropy only on uncompressed media/data where it indicates encryption/packing
  if (entropy > 7.7 && !['ZIP Archive', 'MP4 Video', 'WEBP Image'].includes(structure.detectedType)) {
    allFindings.push(`High Shannon entropy (${entropy} / 8.0) suggests packed or encrypted payload segments.`);
  }

  // Offline knowledge retrieval
  const ragQuery = [structure.detectedType, originalFileName, ...allFindings.slice(0, 3)];
  const ragMatches = searchKnowledge(ragQuery);

  return {
    success: true,
    fileName: originalFileName,
    fileSize: buffer.length,
    sha256,
    md5,
    entropy,
    verdict,
    riskScore: combinedScore,
    confidence: allFindings.length > 0 ? 0.92 : 0.96,
    detectedType: structure.detectedType,
    matchedMime: structure.matchedMime,
    findings: allFindings.length > 0 ? allFindings : ['No malicious signatures or polyglot structures detected'],
    structureTree: structure.structureTree,
    offsetTimeline: structure.offsetTimeline,
    polyglotFindings: structure.polyglotFindings,
    ragMatches,
    offlineNotice: 'Scan performed completely offline using local signature database and deterministic structural parsing.'
  };
}

module.exports = {
  analyzeMediaFileOffline,
  analyzeMediaStructure,
  detectMagicBytes,
  calculateBufferEntropy,
  KNOWN_MALWARE_HASHES
};
