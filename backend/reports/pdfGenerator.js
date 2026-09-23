const PDFDocument = require('pdfkit');

/**
 * Generate a formatted, professional cybersecurity PDF audit report
 * @param {Object} scanResult - Full scan result object
 * @returns {Promise<Buffer>} - Buffer of generated PDF
 */
function generatePdfReport(scanResult) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        margin: 40,
        size: 'A4',
        info: {
          Title: `Threat Analysis Report - ${scanResult.target || 'Target'}`,
          Author: 'Safety Downloader AI Platform',
          Subject: 'Cybersecurity Threat Audit and Structural Analysis',
          Keywords: 'phishing, malware, cybersecurity, gemini, steganography, polyglot'
        }
      });

      const buffers = [];
      doc.on('data', buffers.push.bind(buffers));
      doc.on('end', () => resolve(Buffer.concat(buffers)));

      // Colors
      const primaryColor = scanResult.mode === 'offline' ? '#00b06f' : '#0084b4';
      const darkBg = '#0e1a24';
      const textDark = '#1a242f';
      const textDim = '#5a6d7d';
      
      let verdictColor = '#00b06f';
      if (scanResult.verdict === 'MALICIOUS' || scanResult.verdict === 'HIGH_RISK') {
        verdictColor = '#d92546';
      } else if (scanResult.verdict === 'SUSPICIOUS') {
        verdictColor = '#d98200';
      }

      // ── Header Banner ──
      doc.rect(40, 40, 515, 60).fill(darkBg);
      doc.fillColor('#ffffff').fontSize(18).font('Helvetica-Bold')
         .text('SAFETY DOWNLOADER — THREAT AUDIT REPORT', 55, 52);
      doc.fillColor(primaryColor).fontSize(9).font('Helvetica')
         .text(`ENVIRONMENT: ${scanResult.mode === 'offline' ? 'OFFLINE AIR-GAPPED LOCAL MODE' : 'ONLINE AI-ASSISTED MODE'} · ENGINE v2.4`, 55, 75);

      doc.moveDown(2);

      // ── Target Metadata Table ──
      let y = 115;
      doc.rect(40, y, 515, 65).fill('#f4f7f9').stroke('#dce4e8');
      doc.fillColor(textDark).fontSize(9).font('Helvetica-Bold');
      doc.text('Target Sample:', 50, y + 10);
      doc.font('Helvetica').text(String(scanResult.target || 'N/A'), 130, y + 10, { width: 410, ellipsis: true });

      doc.font('Helvetica-Bold').text('Target Type:', 50, y + 25);
      doc.font('Helvetica').text(String(scanResult.targetType || 'N/A').toUpperCase(), 130, y + 25);

      doc.font('Helvetica-Bold').text('Scan ID:', 260, y + 25);
      doc.font('Helvetica').text(String(scanResult.scanId || 'N/A'), 315, y + 25, { width: 230, ellipsis: true });

      doc.font('Helvetica-Bold').text('Generated:', 50, y + 40);
      doc.font('Helvetica').text(String(scanResult.timestamp || new Date().toISOString()), 130, y + 40);

      doc.font('Helvetica-Bold').text('SHA-256:', 260, y + 40);
      doc.font('Helvetica').text(String(scanResult.sha256 || scanResult.parsed?.host || 'N/A'), 315, y + 40, { width: 230, ellipsis: true });

      // ── Verdict & Risk Score Section ──
      y = 195;
      doc.rect(40, y, 515, 50).fill(verdictColor);
      doc.fillColor('#ffffff').fontSize(14).font('Helvetica-Bold');
      doc.text(`VERDICT: ${String(scanResult.verdict || 'UNKNOWN').replace('_', ' ')}`, 55, y + 12);
      doc.fontSize(10).font('Helvetica')
         .text(`Risk Composite Score: ${scanResult.riskScore || 0}/100  ·  Confidence: ${Math.round((scanResult.confidence || 0.9) * 100)}%`, 55, y + 30);

      // Recommendation box
      y = 255;
      doc.rect(40, y, 515, 36).fill('#fff8f0').stroke('#ffe0b2');
      doc.fillColor('#944d00').fontSize(9).font('Helvetica-Bold')
         .text('ACTION RECOMMENDATION:', 50, y + 8);
      doc.fillColor(textDark).fontSize(8.5).font('Helvetica')
         .text(String(scanResult.recommendation || 'No immediate action required.'), 50, y + 20, { width: 495 });

      // ── Telemetry Layers Breakdown ──
      y = 305;
      doc.fillColor(textDark).fontSize(11).font('Helvetica-Bold').text('Multi-Layer Telemetry Assessment', 40, y);
      y += 18;
      
      const layers = [
        { label: 'Static Signature & Heuristic Risk', score: scanResult.layerScores?.staticScore ?? 'N/A' },
        { label: 'ML Vector Anomaly Index', score: scanResult.layerScores?.mlScore ?? 'N/A' },
        { label: 'Behavioral Sandbox Telemetry Risk', score: scanResult.layerScores?.behaviorScore ?? 'N/A' },
        { label: 'Gemini AI Security Reasoning', score: scanResult.layerScores?.aiAssessment ?? (scanResult.mode === 'offline' ? 'Offline (Disabled)' : 'Completed') }
      ];

      layers.forEach(item => {
        doc.rect(40, y, 515, 20).fill('#fafbfc').stroke('#e1e6ea');
        doc.fillColor(textDark).fontSize(8.5).font('Helvetica').text(item.label, 50, y + 5);
        doc.font('Helvetica-Bold').text(String(item.score), 460, y + 5, { width: 85, align: 'right' });
        y += 24;
      });

      // ── Key Findings & Evidence Timeline ──
      y += 6;
      doc.fillColor(textDark).fontSize(11).font('Helvetica-Bold').text('Consolidated Findings & Evidence Timeline', 40, y);
      y += 18;

      const findings = scanResult.findings || [];
      if (findings.length === 0) {
        doc.rect(40, y, 515, 22).fill('#f9fbfa').stroke('#dce4e8');
        doc.fillColor(textDim).fontSize(8.5).font('Helvetica')
           .text('No suspicious anomalies or threat signatures triggered during static inspection.', 50, y + 6);
        y += 28;
      } else {
        findings.slice(0, 5).forEach(f => {
          doc.rect(40, y, 515, 22).fill('#fffafb').stroke('#fedfe3');
          doc.fillColor('#b51834').fontSize(8.5).font('Helvetica-Bold').text('CRITICAL / WARNING: ', 50, y + 6);
          doc.fillColor(textDark).font('Helvetica').text(String(f), 160, y + 6, { width: 380, ellipsis: true });
          y += 26;
        });
      }

      // ── Structural & Polyglot Analysis ──
      if (scanResult.structureTree && scanResult.structureTree.length > 0) {
        y += 4;
        doc.fillColor(textDark).fontSize(11).font('Helvetica-Bold').text('Container Structural Inspection', 40, y);
        y += 18;
        scanResult.structureTree.slice(0, 3).forEach(node => {
          doc.rect(40, y, 515, 22).fill('#f4f7f9').stroke('#dce4e8');
          doc.fillColor(textDark).fontSize(8.5).font('Helvetica-Bold').text(`${node.title}: `, 50, y + 6);
          doc.font('Helvetica').text(String(node.details), 180, y + 6, { width: 360, ellipsis: true });
          y += 26;
        });
      }

      // ── AI Reasoning Findings ──
      if (scanResult.aiAnalysis && scanResult.aiAnalysis.available) {
        y += 4;
        doc.fillColor(textDark).fontSize(11).font('Helvetica-Bold').text(`Gemini AI Analysis Findings (${scanResult.aiAnalysis.model || 'gemini-3.8-flash'})`, 40, y);
        y += 18;
        doc.rect(40, y, 515, 42).fill('#fbf5ff').stroke('#ecd3ff');
        doc.fillColor('#6a1bb0').fontSize(8.5).font('Helvetica-Bold')
           .text(`CLASSIFICATION: ${scanResult.aiAnalysis.classification || 'Analyzed'} · CATEGORY: ${scanResult.aiAnalysis.attack_category || 'N/A'}`, 50, y + 6);
        doc.fillColor(textDark).font('Helvetica')
           .text(String(scanResult.aiAnalysis.explanation || 'Detailed AI evaluation completed.'), 50, y + 20, { width: 495 });
        y += 48;
      }

      // ── Footer ──
      doc.fontSize(7.5).fillColor(textDim)
         .text('This document was automatically generated by Safety Downloader. Heuristic and AI telemetry should be validated before executing high-risk binaries.', 40, 780, { align: 'center', width: 515 });

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

module.exports = {
  generatePdfReport
};
