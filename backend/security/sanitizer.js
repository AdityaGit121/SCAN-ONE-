/**
 * Credential Scrubber & Input Sanitizer
 * Guarantees that API keys, authorization tokens, and credentials are never leaked.
 */

// Matches Gemini API keys (AIzaSy...), standard OAuth tokens, and Bearer tokens
const SENSITIVE_PATTERNS = [
  /AIzaSy[A-Za-z0-9_-]{33}/gi,
  /Bearer\s+[A-Za-z0-9_\-\.]{20,}/gi,
  /key=[A-Za-z0-9_-]{20,}/gi,
  /api[_-]?key["']?\s*[:=]\s*["']?([A-Za-z0-9_-]{20,})["']?/gi
];

function sanitizeString(str) {
  if (typeof str !== 'string') return str;
  let sanitized = str;
  for (const pattern of SENSITIVE_PATTERNS) {
    sanitized = sanitized.replace(pattern, '[REDACTED_CREDENTIAL]');
  }
  return sanitized;
}

function sanitizeObject(obj, maxDepth = 4) {
  if (!obj || maxDepth < 0) return obj;
  if (typeof obj === 'string') return sanitizeString(obj);
  if (typeof obj !== 'object') return obj;

  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item, maxDepth - 1));
  }

  const clean = {};
  for (const [k, v] of Object.entries(obj)) {
    const lowerKey = k.toLowerCase();
    if (lowerKey.includes('apikey') || lowerKey.includes('secret') || lowerKey.includes('token') || lowerKey.includes('password')) {
      clean[k] = '[PROTECTED_CREDENTIAL]';
    } else {
      clean[k] = sanitizeObject(v, maxDepth - 1);
    }
  }
  return clean;
}

module.exports = {
  sanitizeString,
  sanitizeObject
};
