const { GoogleGenAI, Type } = require('@google/genai');

/**
 * Gemini AI Security Reasoning Engine
 * Uses modern @google/genai SDK with structured output schemas and resilient model fallback.
 * Target Model: gemini-3.6-flash (fallback: gemini-2.5-flash, gemini-3.8-flash)
 */

const DEFAULT_MODEL = 'gemini-3.6-flash';
const FALLBACK_MODELS = ['gemini-3.6-flash', 'gemini-2.5-flash', 'gemini-3.8-flash'];

function getGenAIClient(customApiKey) {
  const key = customApiKey || process.env.GEMINI_API_KEY;
  if (!key) return null;

  return new GoogleGenAI({
    apiKey: key,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build'
      }
    }
  });
}

/**
 * Schema for structured security analysis
 */
const SECURITY_ANALYSIS_SCHEMA = {
  type: Type.OBJECT,
  properties: {
    classification: {
      type: Type.STRING,
      description: 'Classification: "phishing", "malicious_file", "suspicious", or "benign"'
    },
    risk_score: {
      type: Type.INTEGER,
      description: 'Risk score from 0 to 100'
    },
    confidence: {
      type: Type.NUMBER,
      description: 'Confidence score from 0.0 to 1.0'
    },
    attack_category: {
      type: Type.STRING,
      description: 'Attack category, e.g. "credential_harvesting", "polyglot_carrier", "social_engineering", "none"'
    },
    explanation: {
      type: Type.STRING,
      description: 'Clear, concise technical justification under 2 sentences.'
    },
    evidence: {
      type: Type.ARRAY,
      items: {
        type: Type.OBJECT,
        properties: {
          type: { type: Type.STRING },
          severity: { type: Type.STRING },
          description: { type: Type.STRING }
        },
        required: ['type', 'severity', 'description']
      }
    },
    recommended_action: {
      type: Type.STRING,
      description: 'Safety recommendation for security analysts or end users.'
    }
  },
  required: ['classification', 'risk_score', 'confidence', 'explanation', 'evidence', 'recommended_action']
};

/**
 * Helper to execute generateContent with automatic retry and model fallback cascade on 503/429
 */
async function executeWithModelFallback(ai, prompt, requestedModel = DEFAULT_MODEL) {
  const modelsToTry = [
    requestedModel,
    ...FALLBACK_MODELS
  ].filter((m, idx, arr) => m && arr.indexOf(m) === idx);

  let lastError = null;

  for (const candidateModel of modelsToTry) {
    try {
      const response = await ai.models.generateContent({
        model: candidateModel,
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
          responseSchema: SECURITY_ANALYSIS_SCHEMA
        }
      });

      const text = response.text ? response.text.trim() : '{}';
      const parsedJson = JSON.parse(text);

      return {
        success: true,
        modelUsed: candidateModel,
        data: parsedJson
      };
    } catch (err) {
      lastError = err;
      const rawMsg = err.message || '';
      const isTemporary = rawMsg.includes('503') || rawMsg.includes('high demand') || rawMsg.includes('UNAVAILABLE') || rawMsg.includes('429');

      if (isTemporary) {
        console.warn(`[Gemini AI Fallback] Model '${candidateModel}' encountered high demand (503/429). Cascading to next candidate...`);
        // Brief jitter delay before fallback
        await new Promise(r => setTimeout(r, 400));
        continue;
      }

      // Non-transient errors (e.g. invalid API key) break early
      break;
    }
  }

  // Clean error message extraction
  let cleanErrorMessage = 'Gemini model service experiencing temporary high demand.';
  if (lastError && lastError.message) {
    try {
      const parsed = JSON.parse(lastError.message);
      if (parsed.error && parsed.error.message) {
        cleanErrorMessage = parsed.error.message;
      } else {
        cleanErrorMessage = lastError.message;
      }
    } catch (_) {
      cleanErrorMessage = lastError.message;
    }
  }

  return {
    success: false,
    error: cleanErrorMessage
  };
}

/**
 * Test Connection endpoint for Gemini API
 */
async function testGeminiConnection(apiKey, modelName = DEFAULT_MODEL) {
  try {
    const ai = getGenAIClient(apiKey);
    if (!ai) {
      return {
        connected: false,
        error: 'No API key provided or configured in environment.'
      };
    }

    const candidateModels = [modelName, ...FALLBACK_MODELS].filter((m, idx, arr) => m && arr.indexOf(m) === idx);
    let lastError = null;

    for (const m of candidateModels) {
      try {
        const response = await ai.models.generateContent({
          model: m,
          contents: 'Ping: respond with "PONG".',
          config: {
            maxOutputTokens: 20
          }
        });

        const text = response.text || '';
        return {
          connected: true,
          model: m,
          message: 'Connection verified successfully.',
          sampleResponse: text.trim()
        };
      } catch (e) {
        lastError = e;
        const msg = e.message || '';
        if (msg.includes('503') || msg.includes('high demand') || msg.includes('UNAVAILABLE')) {
          continue;
        }
        break;
      }
    }

    let cleanMsg = lastError?.message || 'Failed to authenticate with Gemini API';
    try {
      const parsed = JSON.parse(cleanMsg);
      if (parsed.error?.message) cleanMsg = parsed.error.message;
    } catch (_) {}

    return {
      connected: false,
      model: modelName,
      error: cleanMsg
    };
  } catch (err) {
    return {
      connected: false,
      model: modelName,
      error: err.message || 'Failed to authenticate with Gemini API'
    };
  }
}

/**
 * Perform AI reasoning on URL phishing and social engineering telemetry
 */
async function analyzeUrlWithGemini({ url, heuristics, customApiKey, model = DEFAULT_MODEL }) {
  const ai = getGenAIClient(customApiKey);
  if (!ai) {
    return {
      available: false,
      reason: 'Gemini API key not configured',
      fallbackNotice: 'AI reasoning skipped. Traditional heuristics and local rules active.'
    };
  }

  const prompt = `You are a Principal Security Threat Analyst. Analyze this URL and its static heuristic evidence:
URL: ${url}
Static Findings: ${JSON.stringify(heuristics.findings || [])}
Domain Entropy: ${heuristics.parsed?.entropy || 'N/A'}
Hostname: ${heuristics.parsed?.host || 'N/A'}
Protocol: ${heuristics.parsed?.protocol || 'N/A'}

Evaluate if this URL demonstrates phishing, typosquatting, credential harvesting, or social engineering tactics.
Provide structured JSON adhering to the defined schema. Keep the explanation under 2 sentences.`;

  const result = await executeWithModelFallback(ai, prompt, model);

  if (result.success) {
    return {
      available: true,
      model: result.modelUsed,
      ...result.data
    };
  }

  console.warn('[Gemini URL Analysis Notice]:', result.error);
  return {
    available: false,
    error: result.error,
    fallbackNotice: 'AI reasoning temporarily unavailable due to upstream demand; reliance placed on deterministic static detection layers.'
  };
}

/**
 * Perform AI reasoning on media structural and polyglot findings
 */
async function analyzeMediaWithGemini({ fileName, fileSize, sha256, staticFindings, structureTree, polyglotFindings, customApiKey, model = DEFAULT_MODEL }) {
  const ai = getGenAIClient(customApiKey);
  if (!ai) {
    return {
      available: false,
      reason: 'Gemini API key not configured',
      fallbackNotice: 'AI reasoning skipped. Local structural, magic-bytes, and hash inspection active.'
    };
  }

  const prompt = `You are a Senior Malware Reverse Engineer. Analyze this media file telemetry:
File Name: ${fileName}
Size: ${fileSize} bytes
SHA-256: ${sha256}
Static Findings: ${JSON.stringify(staticFindings || [])}
Polyglot Signatures: ${JSON.stringify(polyglotFindings || [])}
Structure: ${JSON.stringify(structureTree || [])}

Evaluate whether this file exhibits steganography, polyglot embedding (e.g. PE MZ executable or ZIP in media), or code injection.
Return structured JSON adhering to the response schema. Keep explanation under 2 sentences.`;

  const result = await executeWithModelFallback(ai, prompt, model);

  if (result.success) {
    return {
      available: true,
      model: result.modelUsed,
      ...result.data
    };
  }

  console.warn('[Gemini Media Analysis Notice]:', result.error);
  return {
    available: false,
    error: result.error,
    fallbackNotice: 'AI reasoning temporarily unavailable due to upstream demand; deterministic static and polyglot detections retained.'
  };
}

module.exports = {
  DEFAULT_MODEL,
  getGenAIClient,
  testGeminiConnection,
  analyzeUrlWithGemini,
  analyzeMediaWithGemini
};
