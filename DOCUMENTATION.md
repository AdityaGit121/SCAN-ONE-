# SCAN ONE — Dual-Mode AI & Air-Gapped Threat Analysis Platform
## Comprehensive Engineering Documentation, System Architecture, and Security Audit

---

### Table of Contents
1. **Executive Summary & Acknowledgement**
2. **Problem Statement**
3. **Core Objectives & Security Philosophy**
4. **Platform Introduction**
5. **System Architecture & Data Flow Diagrams**
6. **Core Capabilities & Scanning Modules**
   - Heuristic URL & Phishing Detection Engine
   - Deep Media & Polyglot Binary Carver
   - Shannon Entropy & Steganographic Signal Analyzer
   - Deterministic ML Anomaly Classifier
   - Safe Disassembly Sandbox Adapter
   - Offline Threat Intelligence & Lexical Knowledge Base
   - Evidence Fusion Engine & Risk Scorer
   - Multi-Modal Cloud Gemini AI Reasoning Engine
7. **Technology Stack & Justification Matrix**
8. **Military-Grade Security & Isolation Controls**
9. **User Operation Manual & Workflows**
10. **Automated Verification & Test Suite Audit (37/37 Pass)**

---

## 1. Executive Summary & Acknowledgement

**SCAN ONE** is a dual-mode, hybrid-engine security intelligence platform engineered to analyze untrusted URLs, media files, executables, and polyglots before they enter local filesystems or corporate networks. Built on a zero-trust model, the platform guarantees that users never have to risk malware infection, credential theft, or privacy exposure when assessing unknown web assets.

### Acknowledgement
This software was architected with strict adherence to:
- **Zero-Data Leakage**: Transient memory isolation of user API credentials.
- **Air-Gapped Sovereign Readiness**: 100% offline functionality without external dependencies.
- **Explainable Threat Attribution**: Grounding all verdicts in deterministic mathematical, structural, and behavioral telemetry rather than black-box guesses.

---

## 2. Problem Statement

Modern malware and phishing vectors have evolved beyond basic signature-based antivirus detection:
1. **Polyglot Files**: Attackers embed executable zip archives or shell payloads inside valid JPEG/PNG headers, bypassing simplistic content-type checks.
2. **Steganographic Infiltration**: High-entropy covert channels (e.g., LSB alterations) hide command-and-control (C2) payloads within innocuous media.
3. **Dynamic & Obfuscated Phishing**: Typosquatting, IDN homograph punycode, and zero-day redirect chains easily evade legacy static blocklists.
4. **Privacy & API Exploits**: Conventional cloud scanners often store uploaded files, log sensitive user API keys, or become vulnerable to Server-Side Request Forgery (SSRF) and Server-Side Template Injection.

Traditional tools force users into an undesirable trade-off: surrender data privacy to third-party cloud services or lose the analytical power of state-of-the-art AI.

---

## 3. Core Objectives & Security Philosophy

SCAN ONE was built to eliminate this compromise by providing:

```
                  ┌──────────────────────────────────────────────┐
                  │          ZERO-TRUST DUAL ENGINE              │
                  ├──────────────────────┬───────────────────────┤
                  │   AIR-GAPPED MODE    │   ONLINE AI MODE      │
                  │   100% Deterministic │   Gemini Multi-Modal  │
                  │   Zero Network I/O   │   Ephemeral Memory    │
                  └──────────────────────┴───────────────────────┘
```

1. **Dual Engine Sovereignty**: Switch instantaneously between **Offline Local Mode** (zero internet calls, deterministic heuristics, local rule-based MITRE ATT&CK mapping) and **Online AI Mode** (cloud-assisted reasoning via Google Gemini 3.7/2.5).
2. **Ephemeral Credential Security**: API keys reside purely in transient browser memory (`sessionStorage`) and are never written to disk, database, server logs, or telemetry pipelines.
3. **Transparent Evidence Provenance**: Every finding contains a rigorous source citation, severity classification, confidence score, and remediation guideline.

---

## 4. System Architecture Diagram

```
+---------------------------------------------------------------------------------------+
|                                    CLIENT BROWSER                                     |
|  +---------------------------------------------------------------------------------+  |
|  |  Interactive HUD / Three.js 3D Threat Visualizer / Kinetic Typography Terminal  |  |
|  +---------------------------------------------------------------------------------+  |
|         │                                                                             |
|         │ WebSockets / SSE / HTTPS (Sanitized Payloads)                               |
|         ▼                                                                             |
+---------------------------------------------------------------------------------------+
|                              EDGE / INGRESS SECURITY                                  |
|  +--------------------------+  +-------------------------+  +----------------------+  |
|  | Sliding-Window Rate      |  | Multi-Encoding SSRF     |  | Transient Credential |  |
|  | Limiter (60 req/min)     |  | Guard (Hex/Oct/Dec/DNS) |  | Scrubber & Sanitizer |  |
|  +--------------------------+  +-------------------------+  +----------------------+  |
+---------------------------------------------------------------------------------------+
                                          │
                  ┌───────────────────────┴───────────────────────┐
                  ▼                                               ▼
+───────────────────────────────────+   +───────────────────────────────────+
|     AIR-GAPPED LOCAL PIPELINE     |   |       CLOUD AI ORCHESTRATION      |
|  +-----------------------------+  |   |  +-----------------------------+  |
|  | Heuristic URL Scanner       |  |   |  | Google GenAI SDK Client     |  |
|  +-----------------------------+  |   |  +-----------------------------+  |
|  | Media & Polyglot Carver     |  |   |  | Gemini 3.7 / 2.5 Flash      |  |
|  +-----------------------------+  |   |  +-----------------------------+  |
|  | Shannon Entropy / Stego     |  |   |  | Multimodal Media Ingestion  |  |
|  +-----------------------------+  |   |  +-----------------------------+  |
|  | Byte Anomaly ML Classifier  |  |   |  | Dynamic Threat Synthesis    |  |
|  +-----------------------------+  |   +───────────────────────────────────+
|  | Static Disassembly Sandbox  |  |                     │
|  +-----------------------------+  |                     │
|  | MITRE BM25 Knowledge Base   |  |                     │
|  +-----------------------------+  |                     │
+───────────────────────────────────+                     │
                  │                                       │
                  └───────────────────┬───────────────────┘
                                      ▼
+---------------------------------------------------------------------------------------+
|                            EVIDENCE FUSION ENGINE & SCORER                            |
|  • Deduplicates findings across local and neural detectors                             |
|  • Calculates weighted composite Risk Score (0-100)                                   |
|  • Generates Verdict: [SAFE | SUSPICIOUS | MALICIOUS | UNKNOWN]                       |
|  • Synthesizes MITRE ATT&CK TTPs & Defense-in-Depth Remediation Steps                 |
+---------------------------------------------------------------------------------------+
                                      │
                                      ▼
+---------------------------------------------------------------------------------------+
|                               REPORT & EXPORT ENGINE                                  |
|  • PDF Forensics Report Generation (PDFKit)                                           |
|  • JSON / CSV Raw Telemetry Export                                                    |
+---------------------------------------------------------------------------------------+
```

---

## 5. Technology Stack & Justification Matrix

| Technology | Purpose | Selection Reasoning |
| :--- | :--- | :--- |
| **Node.js (v20+)** | Runtime Environment | High-performance asynchronous non-blocking I/O for stream processing and binary slicing. |
| **Express.js** | HTTP REST & API Gateway | Minimalist, auditable request handling with lightweight middleware hooks. |
| **Three.js (WebGL)** | 3D Threat Telemetry Visualizer | Hardware-accelerated interactive globe and particle mesh for situational awareness without external UI bloat. |
| **Multer (In-Memory)** | Ephemeral File Processing | Uses `memoryStorage()` exclusively to prevent disk caching of potentially malicious binaries. |
| **@google/genai SDK** | Cloud AI Analysis | Official Google GenAI SDK for Gemini 3.7 / 2.5 multimodal threat reasoning. |
| **PDFKit** | Forensic PDF Generation | Pure JavaScript PDF generation for exportable threat reports without headless browser vulnerabilities. |
| **Vanilla ES6+ UI** | Frontend Client | Zero third-party runtime framework dependencies, eliminating dependency supply chain risks. |

---

## 6. Detailed Capabilities & Pipeline Stages

### Stage 1: Ingress Protection & SSRF Firewall
- Normalizes URL representations across standard, hexadecimal (`0x7f000001`), integer (`2130706433`), and octal notations.
- Verifies destination IP through asynchronous DNS resolution to block private RFC 1918 subnets, carrier NAT, link-local addresses, and cloud hypervisor metadata services (AWS, GCP, Azure, Alibaba, Kubernetes).

### Stage 2: Media Structural & Polyglot Carving
- Inspects magic bytes (`FF D8 FF` for JPEG, `89 50 4E 47` for PNG, `25 50 44 46` for PDF, `4D 5A` for PE Executables, `7F 45 4C 46` for Linux ELF).
- Carves trailing embedded structures to catch hidden ZIP, RAR, or binary payloads concatenated after End-of-Image markers (`FF D9` / `IEND`).

### Stage 3: Steganographic & Shannon Entropy Analysis
- Computes byte frequency distribution and Shannon entropy:
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
- Assesses Least Significant Bit (LSB) variance across pixel channels to detect hidden payloads and encrypted payload carriers.

### Stage 4: Safe Static Disassembly Sandbox
- Evaluates PE/ELF headers, section names (`.text`, `.rsrc`, `.upx`), imported API symbols (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`), and obfuscation indicators without executing the binary on host systems.

### Stage 5: Offline Threat Intel & BM25 Knowledge Base
- Cross-references extracted indicators against an offline repository of known threat actors (e.g., APT28, Lazarus, FIN7) and MITRE ATT&CK techniques using BM25 lexical relevance ranking.

### Stage 6: Evidence Fusion & Verdict Synthesis
- Correlates findings from all modules with weighted confidence scoring:
  - **Score 0 - 24**: `SAFE` (Benign asset)
  - **Score 25 - 69**: `SUSPICIOUS` (Anomalies detected, caution required)
  - **Score 70 - 100**: `MALICIOUS` (Confirmed threat or exploit payload)

---

## 7. Military-Grade Security & Isolation Controls

1. **Ephemeral RAM Credentials**: API keys exist only in client browser session memory (`sessionStorage`). They are automatically purged on window close or via the manual "Wipe Key from Memory" action.
2. **Credential Scrubber**: Regex scrubbing automatically removes API keys and authorization headers from all server outputs, error traces, and JSON payloads.
3. **Sliding-Window Rate Limiting**: Enforces strict throttling (60 requests/minute for scans; 15 requests/minute for credential testing).
4. **Content Security Policy (CSP)**: Strict CSP disallows untrusted scripts, object injection, or unauthenticated cross-origin requests.

---

## 8. User Operation Manual

### Analyzing a Suspicious URL
1. Select **URL Threat Scan** on the main dashboard.
2. Enter the target web address.
3. Select your operational mode:
   - **Offline Local**: Air-gapped static heuristics (No API key needed).
   - **Online AI**: Multi-modal Gemini analysis (Uses transient session key).
4. Click **Execute Threat Analysis**.
5. Inspect the interactive 3D Globe, Threat Radar, and Evidence Breakdown.

### Inspecting Files & Polyglot Payloads
1. Navigate to the **File & Binary Inspector** tab.
2. Drag and drop any image, document, archive, or executable (up to 20MB).
3. View the generated SHA-256 hash, entropy distribution, magic byte verification, and carved sub-file payloads.
4. Click **Download Forensic PDF Report** for formal incident reporting.

---

## 9. Verification & Test Suite Proof

The entire security framework is covered by a 37-point automated verification test suite:

```
[SECTION 1] SSRF Private IP & Gateway Defenses (10/10 Passed)
[SECTION 2] URL Threat & Phishing Heuristics (7/7 Passed)
[SECTION 3] Media Structural, Polyglot & Masquerading (5/5 Passed)
[SECTION 4] Statistical ML Anomaly & Stego Entropy Analysis (2/2 Passed)
[SECTION 5] Safe Sandbox Adapter Architecture (1/1 Passed)
[SECTION 6] Threat Intelligence & Offline Knowledge Base (2/2 Passed)
[SECTION 7] Evidence Fusion Engine & Provenance (2/2 Passed)
[SECTION 8] Military-Grade Security & Anti-Exploit Defenses (8/8 Passed)
================================================================
TOTAL: 37 / 37 TESTS PASSED WITH ZERO FAILURES (100% SUCCESS)
================================================================
```
