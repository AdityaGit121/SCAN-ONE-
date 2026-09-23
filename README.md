# Safety Downloader — AI Security Platform

**Safety Downloader** is a dual-mode cybersecurity threat-analysis platform engineered to detect sophisticated phishing campaigns, polyglot binary attacks, steganographic media payloads, and malicious file anomalies. It operates across two dedicated environments: **Online AI Mode** (powered by Google Gemini `@google/genai` SDK and live threat graphing) and **Offline Local Mode** (100% air-gapped, zero-cloud deterministic analysis).

---

## Features

- **Dual-Mode Operational Architecture**: Toggle seamlessly between cloud-assisted AI reasoning and strictly air-gapped offline local analysis.
- **Multimodal Phishing Detection**: URL decomposition, IDN Punycode homograph inspection, brand typosquatting heuristics, Shannon entropy DGA scoring, and syntactic credential harvest tagging.
- **Deep Media Structural & Polyglot Parsing**: Validates container headers against magic bytes (JPEG, PNG, WEBP, MP4, GIF, PDF, SVG). Carves trailing payloads, hidden Windows PE (`MZ`) executables, Linux ELF binaries, and ZIP structures embedded in images.
- **Steganography & LSB Variance Detection**: Measures Least Significant Bit (LSB) variance, high-frequency byte distributions, and payload entropy jumps.
- **Statistical Local ML Classifier**: In-memory feature vector classifier calculating anomaly scores on byte distributions without requiring heavy runtime frameworks.
- **Isolated Behavioral Sandbox Adapter**: Multi-adapter sandbox interface (`SandboxEngine`) capturing process creation, registry persistence hooks, and outbound network staging safely.
- **Offline RAG Knowledge Base**: Curated local database of MITRE ATT&CK techniques (T1036, T1027.003, etc.) and remediation strategies accessible with zero network dependency.
- **Evidence Fusion Engine**: Synthesizes scores from traditional heuristics, structural parsers, ML vector models, sandbox telemetry, and Gemini reasoning into an explainable verdict: `SAFE`, `LOW_RISK`, `SUSPICIOUS`, `HIGH_RISK`, `MALICIOUS`, or `UNKNOWN`.
- **SSRF Defense Architecture**: Restricts online scanning from touching private IP ranges (RFC 1918), localhost loopbacks, link-local metadata endpoints (`169.254.169.254`), or internal cloud metadata services.
- **Interactive 3D Threat Radar**: Hardware-accelerated Three.js visualizer rendering live threat state transitions.

---

## Online AI Mode

Online AI Mode combines local deterministic scanning with Google Gemini models via `@google/genai`.
- **Reasoning Models**: Supported models include `gemini-3.8-flash` (recommended, low latency), `gemini-3.1-pro-preview`, and `gemini-3.1-flash-lite`.
- **Structured Schema Enforcements**: Guarantees predictable machine-readable JSON verdicts (`risk_score`, `confidence`, `attack_category`, `evidence`, `recommended_action`).
- **Telemetry Enriched**: Supplies Gemini with static findings, Shannon entropy, file headers, and sandbox telemetry for contextual reasoning.
- **Fault-Tolerant Fallback**: If cloud API quotas are exhausted or network connectivity drops, the system seamlessly outputs deterministic local verdicts.

---

## Offline Local Mode

Offline Local Mode guarantees **100% air-gapped security**.
- Disables all external network requests, DNS queries, and Gemini API calls.
- Employs deterministic magic byte matching, local signature databases, and binary chunk inspection.
- Queries the embedded Local RAG Knowledge Base for MITRE ATT&CK mappings.
- Safe for highly sensitive, classified, or privacy-critical file triage.

---

## Supported Media & Containers

- **Images**: JPEG (`.jpg`, `.jpeg`), PNG (`.png`), WEBP (`.webp`), GIF (`.gif`), SVG (`.svg`)
- **Documents & Archives**: PDF (`.pdf`), ZIP (`.zip`), Microsoft Office containers
- **Audio & Video**: MP4 (`.mp4`), WAV (`.wav`), MP3 (`.mp3`)
- **Binaries & Scripts**: Windows PE (`.exe`), Linux ELF (`.elf`), PowerShell, Batch, VBScript

---

## Phishing Detection Architecture

1. **Syntax & Protocol Verification**: Identifies plaintext HTTP transmissions and suspicious port destinations.
2. **Homograph & Punycode Scanner**: Flags `xn--` IDN labels used to impersonate high-value targets (e.g., PayPal, Google, Microsoft).
3. **Shannon Entropy Engine**: Identifies randomly generated subdomains produced by Domain Generation Algorithms (DGA).
4. **Credential Harvesting Lexicon**: Flags high-density urgency prompts (`verify`, `suspend`, `unlock`, `kyc`, `banking`).
5. **Brand Impersonation Classifier**: Detects unauthorized use of protected brand trademarks in non-official domains.

---

## Structural & Polyglot Analysis

Polyglots are files crafted to execute as multiple distinct formats simultaneously (e.g., a file displaying as a valid JPEG image while containing an embedded PE executable header at offset `0xA840`).
- **Header vs Extension Verification**: Detects when an executable or script is disguised with an image extension.
- **Chunk Parsing**: Walks PNG chunk trees (`IHDR` to `IEND`) and JPEG stream markers (`0xFFD8` to `0xFFD9`), alerting on unexpected trailing data.
- **Carving Engine**: Scans arbitrary offsets for nested `MZ`, `PE\0\0`, `ELF`, or `PK\x03\x04` markers.

---

## Sandbox Architecture

The platform incorporates an extensible `SandboxEngine` interface:
```text
SandboxEngine
 ├── LocalContainerSandbox (Docker micro-VM isolation)
 ├── WindowsSandboxAdapter (Windows host integration)
 ├── LinuxSandboxAdapter (Unprivileged namespaces)
 └── SafeEmulatedSandbox (Static behavioral telemetry emulation)
```
Untrusted files are never executed directly on the host machine. If external virtualization is unconfigured, the safe emulation engine parses disassembly paths to flag API calls (`reg add`, `powershell`, outbound sockets).

---

## Local ML & Offline RAG

- **Vector Anomaly Classifier**: Analyzes 4-dimensional statistical feature vectors (file size log scale, high-byte density, zero-byte density, and ASCII character ratio) to detect packed binaries and shellcode sleds.
- **Offline RAG Knowledge Base**: Retrieves contextual cybersecurity documentation matching detected symptoms for instant remediation guidance.

---

## Gemini API Setup

You can configure your Gemini API key in two ways:
1. **Server Environment Variable**:
   Set `GEMINI_API_KEY=your_key_here` in `.env`.
2. **In-Dashboard Session Storage**:
   Navigate to **Gemini AI Config** in the web interface, paste your key, test the connection, and save locally. Keys are stored only in your browser's private session storage and are never logged or stored in scan records.

---

## Installation

### Prerequisites
- Node.js 18+ or 22+
- npm 9+

```bash
git clone https://github.com/AdityaGit121/SafetyDownloder.git
cd SafetyDownloder
npm install
```

---

## Windows Setup

```cmd
:: Open Command Prompt or PowerShell as Administrator
git clone https://github.com/AdityaGit121/SafetyDownloder.git
cd SafetyDownloder
npm install
copy .env.example .env
npm start
```

---

## Linux Setup

```bash
git clone https://github.com/AdityaGit121/SafetyDownloder.git
cd SafetyDownloder
npm install
cp .env.example .env
npm start
```

---

## Running

- **Development Mode**: `npm run dev`
- **Production Mode**: `npm start`
- **Run Test Suite**: `npm test`

The application binds to `http://0.0.0.0:3000`.

---

## Security Considerations

- **Strict SSRF Protection**: Online scanners filter all user-supplied URLs against private IP subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `::1`).
- **Memory Quarantine**: Uploaded files are buffered in memory with a hard 20MB limit and automatically purged after scanning.
- **XSS & CSP Headers**: Equipped with `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, and strict HTML sanitization.

---

## Privacy

- Files and URLs scanned in **Offline Local Mode** never leave your local environment.
- In **Online AI Mode**, telemetry is sent strictly to the configured Google Gemini API endpoint over TLS.
- API keys are never stored in scan history or telemetry logs.

---

## Limitations

- **Static Emulation**: Static behavioral trace analysis does not replace bare-metal dynamic sandbox detonation for advanced evasion malware.
- **Deep Model Weights**: ONNX and TensorFlow deep weights require external local file mounting for specialized visual steganography neural networks.
- **Live Reputation**: Offline mode cannot confirm newly registered malicious domains without cached local intelligence.

---

## Future Improvements

- Integration with local Ollama / llama.cpp endpoints for offline LLM reasoning.
- Bare-metal micro-VM sandbox integration using Firecracker or gVisor.
- YARA rule compilation engine for custom enterprise rule authoring.
