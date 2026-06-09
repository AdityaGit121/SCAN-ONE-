# 🔐 Safety Downloader — Threat Intelligence Scanner

A free online tool to scan URLs and files for hidden threats, malware, and phishing attacks.

**Live analysis engine checks:**
- Binary headers (PE/ELF/Mach-O executables)
- Known malware SHA-256 hashes
- Suspicious file extensions (`.exe`, `.bat`, `.vbs`, `.scr`, etc.)
- Heuristic content patterns (PowerShell, eval, base64_decode, etc.)
- URL blacklist & phishing keyword detection
- TLD risk scoring, IP-based URLs, redirect attacks

---

## 🚀 Deploy in 5 Minutes (Free)

### Option A — Render.com (Recommended)

1. Push this folder to a **GitHub repo**
2. Go to [render.com](https://render.com) → **New → Web Service**
3. Connect your GitHub repo
4. Set these values:
   - **Runtime:** Node
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
   - **Instance Type:** Free
5. Click **Deploy** — your site will be live at `https://your-app.onrender.com`

---

### Option B — Railway.app

1. Push to GitHub
2. Go to [railway.app](https://railway.app) → **New Project → Deploy from GitHub**
3. Select your repo — Railway auto-detects Node.js
4. Your app is live in ~2 minutes at `https://your-app.up.railway.app`

---

### Option C — Fly.io

```bash
npm install -g flyctl
flyctl auth login
flyctl launch        # follow prompts, choose free tier
flyctl deploy
```

---

### Option D — Local Development

```bash
npm install
npm start
# Open http://localhost:3000
```

---

## 📁 Project Structure

```
safety-downloader/
├── server.js          # Express backend — all scan logic
├── package.json
├── public/
│   └── index.html     # Frontend — Three.js globe + scan UI
└── README.md
```

## 🌐 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/scan?url=<url>` | Scan a URL for threats |
| POST | `/api/scan-file` | Scan an uploaded file (multipart/form-data, field: `file`) |
| GET | `/health` | Health check |

### Example Response

```json
{
  "status": "WARNING",
  "message": "Advanced URL threat intelligence analysis completed",
  "riskLevel": "MODERATE",
  "riskLabel": "Moderate Risk",
  "riskScore": 45,
  "findings": [
    "No HTTPS — unencrypted connection",
    "Phishing keywords in domain: login, verify"
  ],
  "url": "http://login-verify-bank.tk"
}
```

## 🔧 Tech Stack

- **Backend:** Node.js + Express
- **Frontend:** Vanilla JS + Three.js
- **Deployment:** Any Node.js host (Render, Railway, Fly.io, Vercel, VPS)
- **No database required** — fully stateless

---

Original project by Jay Kanaka Aditya Kunche · Spring Boot → Node.js migration
