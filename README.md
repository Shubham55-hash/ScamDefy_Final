# ScamDefy — AI-Powered Chrome Extension
### Real-time protection against phishing, dangerous URLs, fake login forms & AI voice deepfakes

---

## 🚀 Quick Setup (Developer Mode)

### 1. Add Your API Keys

Open `api/apiService.js` and replace the placeholder keys at the top:

```js
const API_KEYS = {
  GOOGLE_SAFE_BROWSING: "YOUR_GOOGLE_SAFE_BROWSING_API_KEY",
  VIRUSTOTAL:           "YOUR_VIRUSTOTAL_API_KEY",
  IPQUALITYSCORE:       "YOUR_IPQUALITYSCORE_API_KEY",
  GEMINI:               "YOUR_GEMINI_API_KEY",
};
```

#### Where to get them:
| API | Link | Cost |
|-----|------|------|
| Google Safe Browsing | [console.cloud.google.com](https://console.cloud.google.com) | Free |
| VirusTotal | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) | Free (500 req/day) |
| IPQualityScore | [ipqualityscore.com](https://www.ipqualityscore.com) | Free (5000 req/mo) |
| Google Gemini | [aistudio.google.com](https://aistudio.google.com) | Free tier |

Also update `BACKEND_URL` in `api/apiService.js` to point to your deployed FastAPI backend.

---

### 2. Load the Extension in Chrome

1. Open Chrome → go to `chrome://extensions`
2. Enable **Developer Mode** (top-right toggle)
3. Click **"Load unpacked"**
4. Select the `scamdefy-extension/` folder
5. The ScamDefy shield icon will appear in your toolbar ✅

---

## 📁 File Structure

```
scamdefy-extension/
├── manifest.json          ← Extension config (MV3)
├── background.js          ← Service worker — scan pipeline orchestrator
├── content/
│   └── content.js         ← Page scanner — links, forms, banner injection
├── modules/
│   ├── urlDetection.js    ← URL heuristics + Safe Browsing + PhishTank
│   ├── phishingDetection.js ← SSL, domain age, form analysis, impersonation
│   ├── voiceDetection.js  ← Audio capture + deepfake backend detection
│   └── scamExplainer.js   ← ✨ AI-powered scam explanation (Gemini)
├── api/
│   └── apiService.js      ← All external API calls (centralized)
├── utils/
│   ├── riskScorer.js      ← Weighted scoring → LOW/MEDIUM/HIGH/CRITICAL
│   └── logger.js          ← Chrome storage + Firebase sync
├── ui/
│   ├── popup.html         ← Extension popup dashboard
│   ├── popup.js           ← Dashboard controller
│   ├── warning.html       ← Full-page threat block UI
│   └── style.css          ← Dark theme design system
└── icons/
    ├── icon16.svg
    ├── icon32.svg
    ├── icon48.svg
    └── icon128.svg
```

---

## 🔒 How It Works

```
User visits URL
     │
     ▼
background.js intercepts via chrome.tabs.onUpdated
     │
     ├── urlDetection.js    → Google Safe Browsing + PhishTank + heuristics
     ├── phishingDetection.js → IPQS domain age + SSL + form + brand check
     └── checkVirusTotal()  → VirusTotal multi-engine scan
          │
          ▼
     riskScorer.js calculates weighted score (0–100)
          │
     ┌────┴────┐
     │         │
  LOW/MED    HIGH/CRITICAL
   (silent)       │
               scamExplainer.js calls Gemini API
                  │
               warning.html shown with AI explanation
               logger.js saves to chrome.storage
```

---

## ✨ The Scam Explainer Feature

Instead of just saying "DANGEROUS", ScamDefy tells users **exactly why**:

> *"Banking Credential Harvesting Scam — This domain was created 2 days ago and impersonates HDFC Bank's official website. The login form on this page sends your username and password to a server located in a foreign country. Do not enter any credentials here."*

This is powered by **Google Gemini AI** + all collected risk signals.

---

## 🛡️ Risk Levels

| Level | Score | Behavior |
|-------|-------|----------|
| ✅ LOW | 0–24 | Silent — no alert |
| ⚠️ MEDIUM | 25–49 | Banner shown on page |
| 🔴 HIGH | 50–74 | Full-page warning, AI explanation |
| ☠️ CRITICAL | 75+ | Full-page block, strong AI warning |

---

## 🎙️ Voice Deepfake Detection

Voice detection requires your FastAPI backend to be running with the HuggingFace model.

Backend endpoint expected: `POST /voice-detect` accepting `multipart/form-data` with field `audio`.

Returns: `{ "label": "FAKE"|"REAL", "confidence": 0.95 }`

---

## 📊 Firebase Integration (Optional)

1. Create a Firebase project at [console.firebase.google.com](https://console.firebase.google.com)
2. Add your config to `utils/logger.js` under `FIREBASE_CONFIG`
3. Uncomment the `syncToFirebase()` call in `logThreat()`

---

## 🧪 Testing

To test with a known phishing URL, use any URL from [phishtank.com](https://phishtank.com).

To test the warning page directly, navigate to:
```
chrome-extension://[YOUR_EXTENSION_ID]/ui/warning.html?level=CRITICAL&score=88&type=Banking+Phishing&blocked=http://fake-hdfc-login.xyz&explanation=This+is+a+test+warning
```

---

*Built with ❤️ by the ScamDefy Team*
