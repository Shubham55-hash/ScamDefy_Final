# ScamDefy Environment Setup Guide

## 🔒 Secure Configuration for Development & Production

This guide explains how to set up API keys securely so they're never accidentally uploaded to GitHub.

---

## 📋 Quick Start

### For Developers (Development Setup)

1. **Copy the template file:**
   ```bash
   cp .env.example .env
   ```

2. **Fill in your API keys in `.env`:**
   ```bash
   # Get your FREE keys:
   # - Google Safe Browsing: https://console.cloud.google.com
   # - Google Gemini: https://aistudio.google.com/app/apikey
   # - IPQualityScore: https://www.ipqualityscore.com/create-account
   # - VirusTotal: https://www.virustotal.com (optional)
   
   VITE_GOOGLE_SAFE_BROWSING=your_key_here
   VITE_GEMINI=your_key_here
   VITE_IPQUALITYSCORE=your_key_here
   VITE_VIRUSTOTAL=your_key_here
   ```

3. **Important:** The `.env` file is gitignored — it will NOT be uploaded when you commit/push to GitHub ✅

### For End Users (Production Setup)

Users can configure API keys directly in the extension:

1. Right-click extension icon → "Options"
2. Paste your API keys in the form
3. Keys are stored in Chrome's secure sync storage
4. They sync across all your Chrome devices
5. They are **never** sent to GitHub or any external server

---

## 🏗️ Architecture

### Configuration Files:

```
env/
├── config.js        # Configuration loader & manager
├── loadEnv.js       # Loads .env file for development

.env.example         # Template (commit this to git)
.env                 # Actual keys (gitignored - NEVER commit)
.gitignore           # Prevents .env from being uploaded
```

### How It Works:

1. **Development Mode:**
   - You create `.env` with your test keys
   - `config.js` reads from Chrome storage or environment
   - `loadEnv.js` injects values from `.env` for testing

2. **Production Mode (on GitHub):**
   - `.env` is not included (it's in `.gitignore`)
   - Users receive the extension without any hardcoded keys
   - Users configure keys via extension options

3. **User Installation (from Chrome Web Store):**
   - Extension comes with `.env.example` (shows structure)
   - No actual API keys are included
   - Users optionally configure keys via options page

---

## 🔑 API Keys Usage

### Which APIs require keys?

| API | Key Required | Free Tier | Rate Limit |
|-----|:---:|:---:|:---:|
| URLHaus | ❌ No | ✅ Yes | Unlimited |
| Google Safe Browsing | ✅ Yes | ✅ 10k/day | 10,000 req/day |
| Google Gemini | ✅ Yes | ✅ Limited | 15 req/min |
| IPQualityScore | ✅ Yes | ✅ 5k/month | 5,000 req/month |
| VirusTotal | ✅ Yes (optional) | ✅ 500/day | 500 req/day |

### Getting Free API Keys (< 5 minutes):

**Google Safe Browsing:**
- Go to https://console.cloud.google.com
- Create a new project
- Enable "Safe Browsing API"
- Create an API key under Credentials

**Google Gemini:**
- Go to https://aistudio.google.com/app/apikey
- Click "Get API Key"
- Copy and paste into `.env`

**IPQualityScore:**
- Go to https://www.ipqualityscore.com/create-account
- Sign up and verify email
- Find API key in dashboard
- Copy and paste into `.env`

**VirusTotal (Optional):**
- Go to https://www.virustotal.com/gui/join-us
- Sign up and verify
- Find API key in settings
- Leave empty if you don't need it

---

## 🚀 Using Configuration in Code

### For Developers:

Import the config module and initialize it:

```javascript
import { config } from './env/config.js';

// Get all configuration
const cfg = await config.getAll();
console.log(cfg.GOOGLE_SAFE_BROWSING); // Your key

// Get specific key
const geminiKey = await config.get('GEMINI');

// Set a key (saves to Chrome storage)
await config.set('GEMINI', 'new_key_here');
```

### In apiService.js:

The `initializeConfig()` function automatically loads keys on first API call. No manual setup needed!

---

## 🔐 Security Best Practices

✅ **DO:**
- Store `.env` locally only
- Add `.env` to `.gitignore` (already done)
- Rotate API keys periodically
- Use free tier limits to stay within budget
- Never commit `.env` to any branch

❌ **DON'T:**
- Put API keys directly in code
- Commit `.env` to GitHub
- Share API keys in pull requests or issues
- Use production keys for testing
- Expose keys in error messages

---

## 🐛 Troubleshooting

### "API keys not loading"

1. Check that `.env` file exists in project root
2. Verify you're not in a subdirectory when reading `.env`
3. Restart the extension (reload in `chrome://extensions`)

### "Chrome storage permission denied"

- Ensure extension has `storage` permission in `manifest.json`
- Already included ✅

### "API calls failing"

1. Verify API key is correct
2. Check rate limits haven't been exceeded
3. Test key on the service's website first
4. Look at browser console for error messages

---

## 📦 Publishing to Chrome Web Store

When ready to release on Chrome Web Store:

1. Remove `.env` file (already in `.gitignore`)
2. `.env.example` stays for reference
3. Extension will ship without any API keys
4. Users configure keys optionally in settings
5. Push to GitHub safely ✅

---

## 🔄 Migrating from Old Code

If you previously had hardcoded keys:

**Before (insecure):**
```javascript
const API_KEY = "AIzaSy..."; // ❌ Exposed on GitHub
```

**After (secure):**
```javascript
import { config } from './env/config.js';
const apiKey = await config.get('GOOGLE_SAFE_BROWSING'); // ✅ Safe
```

---

## 📚 References

- [Chrome Storage API](https://developer.chrome.com/docs/extensions/reference/storage/)
- [Google Safe Browsing API](https://developers.google.com/safe-browsing)
- [Google Gemini API](https://ai.google.dev/)
- [Environment Variables in Web Apps](https://12factor.net/config)

---

**Questions?** Check the console logs for debug info with `[ScamDefy]` prefix.
