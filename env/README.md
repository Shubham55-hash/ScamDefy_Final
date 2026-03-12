# env/ — Environment Configuration Module

This folder contains the configuration system for ScamDefy's API keys and sensitive settings.

## Files

### `config.js`
The main configuration module that:
- Loads API keys from Chrome storage (user's saved settings)
- Falls back to environment variables if available
- Provides methods to get/set/remove configuration values
- Works as a singleton instance

**Usage:**
```javascript
import { config } from '../env/config.js';

// Initialize and get all config
const cfg = await config.getAll();

// Get specific key
const key = await config.get('GEMINI');

// Set key (saves to Chrome storage)
await config.set('GEMINI', 'your-key-here');

// Remove key
await config.remove('GEMINI');

// Clear all config
await config.clear();
```

### `loadEnv.js`
Development-only helper that:
- Reads the root `.env` file
- Injects values into `window.__SCAMDEFY_ENV__`
- Allows testing with local .env file
- **Not used in production**

## How Configuration Works

### Priority Order (1st found is used):
1. **Chrome sync storage** — User's saved settings from extension options
2. **Environment variables** — Values from `.env` file (development only)
3. **Defaults** — Falls back to safe defaults

### For Developers:
1. Copy `.env.example` to `.env` at project root
2. Fill in your test API keys
3. Run the extension
4. `config.js` reads from `.env` automatically

### For End Users:
1. User installs extension
2. Extension has no hardcoded keys (secure!)
3. User can optionally configure keys in extension options
4. Keys are stored in Chrome's sync storage (encrypted)
5. Keys sync across all user's Chrome devices

## Setup Instructions

1. **Create Environment File:**
   ```bash
   cp ../.env.example ../.env
   ```

2. **Add Your API Keys:**
   ```bash
   # Edit ../.env and fill in your keys
   VITE_GOOGLE_SAFE_BROWSING=your_key
   VITE_GEMINI=your_key
   # ... etc
   ```

3. **Never commit .env:**
   - `.env` is in `.gitignore`
   - Only `.env.example` is committed

## Integration Points

- **apiService.js** — Calls `config.getAll()` on first API request
- **popup.js** — Can read/write user settings using `config`
- **background.js** — Can manage config across extension lifetime

## Security Notes

- ✅ API keys are never stored in files that get version controlled
- ✅ `.env` file is in `.gitignore`
- ✅ Chrome storage is encrypted by browser
- ✅ No keys are hardcoded in the extension
- ✅ Users must opt-in to configure keys
