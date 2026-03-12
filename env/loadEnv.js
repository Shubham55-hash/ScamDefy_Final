/**
 * env/loadEnv.js — Load .env file for DEVELOPMENT ONLY
 * 
 * NOTE: This is for local development/testing ONLY.
 * The .env file is NOT shipped with the extension.
 * In production, users configure keys via extension options.
 * 
 * For development testing:
 * 1. Create .env file at project root with your keys
 * 2. This script can inject them for testing
 * 3. Or just use Chrome's extension options page
 */

// This module is optional and only used during local development
// The extension will work fine without it

export function setupEnvForDevelopment() {
    // Placeholder for development setup
    // You can manually set keys using:
    // window.__SCAMDEFY_ENV__ = {
    //     GOOGLE_SAFE_BROWSING: 'your-key',
    //     GEMINI: 'your-key',
    //     ...
    // };
    console.log('[ScamDefy] Development environment setup (optional)');
}
