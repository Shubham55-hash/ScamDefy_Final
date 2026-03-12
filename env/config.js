/**
 * env/config.js — Simple Configuration Manager
 * 
 * Loads API keys from Chrome storage.
 * No complex initialization — just simple sync/async getters.
 */

class Config {
    constructor() {
        this.cache = null;
    }

    /**
     * Get a specific config value
     */
    async get(key) {
        try {
            if (!chrome?.storage?.sync) return '';
            const stored = await chrome.storage.sync.get([key]);
            return stored[key] || '';
        } catch (err) {
            console.warn(`[Config] Failed to get ${key}:`, err.message);
            return '';
        }
    }

    /**
     * Get all config
     */
    async getAll() {
        try {
            if (!chrome?.storage?.sync) {
                return {
                    GOOGLE_SAFE_BROWSING: '',
                    GEMINI: '',
                    VIRUSTOTAL: '',
                    IPQUALITYSCORE: '',
                    BACKEND_URL: 'https://your-scamdefy-backend.onrender.com',
                };
            }
            
            const stored = await chrome.storage.sync.get([
                'GOOGLE_SAFE_BROWSING',
                'GEMINI',
                'VIRUSTOTAL',
                'IPQUALITYSCORE',
                'BACKEND_URL',
            ]);

            return {
                GOOGLE_SAFE_BROWSING: stored.GOOGLE_SAFE_BROWSING || '',
                GEMINI: stored.GEMINI || '',
                VIRUSTOTAL: stored.VIRUSTOTAL || '',
                IPQUALITYSCORE: stored.IPQUALITYSCORE || '',
                BACKEND_URL: stored.BACKEND_URL || 'https://your-scamdefy-backend.onrender.com',
            };
        } catch (err) {
            console.warn('[Config] Failed to get all config:', err.message);
            return {
                GOOGLE_SAFE_BROWSING: '',
                GEMINI: '',
                VIRUSTOTAL: '',
                IPQUALITYSCORE: '',
                BACKEND_URL: 'https://your-scamdefy-backend.onrender.com',
            };
        }
    }

    /**
     * Set a config value
     */
    async set(key, value) {
        try {
            if (!chrome?.storage?.sync) {
                console.warn('[Config] Chrome storage not available');
                return false;
            }
            await chrome.storage.sync.set({ [key]: value });
            console.log(`[Config] Saved ${key}`);
            return true;
        } catch (err) {
            console.error(`[Config] Failed to save ${key}:`, err.message);
            return false;
        }
    }

    /**
     * Remove a config value
     */
    async remove(key) {
        try {
            if (!chrome?.storage?.sync) return false;
            await chrome.storage.sync.remove([key]);
            console.log(`[Config] Removed ${key}`);
            return true;
        } catch (err) {
            console.error(`[Config] Failed to remove ${key}:`, err.message);
            return false;
        }
    }

    /**
     * Clear all config
     */
    async clear() {
        try {
            if (!chrome?.storage?.sync) return false;
            await chrome.storage.sync.clear();
            console.log('[Config] Cleared all');
            return true;
        } catch (err) {
            console.error('[Config] Failed to clear:', err.message);
            return false;
        }
    }
}

// Export singleton instance
export const config = new Config();
