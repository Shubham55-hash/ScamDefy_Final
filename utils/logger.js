/**
 * logger.js — ScamDefy Threat Logging & History Module
 *
 * - Saves every threat detection to Chrome local storage
 * - Timestamps all entries
 * - Provides data to the popup dashboard
 * - Firebase Firestore sync (optional — requires Firebase config)
 *
 * Uses indexedStorage.js for O(1) lookups by id, hostname, riskLevel, and date
 * instead of O(n) linear scans over the full threat array.
 */

import {
    getAllThreats as _getAllThreats,
    insertThreat,
    getThreatById,
    getThreatsByHostname,
    getThreatsByRiskLevel,
    getThreatsForDate,
    getTodayThreats as _getTodayThreats,
    getThreatsByDateRange,
    getRecentThreats as _getRecentThreats,
    updateThreat,
    isHostnameFlagged,
    countByRiskLevel,
    clearAll as clearIndexes,
} from './indexedStorage.js';

// ─── CONSTANTS ─────────────────────────────────────────────────────────────────
const STORAGE_KEY = 'scamdefy_threat_log';

// ─── FIREBASE CONFIG (Optional — replace with your config) ────────────────────
// To enable Firebase, replace these values and uncomment the Firebase import below.
const FIREBASE_CONFIG = {
    apiKey: "YOUR_FIREBASE_API_KEY",
    authDomain: "your-app.firebaseapp.com",
    projectId: "your-project-id",
    storageBucket: "your-app.appspot.com",
    messagingSenderId: "YOUR_SENDER_ID",
    appId: "YOUR_APP_ID",
};
// Note: Firebase SDK must be added as a separate script for MV3 compliance.
// For now, all threat data is stored in chrome.storage.local.

// ─── STORAGE HELPERS (delegated to indexedStorage.js) ─────────────────────────

/**
 * Get all stored threat entries from indexed storage.
 * Array is sorted newest-first.
 * @returns {Promise<Array>}
 */
export async function getAllThreats() {
    return _getAllThreats();
}

// ─── LOG A THREAT ──────────────────────────────────────────────────────────────

/**
 * Log a detected threat to local storage.
 *
 * @param {object} threatData
 * @param {string} threatData.url          — the flagged URL
 * @param {string} threatData.riskLevel    — LOW / MEDIUM / HIGH / CRITICAL
 * @param {number} threatData.score        — numeric risk score
 * @param {string} threatData.scamType     — classified scam type
 * @param {string} threatData.explanation  — AI-generated explanation
 * @param {string[]} threatData.reasons    — list of risk signals
 * @param {boolean} [threatData.userProceeded] — whether user clicked "proceed anyway"
 *
 * @returns {Promise<string>} — the entry ID
 */
export async function logThreat(threatData) {
    const entry = {
        id: `sd_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
        timestamp: new Date().toISOString(),
        url: threatData.url || 'Unknown URL',
        hostname: (() => {
            try { return new URL(threatData.url).hostname; } catch { return 'unknown'; }
        })(),
        riskLevel: threatData.riskLevel || 'HIGH',
        score: threatData.score || 0,
        scamType: threatData.scamType || 'Suspicious Website',
        explanation: threatData.explanation || '',
        reasons: threatData.reasons || [],
        userProceeded: threatData.userProceeded || false,
        blocked: !threatData.userProceeded,
    };

    // Insert into indexed storage (handles prepend, cap enforcement, and persist)
    await insertThreat(entry);
    await incrementBlockedCount(entry.blocked);

    // Optional: sync to Firebase
    // await syncToFirebase(entry);

    console.log('[ScamDefy] Threat logged:', entry.id, entry.riskLevel, entry.url);
    return entry.id;
}

// ─── STATISTICS ────────────────────────────────────────────────────────────────

const STATS_KEY = 'scamdefy_stats';

/**
 * Increment the total blocked threats counter.
 * @param {boolean} blocked
 */
async function incrementBlockedCount(blocked) {
    return new Promise((resolve) => {
        chrome.storage.local.get([STATS_KEY], (result) => {
            const stats = result[STATS_KEY] || { totalBlocked: 0, totalDetected: 0 };
            stats.totalDetected = (stats.totalDetected || 0) + 1;
            if (blocked) stats.totalBlocked = (stats.totalBlocked || 0) + 1;
            chrome.storage.local.set({ [STATS_KEY]: stats }, resolve);
        });
    });
}

/**
 * Get lifetime statistics.
 * @returns {Promise<{totalBlocked: number, totalDetected: number}>}
 */
export async function getStats() {
    return new Promise((resolve) => {
        chrome.storage.local.get([STATS_KEY], (result) => {
            resolve(result[STATS_KEY] || { totalBlocked: 0, totalDetected: 0 });
        });
    });
}

/**
 * Get threats detected today only.
 * Uses the date index for O(1) lookup instead of O(n) filter.
 * @returns {Promise<Array>}
 */
export async function getTodayThreats() {
    return _getTodayThreats();
}

/**
 * Get the N most recent threats.
 * O(1) slice on the pre-sorted array.
 * @param {number} n
 * @returns {Promise<Array>}
 */
export async function getRecentThreats(n = 10) {
    return _getRecentThreats(n);
}

/**
 * Mark a threat entry as "user proceeded despite warning".
 * Uses the id index for O(1) lookup instead of O(n) Array.find().
 * @param {string} entryId
 */
export async function markUserProceeded(entryId) {
    await updateThreat(entryId, { userProceeded: true, blocked: false });
}

/**
 * Clear all threat history from local storage and reset indexes.
 * @returns {Promise<void>}
 */
export async function clearHistory() {
    await clearIndexes();
    return new Promise((resolve) => {
        chrome.storage.local.remove([STORAGE_KEY, STATS_KEY], resolve);
    });
}

// ─── INDEXED QUERY EXPORTS ──────────────────────────────────────────────────
// Re-export indexed query functions for use by other modules.

export {
    getThreatById,
    getThreatsByHostname,
    getThreatsByRiskLevel,
    getThreatsForDate,
    getThreatsByDateRange,
    isHostnameFlagged,
    countByRiskLevel,
};

// ─── FIREBASE SYNC (Optional) ──────────────────────────────────────────────────
/**
 * Sync a threat entry to Firebase Firestore.
 * Uncomment and configure to enable cloud backup.
 *
 * async function syncToFirebase(entry) {
 *   try {
 *     await fetch(`https://firestore.googleapis.com/v1/projects/${FIREBASE_CONFIG.projectId}/databases/(default)/documents/threats`, {
 *       method: 'POST',
 *       headers: { 'Content-Type': 'application/json' },
 *       body: JSON.stringify({
 *         fields: {
 *           url: { stringValue: entry.url },
 *           riskLevel: { stringValue: entry.riskLevel },
 *           scamType: { stringValue: entry.scamType },
 *           timestamp: { stringValue: entry.timestamp },
 *         }
 *       })
 *     });
 *   } catch (err) {
 *     console.warn('[ScamDefy] Firebase sync failed:', err);
 *   }
 * }
 */
