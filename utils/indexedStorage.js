/**
 * indexedStorage.js — ScamDefy In-Memory Indexed Storage Layer
 *
 * Maintains in-memory indexes over the threat log stored in chrome.storage.local.
 * Provides O(1) lookups by id, hostname, and riskLevel instead of O(n) linear scans.
 *
 * Indexes maintained:
 *   - idIndex:        Map<id, entry>           — point lookups by threat ID
 *   - hostnameIndex:  Map<hostname, entry[]>   — all threats for a given domain
 *   - riskLevelIndex: Map<riskLevel, entry[]>  — all threats at a given severity
 *   - dateIndex:      Map<dateKey, entry[]>    — all threats on a given day (YYYY-MM-DD)
 *
 * The underlying array is kept sorted by timestamp DESC (newest first),
 * so getRecent() and date-range queries benefit from early termination.
 */

// ─── CONSTANTS ─────────────────────────────────────────────────────────────────
const STORAGE_KEY = 'scamdefy_threat_log';
const MAX_LOCAL_ENTRIES = 200;

// ─── INDEX STATE ───────────────────────────────────────────────────────────────
let threats = [];
let idIndex = new Map();          // id        -> entry reference
let hostnameIndex = new Map();    // hostname  -> [entry, ...]
let riskLevelIndex = new Map();   // riskLevel -> [entry, ...]
let dateIndex = new Map();        // 'YYYY-MM-DD' -> [entry, ...]
let indexReady = false;

// ─── INDEX HELPERS ─────────────────────────────────────────────────────────────

/**
 * Extract a YYYY-MM-DD date key from an ISO timestamp string.
 * @param {string} isoTimestamp
 * @returns {string}
 */
function dateKey(isoTimestamp) {
    return isoTimestamp ? isoTimestamp.slice(0, 10) : 'unknown';
}

/**
 * Add a single entry to all in-memory indexes.
 * @param {object} entry
 */
function addToIndexes(entry) {
    // id index — unique
    idIndex.set(entry.id, entry);

    // hostname index — grouped
    const host = entry.hostname || 'unknown';
    if (!hostnameIndex.has(host)) hostnameIndex.set(host, []);
    hostnameIndex.get(host).push(entry);

    // riskLevel index — grouped
    const level = entry.riskLevel || 'HIGH';
    if (!riskLevelIndex.has(level)) riskLevelIndex.set(level, []);
    riskLevelIndex.get(level).push(entry);

    // date index — grouped by day
    const dk = dateKey(entry.timestamp);
    if (!dateIndex.has(dk)) dateIndex.set(dk, []);
    dateIndex.get(dk).push(entry);
}

/**
 * Remove a single entry from all grouped indexes (hostname, riskLevel, date).
 * Called when entries are evicted due to MAX_LOCAL_ENTRIES cap.
 * @param {object} entry
 */
function removeFromIndexes(entry) {
    idIndex.delete(entry.id);

    const host = entry.hostname || 'unknown';
    if (hostnameIndex.has(host)) {
        const arr = hostnameIndex.get(host).filter(e => e.id !== entry.id);
        if (arr.length === 0) hostnameIndex.delete(host);
        else hostnameIndex.set(host, arr);
    }

    const level = entry.riskLevel || 'HIGH';
    if (riskLevelIndex.has(level)) {
        const arr = riskLevelIndex.get(level).filter(e => e.id !== entry.id);
        if (arr.length === 0) riskLevelIndex.delete(level);
        else riskLevelIndex.set(level, arr);
    }

    const dk = dateKey(entry.timestamp);
    if (dateIndex.has(dk)) {
        const arr = dateIndex.get(dk).filter(e => e.id !== entry.id);
        if (arr.length === 0) dateIndex.delete(dk);
        else dateIndex.set(dk, arr);
    }
}

/**
 * Rebuild all indexes from the threat array.
 * Called once on first load and after clearHistory().
 */
function rebuildIndexes() {
    idIndex.clear();
    hostnameIndex.clear();
    riskLevelIndex.clear();
    dateIndex.clear();

    for (const entry of threats) {
        addToIndexes(entry);
    }
}

// ─── STORAGE I/O ───────────────────────────────────────────────────────────────

/**
 * Load threats from Chrome storage and rebuild indexes.
 * Called lazily on the first query or write.
 * @returns {Promise<void>}
 */
async function ensureLoaded() {
    if (indexReady) return;

    threats = await new Promise((resolve) => {
        chrome.storage.local.get([STORAGE_KEY], (result) => {
            resolve(result[STORAGE_KEY] || []);
        });
    });

    rebuildIndexes();
    indexReady = true;
}

/**
 * Persist the current threat array to Chrome storage.
 * @returns {Promise<void>}
 */
async function persist() {
    return new Promise((resolve) => {
        chrome.storage.local.set({ [STORAGE_KEY]: threats }, resolve);
    });
}

// ─── PUBLIC API ────────────────────────────────────────────────────────────────

/**
 * Get all stored threat entries (array is sorted newest-first).
 * @returns {Promise<Array>}
 */
export async function getAllThreats() {
    await ensureLoaded();
    return threats;
}

/**
 * Insert a new threat entry. Maintains indexes and enforces the max-entries cap.
 * @param {object} entry — fully formed threat entry with id, timestamp, hostname, etc.
 * @returns {Promise<void>}
 */
export async function insertThreat(entry) {
    await ensureLoaded();

    // Prepend (newest first)
    threats.unshift(entry);
    addToIndexes(entry);

    // Evict oldest entries beyond the cap
    while (threats.length > MAX_LOCAL_ENTRIES) {
        const evicted = threats.pop();
        removeFromIndexes(evicted);
    }

    await persist();
}

/**
 * O(1) lookup: find a single threat by its unique ID.
 * Replaces the previous O(n) Array.find() in markUserProceeded.
 * @param {string} id
 * @returns {Promise<object|null>}
 */
export async function getThreatById(id) {
    await ensureLoaded();
    return idIndex.get(id) || null;
}

/**
 * O(1) lookup: get all threats for a specific hostname.
 * Useful for checking if a domain has been flagged before.
 * @param {string} hostname
 * @returns {Promise<Array>}
 */
export async function getThreatsByHostname(hostname) {
    await ensureLoaded();
    return hostnameIndex.get(hostname) || [];
}

/**
 * O(1) lookup: get all threats at a specific risk level.
 * Useful for dashboard filtering (e.g. show only CRITICAL threats).
 * @param {string} riskLevel — 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
 * @returns {Promise<Array>}
 */
export async function getThreatsByRiskLevel(riskLevel) {
    await ensureLoaded();
    return riskLevelIndex.get(riskLevel) || [];
}

/**
 * O(1) lookup: get all threats from a specific date.
 * Uses the date index keyed by YYYY-MM-DD.
 * @param {Date} date
 * @returns {Promise<Array>}
 */
export async function getThreatsForDate(date) {
    await ensureLoaded();
    const dk = date.toISOString().slice(0, 10);
    return dateIndex.get(dk) || [];
}

/**
 * Get threats detected today using the date index — O(1) instead of O(n) filter.
 * @returns {Promise<Array>}
 */
export async function getTodayThreats() {
    await ensureLoaded();
    const todayKey = new Date().toISOString().slice(0, 10);
    return dateIndex.get(todayKey) || [];
}

/**
 * Get threats within a date range using the date index.
 * Iterates only over the relevant day buckets.
 * @param {Date} startDate
 * @param {Date} endDate
 * @returns {Promise<Array>}
 */
export async function getThreatsByDateRange(startDate, endDate) {
    await ensureLoaded();
    const results = [];
    const startMs = startDate.getTime();
    const endMs = endDate.getTime();

    for (const [dk, entries] of dateIndex) {
        // Quick check: does this day bucket overlap the range?
        const bucketDate = new Date(dk).getTime();
        if (bucketDate >= startMs - 86400000 && bucketDate <= endMs) {
            for (const entry of entries) {
                const entryMs = new Date(entry.timestamp).getTime();
                if (entryMs >= startMs && entryMs <= endMs) {
                    results.push(entry);
                }
            }
        }
    }

    // Return sorted newest-first (consistent with getAllThreats ordering)
    results.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    return results;
}

/**
 * Get the N most recent threats — O(1) slice on the pre-sorted array.
 * @param {number} n
 * @returns {Promise<Array>}
 */
export async function getRecentThreats(n = 10) {
    await ensureLoaded();
    return threats.slice(0, n);
}

/**
 * Update a threat entry in-place and persist.
 * The entry is found via the idIndex in O(1).
 * @param {string} id
 * @param {object} updates — fields to merge into the entry
 * @returns {Promise<boolean>} — true if entry was found and updated
 */
export async function updateThreat(id, updates) {
    await ensureLoaded();
    const entry = idIndex.get(id);
    if (!entry) return false;

    // Track old values for re-indexing if grouped keys changed
    const oldLevel = entry.riskLevel;
    const oldHost = entry.hostname;

    Object.assign(entry, updates);

    // Re-index if grouped keys changed
    if (updates.riskLevel && updates.riskLevel !== oldLevel) {
        // Remove from old riskLevel bucket
        if (riskLevelIndex.has(oldLevel)) {
            const arr = riskLevelIndex.get(oldLevel).filter(e => e.id !== id);
            if (arr.length === 0) riskLevelIndex.delete(oldLevel);
            else riskLevelIndex.set(oldLevel, arr);
        }
        // Add to new bucket
        const newLevel = updates.riskLevel;
        if (!riskLevelIndex.has(newLevel)) riskLevelIndex.set(newLevel, []);
        riskLevelIndex.get(newLevel).push(entry);
    }

    if (updates.hostname && updates.hostname !== oldHost) {
        if (hostnameIndex.has(oldHost)) {
            const arr = hostnameIndex.get(oldHost).filter(e => e.id !== id);
            if (arr.length === 0) hostnameIndex.delete(oldHost);
            else hostnameIndex.set(oldHost, arr);
        }
        const newHost = updates.hostname;
        if (!hostnameIndex.has(newHost)) hostnameIndex.set(newHost, []);
        hostnameIndex.get(newHost).push(entry);
    }

    await persist();
    return true;
}

/**
 * Check if a hostname has been seen before — O(1).
 * Useful in background.js to skip re-scanning known-flagged domains.
 * @param {string} hostname
 * @returns {Promise<boolean>}
 */
export async function isHostnameFlagged(hostname) {
    await ensureLoaded();
    return hostnameIndex.has(hostname);
}

/**
 * Get count of threats by risk level — O(1).
 * @param {string} riskLevel
 * @returns {Promise<number>}
 */
export async function countByRiskLevel(riskLevel) {
    await ensureLoaded();
    const bucket = riskLevelIndex.get(riskLevel);
    return bucket ? bucket.length : 0;
}

/**
 * Clear all data and reset indexes.
 * @returns {Promise<void>}
 */
export async function clearAll() {
    threats = [];
    idIndex.clear();
    hostnameIndex.clear();
    riskLevelIndex.clear();
    dateIndex.clear();
    indexReady = false;
}
