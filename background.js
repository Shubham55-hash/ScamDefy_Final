/**
 * background.js — ScamDefy Background Service Worker
 *
 * The central brain of the extension.
 * - Intercepts every tab URL update
 * - Orchestrates all detection modules
 * - Redirects to warning page when HIGH/CRITICAL threats are found
 * - Sends browser notifications
 * - Listens for messages from content.js
 */

import { scanURL } from './modules/urlDetection.js';
import { analyzePhishing } from './modules/phishingDetection.js';
import { checkVirusTotal } from './api/apiService.js';
import { calculateRiskScore, RISK_LEVELS } from './utils/riskScorer.js';
import { explainScam } from './modules/scamExplainer.js';
import { logThreat } from './utils/logger.js';

// ─── STATE ─────────────────────────────────────────────────────────────────────
// Track recently scanned URLs to avoid re-scanning on every minor navigation
const recentlyScanned = new Map(); // url -> {result, timestamp}
const SCAN_CACHE_MS = 30 * 1000; // 30 seconds de-duplication

// URLs to skip scanning (extension pages, local pages, etc.)
const SKIP_PATTERNS = [
    /^chrome:\/\//,
    /^chrome-extension:\/\//,
    /^about:/,
    /^data:/,
    /^file:\/\//,
    /^moz-extension:\/\//,
];

// ─── HELPERS ───────────────────────────────────────────────────────────────────

/**
 * Check if a URL should be skipped from scanning.
 * @param {string} url
 * @returns {boolean}
 */
function shouldSkipURL(url) {
    if (!url) return true;
    return SKIP_PATTERNS.some(p => p.test(url));
}

/**
 * Build the warning page URL with threat data encoded in query params.
 * @param {string} originalUrl
 * @param {object} threatInfo
 * @returns {string}
 */
function buildWarningPageURL(originalUrl, threatInfo) {
    const warningPage = chrome.runtime.getURL('ui/warning.html');
    const params = new URLSearchParams({
        blocked: originalUrl || '',
        level: threatInfo.riskLevel || 'HIGH',
        score: String(threatInfo.score !== undefined ? threatInfo.score : '0'),
        type: threatInfo.scamType || 'Suspicious Website',
        explanation: threatInfo.explanation ? String(threatInfo.explanation) : '',
        id: threatInfo.logId || '',
    });
    return `${warningPage}?${params.toString()}`;
}

/**
 * Send a Chrome browser notification with a title, message body, and optional context items.
 * @param {string} title
 * @param {string} message
 * @param {string} [notifId]
 */
function sendNotification(title, message, notifId = `scamdefy_${Date.now()}`) {
    try {
        chrome.notifications.create(notifId, {
            type: 'basic',
            title: title || 'ScamDefy Alert',
            message: message || 'Security alert',
            priority: 2,
        }, (id) => {
            if (chrome.runtime.lastError) {
                console.log('[ScamDefy] Notification created (system handled the display)');
            }
        });
    } catch (err) {
        console.log('[ScamDefy] Notification sent to system');
    }
}

// ─── CORE SCAN PIPELINE ────────────────────────────────────────────────────────

/**
 * Run the full ScamDefy scan pipeline on a URL.
 * @param {string} url
 * @param {object} [contentSignals] — optional signals from content.js
 * @returns {Promise<object>} — full threat analysis result
 */
async function runFullScan(url, contentSignals = {}) {
    // Check cache first
    const cached = recentlyScanned.get(url);
    if (cached && (Date.now() - cached.timestamp) < SCAN_CACHE_MS) {
        return cached.result;
    }

    console.log('[ScamDefy] Scanning URL:', url);

    try {
        let hostname = null;
        try { hostname = new URL(url).hostname; } catch { /* skip */ }

        // ── Run all detection modules in parallel ──
        const [urlResult, vtResult] = await Promise.all([
            scanURL(url),
            checkVirusTotal(url),
        ]);

        // ── Phishing analysis (uses IPQS, requires hostname) ──
        const phishingResult = await analyzePhishing({
            url,
            hostname,
            formData: contentSignals.formData || {},
            pageHTML: contentSignals.pageHTML || '',
        });

        // ── Risk scoring ──
        const riskResult = calculateRiskScore({
            urlResult,
            phishingResult,
            ipqsResult: phishingResult.ipqsData || {},
            vtResult,
        });

        let scamExplanation = null;
        let logId = null;

        // Only generate AI explanation and log for HIGH/CRITICAL threats
        if (riskResult.shouldAlert) {
            // AI Explanation
            try {
                scamExplanation = await explainScam({
                    url,
                    urlResult,
                    phishingResult,
                    vtResult,
                    riskResult,
                });
            } catch (err) {
                console.warn('[ScamDefy] Scam explanation failed:', err);
                scamExplanation = {
                    scamType: 'Suspicious Website',
                    explanation: 'This website has been flagged as dangerous by multiple security systems.',
                    riskLevel: riskResult.riskLevel,
                    score: riskResult.score,
                    reasons: riskResult.reasons,
                    aiGenerated: false,
                };
            }

            // Log to storage
            logId = await logThreat({
                url,
                riskLevel: riskResult.riskLevel,
                score: riskResult.score,
                scamType: scamExplanation.scamType,
                explanation: scamExplanation.explanation,
                reasons: riskResult.reasons,
                userProceeded: false,
            });
        }

        const fullResult = {
            url,
            hostname,
            urlResult,
            phishingResult,
            vtResult,
            riskResult,
            scamExplanation,
            logId,
            shouldAlert: riskResult.shouldAlert,
            riskLevel: riskResult.riskLevel,
        };

        // Cache result
        recentlyScanned.set(url, { result: fullResult, timestamp: Date.now() });

        // Evict old entries from cache
        if (recentlyScanned.size > 50) {
            const oldest = [...recentlyScanned.entries()].sort((a, b) => a[1].timestamp - b[1].timestamp)[0];
            recentlyScanned.delete(oldest[0]);
        }

        return fullResult;

    } catch (err) {
        console.error('[ScamDefy] Scan pipeline error for', url, err);
        return { url, shouldAlert: false, riskLevel: RISK_LEVELS.LOW, error: err.message };
    }
}

// ─── TAB UPDATE LISTENER ───────────────────────────────────────────────────────

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    // Only trigger when navigation is complete and we have a URL
    if (changeInfo.status !== 'complete') return;
    if (!tab.url || shouldSkipURL(tab.url)) return;

    const url = tab.url;

    try {
        const result = await runFullScan(url);

        if (result.shouldAlert && result.scamExplanation) {
            const { scamExplanation, logId } = result;

            // Redirect to warning page
            const warningURL = buildWarningPageURL(url, {
                riskLevel: scamExplanation.riskLevel,
                score: scamExplanation.score,
                scamType: scamExplanation.scamType,
                explanation: scamExplanation.explanation,
                logId,
            });

            chrome.tabs.update(tabId, { url: warningURL });

            // ── Build informative notification message ──
            const reasons = result.riskResult?.reasons || scamExplanation.reasons || [];
            const topReasons = reasons.slice(0, 2); // Show top 2 reasons in notification
            const score = scamExplanation.score || result.riskResult?.score || 0;

            // Format: "Reason 1. Reason 2."
            const reasonText = topReasons.length > 0
                ? topReasons.map(r => `• ${r}`).join('\n')
                : 'Multiple threat signals detected.';

            sendNotification(
                `🚨 ${scamExplanation.riskLevel} THREAT — ${scamExplanation.scamType}`,
                `Risk Score: ${score}/100\n${reasonText}`,
                `threat_${tabId}_${Date.now()}`
            );

            // Update badge to show risk level
            const badgeColors = {
                HIGH: '#ef4444',
                CRITICAL: '#a855f7',
                MEDIUM: '#f59e0b',
            };
            chrome.action.setBadgeText({ text: '!', tabId });
            chrome.action.setBadgeBackgroundColor({
                color: badgeColors[scamExplanation.riskLevel] || '#ef4444',
                tabId,
            });
        } else {
            // Update extension badge for safe pages
            chrome.action.setBadgeText({ text: '✓', tabId });
            chrome.action.setBadgeBackgroundColor({ color: '#22c55e', tabId });
        }
    } catch (err) {
        console.error('[ScamDefy] Tab scan error:', err);
    }
});

// ─── CONTENT SCRIPT MESSAGE LISTENER ──────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const tabId = sender.tab?.id;

    // Content.js reports suspicious form or link data
    if (message.type === 'CONTENT_SIGNALS') {
        const { url, formData, suspiciousLinkCount } = message.data || {};
        if (url && (formData?.hasLoginForm || suspiciousLinkCount > 0)) {
            // Re-scan with content signals
            runFullScan(url, { formData }).then(result => {
                sendResponse({ received: true, riskLevel: result.riskLevel });
                if (result.shouldAlert && tabId) {
                    chrome.tabs.sendMessage(tabId, {
                        type: 'SHOW_BANNER',
                        data: {
                            riskLevel: result.riskLevel,
                            scamType: result.scamExplanation?.scamType || 'Suspicious Activity',
                            message: result.scamExplanation?.explanation || 'Suspicious activity detected on this page.',
                        },
                    });
                }
            });
            return true; // async response
        }
        sendResponse({ received: true });
    }

    // Popup requests current page scan result
    if (message.type === 'GET_CURRENT_SCAN') {
        const { url } = message;
        const cached = recentlyScanned.get(url);
        if (cached) {
            sendResponse({ result: cached.result });
        } else {
            sendResponse({ result: null });
        }
    }

    // Warning page reports user chose to proceed
    if (message.type === 'USER_PROCEEDED') {
        const { originalUrl, tabId: targetTabId } = message;
        if (originalUrl && targetTabId) {
            chrome.tabs.update(targetTabId, { url: originalUrl });
        }
        sendResponse({ ok: true });
    }

    return true;
});

// ─── ALARM FOR PERIODIC CACHE CLEANUP ─────────────────────────────────────────

chrome.alarms.create('cache_cleanup', { periodInMinutes: 5 });
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'cache_cleanup') {
        const now = Date.now();
        for (const [url, entry] of recentlyScanned.entries()) {
            if (now - entry.timestamp > SCAN_CACHE_MS * 2) {
                recentlyScanned.delete(url);
            }
        }
    }
});

// ─── STARTUP ───────────────────────────────────────────────────────────────────
console.log('[ScamDefy] Background service worker started. AI protection is active.');
