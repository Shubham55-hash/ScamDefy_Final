/**
 * popup.js — ScamDefy Popup Dashboard Script
 *
 * - Shows current page safety status (safe/medium/high/critical)
 * - Displays today's blocked threats count + total stats
 * - Renders the recent threat history list
 * - All data pulled from chrome.storage via logger.js API
 */

(function () {
    'use strict';

    // ─── RISK CONFIG ──────────────────────────────────────────────────────────────
    const RISK_CONFIG = {
        LOW: { emoji: '✓', label: 'Safe', cssClass: 'safe', color: '#22c55e', scoreColor: '#22c55e' },
        MEDIUM: { emoji: '⚠', label: 'Suspicious', cssClass: 'medium', color: '#f59e0b', scoreColor: '#f59e0b' },
        HIGH: { emoji: '✕', label: 'Dangerous', cssClass: 'high', color: '#ef4444', scoreColor: '#ef4444' },
        CRITICAL: { emoji: '☠', label: 'Critical Risk', cssClass: 'critical', color: '#a855f7', scoreColor: '#a855f7' },
        SCANNING: { emoji: '⟳', label: 'Scanning...', cssClass: 'safe', color: '#6366f1', scoreColor: '#6366f1' },
    };

    // ─── DOM REFS ─────────────────────────────────────────────────────────────────
    const statusCard = document.getElementById('statusCard');
    const statusIndicator = document.getElementById('statusIndicator');
    const statusEmoji = document.getElementById('statusEmoji');
    const statusValue = document.getElementById('statusValue');
    const statusUrl = document.getElementById('statusUrl');
    const scoreDisplay = document.getElementById('scoreDisplay');
    const statBlocked = document.getElementById('statBlocked');
    const statTotal = document.getElementById('statTotal');
    const statDetected = document.getElementById('statDetected');
    const threatList = document.getElementById('threatList');
    const btnClearHistory = document.getElementById('btnClearHistory');

    // ─── HELPERS ──────────────────────────────────────────────────────────────────

    function applyRiskToStatus(riskLevel, score) {
        const cfg = RISK_CONFIG[riskLevel] || RISK_CONFIG.LOW;

        // Clear old class names
        statusCard.className = `status-card ${cfg.cssClass}`;
        statusIndicator.className = `status-indicator ${cfg.cssClass}`;
        statusEmoji.textContent = cfg.emoji;
        statusValue.className = `status-value ${cfg.cssClass}`;
        statusValue.textContent = cfg.label;
        statusValue.style.color = cfg.color;

        scoreDisplay.textContent = score !== undefined && score !== null ? `${score}` : '—';
        scoreDisplay.style.color = cfg.scoreColor;
    }

    function formatRelativeTime(isoString) {
        const date = new Date(isoString);
        const now = Date.now();
        const diff = now - date.getTime();

        if (diff < 60_000) return 'just now';
        if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
        if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
        return date.toLocaleDateString('en-IN', { month: 'short', day: 'numeric' });
    }

    function truncateURL(url, maxLen = 36) {
        if (!url || url.length <= maxLen) return url || '—';
        try {
            const { hostname, pathname } = new URL(url);
            const path = pathname.length > 12 ? pathname.substring(0, 10) + '…' : pathname;
            const display = hostname + path;
            return display.length > maxLen ? display.substring(0, maxLen - 1) + '…' : display;
        } catch {
            return url.substring(0, maxLen - 1) + '…';
        }
    }

    // ─── RENDER THREAT LIST ───────────────────────────────────────────────────────

    function renderThreatList(threats) {
        if (!threats || threats.length === 0) {
            threatList.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">🛡️</div>
          <div class="empty-state-text">No threats detected recently.<br>You're all clear!</div>
        </div>
      `;
            return;
        }

        threatList.innerHTML = threats.map(threat => {
            const cfg = RISK_CONFIG[threat.riskLevel] || RISK_CONFIG.HIGH;
            return `
        <div class="threat-item" title="${threat.url}">
          <span class="threat-badge ${threat.riskLevel}">${threat.riskLevel}</span>
          <div class="threat-info">
            <div class="threat-url">${truncateURL(threat.url)}</div>
            <div class="threat-meta">${threat.scamType || 'Unknown'} · ${threat.blocked ? '🚫 Blocked' : '⚠️ Warned'}</div>
          </div>
          <div class="threat-time">${formatRelativeTime(threat.timestamp)}</div>
        </div>
      `;
        }).join('');
    }

    // ─── LOAD STATS FROM STORAGE ──────────────────────────────────────────────────

    function loadStats() {
        // Get stats
        chrome.storage.local.get(['scamdefy_stats'], (result) => {
            const stats = result.scamdefy_stats || { totalBlocked: 0, totalDetected: 0 };
            animateCounter(statTotal, stats.totalBlocked || 0);
            animateCounter(statDetected, stats.totalDetected || 0);
        });

        // Get today's threats
        chrome.storage.local.get(['scamdefy_threat_log'], (result) => {
            const threats = result.scamdefy_threat_log || [];
            const todayStart = new Date();
            todayStart.setHours(0, 0, 0, 0);
            const todayThreats = threats.filter(t => new Date(t.timestamp) >= todayStart);
            animateCounter(statBlocked, todayThreats.length);

            // Render the most recent 15
            renderThreatList(threats.slice(0, 15));
        });
    }

    function animateCounter(el, target) {
        const duration = 600;
        const start = Date.now();
        const startVal = 0;
        const update = () => {
            const elapsed = Date.now() - start;
            const progress = Math.min(elapsed / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            el.textContent = Math.round(startVal + (target - startVal) * eased);
            if (progress < 1) requestAnimationFrame(update);
        };
        requestAnimationFrame(update);
    }

    // ─── QUERY CURRENT ACTIVE TAB ─────────────────────────────────────────────────

    function loadCurrentTabStatus() {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const tab = tabs[0];
            if (!tab || !tab.url) {
                applyRiskToStatus('LOW', null);
                statusUrl.textContent = 'No active tab';
                return;
            }

            const url = tab.url;

            // Show URL
            statusUrl.textContent = truncateURL(url, 38);

            // Skip chrome:// pages
            if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) {
                applyRiskToStatus('LOW', 0);
                statusValue.textContent = 'Browser Page';
                return;
            }

            // Ask background for cached scan result
            chrome.runtime.sendMessage({ type: 'GET_CURRENT_SCAN', url }, (response) => {
                if (chrome.runtime.lastError) {
                    applyRiskToStatus('LOW', 0);
                    return;
                }
                if (response && response.result) {
                    const result = response.result;
                    const level = result.riskLevel || 'LOW';
                    const score = result.riskResult?.score || 0;
                    applyRiskToStatus(level, score);
                } else {
                    // No cached result — show "Scanning" state briefly
                    applyRiskToStatus('LOW', 0);
                    statusValue.textContent = 'No scan yet';
                }
            });
        });
    }

    // ─── CLEAR HISTORY ────────────────────────────────────────────────────────────

    btnClearHistory.addEventListener('click', () => {
        if (!confirm('Clear all threat history? This cannot be undone.')) return;
        chrome.storage.local.remove(['scamdefy_threat_log', 'scamdefy_stats'], () => {
            loadStats();
            statBlocked.textContent = '0';
            statTotal.textContent = '0';
            statDetected.textContent = '0';
        });
    });

    // ─── INIT ─────────────────────────────────────────────────────────────────────

    function init() {
        loadCurrentTabStatus();
        loadStats();

        // Auto-refresh every 10 seconds (popup is short-lived, but good UX)
        setTimeout(loadCurrentTabStatus, 3000);
    }

    // Run on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
