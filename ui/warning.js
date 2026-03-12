/**
 * warning.js — Warning page logic
 * Handles threat detection display and user actions
 */

(function () {
    'use strict';

    // ── Read URL params ───────────────────────────────────────────────────────
    const params = new URLSearchParams(window.location.search);
    const blockedURL  = params.get('blocked')     || '';
    const riskLevel   = params.get('level')        || 'HIGH';
    const scoreParam  = params.get('score');
    const score       = scoreParam ? parseInt(scoreParam, 10) : 70;
    const scamType    = params.get('type')         || 'Suspicious Website';
    const explanation = params.get('explanation')  || '';
    const logId       = params.get('id')           || '';
    
    // Debug: Log params to console
    console.log('[ScamDefy Warning] URL Params:', {
        blockedURL,
        riskLevel,
        score,
        scamType,
        explanation: explanation ? explanation.substring(0, 50) + '...' : '(empty)',
        logId,
    });

    // ── Apply risk level styling ──────────────────────────────────────────────
    const card       = document.getElementById('warningCard');
    const shield     = document.getElementById('warningShield');
    const levelBadge = document.getElementById('levelBadge');
    const levelText  = document.getElementById('levelText');
    const scamTypeEl = document.getElementById('scamTypeText');
    const scoreVal   = document.getElementById('riskScoreValue');
    const barFill    = document.getElementById('riskBarFill');
    const aiBadge    = document.getElementById('aiBadge');

    const riskConfig = {
        LOW      : { icon: '✅', label: 'LOW RISK',      color: '#22c55e', barClass: 'LOW'      },
        MEDIUM   : { icon: '⚠️', label: 'MEDIUM RISK',   color: '#f59e0b', barClass: 'MEDIUM'   },
        HIGH     : { icon: '⚠️', label: 'HIGH RISK',     color: '#ef4444', barClass: 'HIGH'     },
        CRITICAL : { icon: '☠️',  label: 'CRITICAL RISK', color: '#a855f7', barClass: 'CRITICAL' },
    };

    const cfg = riskConfig[riskLevel] || riskConfig.HIGH;

    shield.textContent = cfg.icon;
    shield.classList.toggle('critical', riskLevel === 'CRITICAL');
    levelBadge.style.color       = cfg.color;
    levelBadge.style.borderColor = `${cfg.color}55`;
    levelBadge.style.background  = `${cfg.color}18`;
    levelBadge.classList.add(riskLevel);
    levelText.textContent = cfg.label;

    scamTypeEl.textContent = scamType;
    scamTypeEl.classList.toggle('CRITICAL', riskLevel === 'CRITICAL');
    if (riskLevel === 'CRITICAL') {
        card.classList.add('critical');
    }

    // ── Risk score ────────────────────────────────────────────────────────────
    scoreVal.textContent = `${score}/100`;
    scoreVal.classList.toggle('CRITICAL', riskLevel === 'CRITICAL');
    barFill.classList.add(cfg.barClass);
    // Animate bar after a short delay
    setTimeout(() => { barFill.style.width = `${Math.min(score, 100)}%`; }, 200);

    // ── Blocked URL ───────────────────────────────────────────────────────────
    const blockedUrlEl = document.getElementById('blockedUrl');
    if (blockedURL) {
        blockedUrlEl.textContent = blockedURL.length > 70 ? blockedURL.substring(0, 67) + '…' : blockedURL;
        blockedUrlEl.title = blockedURL; // Full URL in tooltip
    } else {
        blockedUrlEl.textContent = '(URL not available)';
        blockedUrlEl.style.color = '#9ca3af';
    }

    // ── Explanation ───────────────────────────────────────────────────────────
    const explainEl = document.getElementById('explanationText');
    if (explanation) {
        explainEl.textContent = explanation;
        aiBadge.textContent = '✨ GEMINI AI';
    } else {
        explainEl.textContent = 'This website has been flagged as potentially dangerous by multiple AI security systems. Our threat intelligence detected suspicious patterns that are commonly associated with scam and phishing operations. Do not enter any personal or financial information on this site.';
        aiBadge.textContent = 'FALLBACK';
        aiBadge.style.background = '#374151';
    }

    // ── Signals from URL params — decode stored reasons if present ────────
    // (For now, reasons are embedded in the explanation. Future: pass as encoded JSON)
    // We can show a couple of static detected signals derived from context
    const signalsSection = document.getElementById('signalsSection');
    const signalsList = document.getElementById('signalsList');
    const autoSignals = [];

    if (riskLevel === 'HIGH' || riskLevel === 'CRITICAL') {
        if (scamType.toLowerCase().includes('phish')) autoSignals.push('Detected in phishing threat databases');
        if (scamType.toLowerCase().includes('impersonat')) autoSignals.push('Domain impersonates a well-known brand');
        if (scamType.toLowerCase().includes('credential')) autoSignals.push('Login form sends data to external server');
        if (scamType.toLowerCase().includes('new') || scamType.toLowerCase().includes('domain')) autoSignals.push('Domain registered within the last 30 days');
        if (autoSignals.length === 0) autoSignals.push('Multiple security engines flagged this URL');
        autoSignals.push(`Risk score: ${score}/100 — exceeds danger threshold`);
    }

    if (autoSignals.length > 0) {
        signalsSection.style.display = 'block';
        autoSignals.forEach(sig => {
            const li = document.createElement('li');
            li.className = 'signal-item';
            li.textContent = sig;
            signalsList.appendChild(li);
        });
    }

    // ── Buttons ───────────────────────────────────────────────────────────────
    document.getElementById('btnGoBack').addEventListener('click', () => {
        window.history.length > 1 ? window.history.back() : window.close();
    });

    document.getElementById('btnProceed').addEventListener('click', () => {
        if (!blockedURL) return;
        const confirmed = window.confirm(
            `⚠️ ScamDefy Warning\n\nYou are about to visit a site flagged as:\n${scamType}\n\nRisk Score: ${score}/100\n\nProceeding may put your personal data at risk.\n\nAre you sure you want to continue?`
        );
        if (confirmed) {
            // Notify background to log that user proceeded
            chrome.runtime.sendMessage({
                type: 'USER_PROCEEDED',
                originalUrl: blockedURL,
                logId,
            });
        }
    });
})();
