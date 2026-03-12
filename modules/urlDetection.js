/**
 * urlDetection.js — ScamDefy URL Detection Module
 *
 * Uses free APIs:
 *  - URLHaus (abuse.ch) — 100% FREE, no key
 *  - ThreatFox (abuse.ch) — 100% FREE, no key
 *  - Google Safe Browsing — FREE key (optional, falls back gracefully)
 * Plus local heuristics that need no API at all.
 */

import { checkURLHaus, checkThreatFox, checkGoogleSafeBrowsing } from '../api/apiService.js';

// ─── SUSPICIOUS TLD LIST ──────────────────────────────────────────────────────
const SUSPICIOUS_TLDS = [
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top',
    '.club', '.online', '.site', '.info', '.biz', '.cc', '.su'
];

// ─── BRAND KEYWORDS ───────────────────────────────────────────────────────────
const BRAND_KEYWORDS = [
    'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix',
    'facebook', 'instagram', 'twitter', 'whatsapp', 'hdfc', 'sbi',
    'icici', 'axis', 'paytm', 'phonepe', 'binance', 'coinbase',
    'dropbox', 'adobe', 'linkedin', 'github', 'steam', 'youtube',
];

// ─── UTILITIES ────────────────────────────────────────────────────────────────
function extractHostname(url) {
    try { return new URL(url).hostname.toLowerCase(); } catch { return null; }
}

function isInsecureProtocol(url) {
    return url.startsWith('http://');
}

function hasSuspiciousTLD(hostname) {
    return SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld));
}

function detectBrandImpersonation(hostname) {
    for (const brand of BRAND_KEYWORDS) {
        if (hostname.includes(brand)) {
            const isReal =
                hostname === `${brand}.com` ||
                hostname === `www.${brand}.com` ||
                hostname.endsWith(`.${brand}.com`) ||
                hostname === `${brand}.co.in` ||
                hostname.endsWith(`.${brand}.co.in`);
            if (!isReal) return { detected: true, brand };
        }
    }
    return { detected: false, brand: null };
}

function isIPAddress(hostname) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
}

function hasExcessiveSubdomains(hostname) {
    return hostname.split('.').length > 4;
}

function hasObfuscation(url) {
    return (url.match(/%[0-9a-fA-F]{2}/g) || []).length > 5;
}

function hasRedirectPattern(url) {
    return ['redirect=', 'url=', 'goto=', 'next=', 'return=']
        .some(p => url.toLowerCase().includes(p));
}

// ─── MAIN SCAN FUNCTION ───────────────────────────────────────────────────────

/**
 * Full URL scan: local heuristics + URLHaus + ThreatFox + (optional) Safe Browsing
 * @param {string} url
 */
export async function scanURL(url) {
    const hostname = extractHostname(url);
    const reasons = [];

    // ── 1. Local heuristics (instant, zero API cost) ──
    const isInsecure = isInsecureProtocol(url);
    const isSuspiciousTLD = hostname ? hasSuspiciousTLD(hostname) : false;
    const isIP = hostname ? isIPAddress(hostname) : false;
    const hasExcessSubs = hostname ? hasExcessiveSubdomains(hostname) : false;
    const hasObfusc = hasObfuscation(url);
    const hasRedirect = hasRedirectPattern(url);
    const brandImpersonation = hostname
        ? detectBrandImpersonation(hostname)
        : { detected: false, brand: null };

    let heuristicScore = 0;
    if (isInsecure) { heuristicScore += 10; reasons.push('Uses insecure HTTP protocol'); }
    if (isSuspiciousTLD) { heuristicScore += 15; reasons.push(`Suspicious TLD (.${hostname.split('.').pop()})`); }
    if (isIP) { heuristicScore += 20; reasons.push('Uses raw IP address instead of domain'); }
    if (hasExcessSubs) { heuristicScore += 10; reasons.push('Unusually many subdomains'); }
    if (hasObfusc) { heuristicScore += 15; reasons.push('URL contains obfuscated characters'); }
    if (hasRedirect) { heuristicScore += 10; reasons.push('URL contains redirect parameters'); }
    if (brandImpersonation.detected) {
        heuristicScore += 25;
        reasons.push(`Possible impersonation of "${brandImpersonation.brand}"`);
    }

    // ── 2. Free API checks (parallel for speed) ──
    let urlHausResult = { isThreat: false };
    let threatFoxResult = { isMalicious: false };
    let googleSBResult = { isThreat: false };

    try {
        [urlHausResult, threatFoxResult, googleSBResult] = await Promise.all([
            checkURLHaus(url),
            hostname ? checkThreatFox(hostname) : Promise.resolve({ isMalicious: false }),
            checkGoogleSafeBrowsing(url), // auto-skips if no key
        ]);
    } catch (err) {
        console.warn('[ScamDefy] API checks failed, using heuristics only:', err.message);
    }

    return {
        url,
        hostname,
        isInsecure,
        isSuspiciousTLD,
        isIPAddress: isIP,
        hasExcessiveSubdomains: hasExcessSubs,
        hasObfuscation: hasObfusc,
        hasRedirectPattern: hasRedirect,
        brandImpersonation,
        // Free API results (replaces old PhishTank which was CORS-blocked)
        urlHaus: urlHausResult,
        threatFox: threatFoxResult,
        googleSafeBrowsing: googleSBResult,
        // Keep phishTank key for riskScorer compatibility
        phishTank: { isPhishing: urlHausResult.isThreat, source: "URLHaus" },
        heuristicScore,
        reasons,
    };
}

/**
 * Quick local-only check (no API) for hover previews in content.js.
 * @param {string} url
 */
export function quickLocalCheck(url) {
    const hostname = extractHostname(url);
    const reasons = [];
    let suspicious = false;

    if (!hostname) return { isSuspicious: false, reasons: [] };

    if (isInsecureProtocol(url)) { suspicious = true; reasons.push('Insecure HTTP'); }
    if (hasSuspiciousTLD(hostname)) { suspicious = true; reasons.push('Suspicious TLD'); }
    if (isIPAddress(hostname)) { suspicious = true; reasons.push('IP address URL'); }
    if (detectBrandImpersonation(hostname).detected) { suspicious = true; reasons.push('Possible brand impersonation'); }

    return { isSuspicious: suspicious, reasons };
}
