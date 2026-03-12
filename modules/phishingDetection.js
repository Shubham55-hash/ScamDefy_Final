/**
 * phishingDetection.js — ScamDefy Phishing Detection Module
 *
 * Analyzes a loaded webpage for phishing signs:
 * SSL status, domain age, fake login forms, brand impersonation patterns.
 * Designed to run in the background service worker context.
 */

import { checkIPQualityScore } from '../api/apiService.js';

// ─── KNOWN LEGITIMATE DOMAINS (whitelist) ──────────────────────────────────────
const WHITELIST = new Set([
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'linkedin.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'paypal.com', 'netflix.com', 'wikipedia.org', 'stackoverflow.com', 'reddit.com',
    'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'paytm.com',
    'phonepe.com', 'npci.org.in', 'rbi.org.in',
]);

/**
 * Check if a hostname is whitelisted (known good domain).
 * @param {string} hostname
 * @returns {boolean}
 */
function isWhitelisted(hostname) {
    if (!hostname) return false;
    const clean = hostname.replace(/^www\./, '');
    return WHITELIST.has(clean);
}

/**
 * Check SSL — a URL starting with https:// is considered SSL-valid for our purposes.
 * In reality, the browser already enforces this, so we use the protocol.
 * @param {string} url
 * @returns {boolean} true if SSL invalid
 */
function checkSSLInvalid(url) {
    try {
        return new URL(url).protocol !== 'https:';
    } catch {
        return true;
    }
}

// ─── FAKE LOGIN FORM DETECTION ─────────────────────────────────────────────────
// This runs in content.js context but the result is passed here for scoring.
// We also include a utility to evaluate content.js's reported form data.

/**
 * Evaluate a form's submission target for phishing indicators.
 * @param {string} formAction — the form's action URL
 * @param {string} pageHostname — the current page's hostname
 * @returns {{isSuspicious: boolean, reason: string|null}}
 */
export function evaluateFormAction(formAction, pageHostname) {
    if (!formAction) return { isSuspicious: false, reason: null };

    try {
        const actionUrl = new URL(formAction, `https://${pageHostname}`);
        const actionHost = actionUrl.hostname.toLowerCase();
        const pageHost = pageHostname.toLowerCase();

        // Form submits to a completely different domain
        if (actionHost && actionHost !== pageHost && !actionHost.endsWith(`.${pageHost}`)) {
            return {
                isSuspicious: true,
                reason: `Form submits to foreign domain: ${actionHost}`,
            };
        }

        // Form submits via HTTP even if page is HTTPS
        if (actionUrl.protocol === 'http:') {
            return {
                isSuspicious: true,
                reason: 'Form submits credentials over insecure HTTP connection',
            };
        }
    } catch {
        // Relative URL — not suspicious
    }

    return { isSuspicious: false, reason: null };
}

// ─── VISUAL CLONING INDICATORS ─────────────────────────────────────────────────
// Detect patterns commonly used by phishing kits that clone real sites.

const CLONING_INDICATORS = [
    { pattern: /cloudflare\.com\/cdn-cgi/i, label: 'Cloudflare caching (common in phishing kits)' },
    { pattern: /bootstrapcdn\.com/i, label: 'Bootstrap CDN (common in cloned sites)' },
];

/**
 * Check page HTML for visual cloning indicator patterns.
 * @param {string} pageHTML
 * @returns {{detected: boolean, indicators: string[]}}
 */
export function detectCloningIndicators(pageHTML) {
    const found = [];
    for (const { pattern, label } of CLONING_INDICATORS) {
        if (pattern.test(pageHTML)) found.push(label);
    }
    return { detected: found.length > 0, indicators: found };
}

// ─── MAIN PHISHING ANALYSIS FUNCTION ──────────────────────────────────────────

/**
 * Run full phishing analysis on a URL and its content signals.
 *
 * @param {object} params
 * @param {string} params.url — page URL
 * @param {string} params.hostname — extracted hostname
 * @param {object} [params.formData] — from content.js: { hasLoginForm, formAction }
 * @param {string} [params.pageHTML] — optional page source for cloning detection
 *
 * @returns {Promise<{
 *   sslInvalid: boolean,
 *   isWhitelisted: boolean,
 *   domainAgeDays: number,
 *   domainAgeRisk: boolean,
 *   hasSuspiciousForm: boolean,
 *   formReason: string|null,
 *   brandImpersonation: object,
 *   cloningDetected: boolean,
 *   ipqsData: object,
 *   overallPhishingScore: number,
 *   reasons: string[]
 * }>}
 */
export async function analyzePhishing({ url, hostname, formData = {}, pageHTML = '' }) {
    const reasons = [];
    let overallPhishingScore = 0;

    // Whitelist check — skip deep analysis for known-good domains
    if (isWhitelisted(hostname)) {
        return {
            sslInvalid: false,
            isWhitelisted: true,
            domainAgeDays: 9999,
            domainAgeRisk: false,
            hasSuspiciousForm: false,
            formReason: null,
            brandImpersonation: { detected: false, brand: null },
            cloningDetected: false,
            ipqsData: {},
            overallPhishingScore: 0,
            reasons: [],
        };
    }

    // 1. SSL check
    const sslInvalid = checkSSLInvalid(url);
    if (sslInvalid) {
        overallPhishingScore += 15;
        reasons.push('No valid HTTPS/SSL certificate');
    }

    // 2. IPQS domain analysis (domain age, reputation)
    let ipqsData = {};
    try {
        ipqsData = await checkIPQualityScore(url);
        if (ipqsData.isNewDomain) {
            overallPhishingScore += 20;
            reasons.push(`Domain is only ${ipqsData.domainAge} days old — brand new domains are a red flag`);
        }
        if (ipqsData.isMalicious) {
            overallPhishingScore += 30;
            reasons.push('Domain is on IPQualityScore malware/phishing list');
        }
        if (ipqsData.isSuspicious) {
            overallPhishingScore += 10;
            reasons.push('Domain has suspicious reputation on IPQualityScore');
        }
    } catch (err) {
        console.warn('[ScamDefy] IPQS check failed:', err);
    }

    // 3. Login form analysis
    let hasSuspiciousForm = false;
    let formReason = null;
    if (formData && formData.hasLoginForm) {
        const formEval = evaluateFormAction(formData.formAction, hostname);
        if (formEval.isSuspicious) {
            hasSuspiciousForm = true;
            formReason = formEval.reason;
            overallPhishingScore += 25;
            reasons.push(formReason);
        }
    }

    // 4. Visual cloning detection
    let cloningDetected = false;
    if (pageHTML) {
        const cloneResult = detectCloningIndicators(pageHTML);
        cloningDetected = cloneResult.detected;
        if (cloningDetected) {
            overallPhishingScore += 10;
            reasons.push('Page contains indicators of a cloned/copied website template');
        }
    }

    // 5. Brand impersonation (re-checked at page level using hostname)
    const brandImpersonation = { detected: false, brand: null };
    const brands = [
        'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix',
        'hdfc', 'sbi', 'icici', 'axis', 'paytm', 'phonepe',
    ];
    if (hostname) {
        for (const brand of brands) {
            if (hostname.includes(brand)) {
                const isReal = hostname === `${brand}.com` || hostname.endsWith(`.${brand}.com`) ||
                    hostname === `${brand}.co.in` || hostname.endsWith(`.${brand}.co.in`);
                if (!isReal) {
                    brandImpersonation.detected = true;
                    brandImpersonation.brand = brand;
                    overallPhishingScore += 25;
                    reasons.push(`Domain impersonates "${brand}" — a major brand`);
                    break;
                }
            }
        }
    }

    return {
        sslInvalid,
        isWhitelisted: false,
        domainAgeDays: ipqsData.domainAge || 9999,
        domainAgeRisk: ipqsData.isNewDomain || false,
        hasSuspiciousForm,
        formReason,
        brandImpersonation,
        cloningDetected,
        ipqsData,
        overallPhishingScore,
        reasons,
    };
}
