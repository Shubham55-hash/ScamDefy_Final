/**
 * riskScorer.js — ScamDefy Weighted Risk Scoring Engine
 *
 * Aggregates results from all detection modules and produces a final
 * risk level: LOW | MEDIUM | HIGH | CRITICAL
 */

// ─── RISK LEVELS ───────────────────────────────────────────────────────────────
export const RISK_LEVELS = {
    LOW: "LOW",
    MEDIUM: "MEDIUM",
    HIGH: "HIGH",
    CRITICAL: "CRITICAL",
};

// ─── SCORE WEIGHTS ─────────────────────────────────────────────────────────────
// Each signal contributes a weighted score (0–100 total scale)
const WEIGHTS = {
    googleSafeBrowsing: 35,    // Very high trust — Google's own blacklist
    phishTank: 30,             // High trust — community verified phishing
    ipqsRiskScore: 20,         // Medium trust — reputation scoring
    virusTotalMalicious: 25,   // High trust — multi-engine scanning
    newDomain: 15,             // Domain < 30 days old is suspicious
    suspiciousForm: 20,        // Login form submitting to foreign domain
    brandImpersonation: 25,    // Known brand impersonation detected
    sslInvalid: 15,            // No valid HTTPS
    ipqsSuspicious: 10,        // IPQualityScore suspicious flag
};

// ─── THRESHOLDS ────────────────────────────────────────────────────────────────
const THRESHOLDS = {
    LOW: 0,        // 0–24: safe to proceed
    MEDIUM: 25,    // 25–49: show a gentle warning
    HIGH: 50,      // 50–74: show a strong warning, suggest going back
    CRITICAL: 75,  // 75+: full page block
};

/**
 * Calculate a final risk score and risk level from all module results.
 *
 * @param {object} signals
 * @param {object} signals.urlResult       — from urlDetection.js
 * @param {object} signals.phishingResult  — from phishingDetection.js
 * @param {object} signals.ipqsResult      — from apiService checkIPQualityScore
 * @param {object} signals.vtResult        — from apiService checkVirusTotal
 *
 * @returns {{
 *   riskLevel: string,
 *   score: number,
 *   breakdown: object,
 *   shouldAlert: boolean,
 *   reasons: string[]
 * }}
 */
export function calculateRiskScore(signals = {}) {
    const {
        urlResult = {},
        phishingResult = {},
        ipqsResult = {},
        vtResult = {},
    } = signals;

    let totalScore = 0;
    const breakdown = {};
    const reasons = [];

    // 1. URLHaus (abuse.ch) — FREE, no key — replaces PhishTank
    if (urlResult.urlHaus && urlResult.urlHaus.isThreat) {
        totalScore += WEIGHTS.phishTank;
        breakdown.urlHaus = WEIGHTS.phishTank;
        reasons.push(`Listed in URLHaus malware database (${urlResult.urlHaus.threatType || 'malware/phishing'})`);
    }

    // 2. ThreatFox (abuse.ch) — FREE, no key — IOC database
    if (urlResult.threatFox && urlResult.threatFox.isMalicious) {
        totalScore += 20;
        breakdown.threatFox = 20;
        reasons.push(`Listed in ThreatFox IOC database (${urlResult.threatFox.malwareFamily || 'malware'})`);
    }

    // 3. Google Safe Browsing (optional free key — auto-skips if blank)
    if (urlResult.googleSafeBrowsing && urlResult.googleSafeBrowsing.isThreat) {
        totalScore += WEIGHTS.googleSafeBrowsing;
        breakdown.googleSafeBrowsing = WEIGHTS.googleSafeBrowsing;
        reasons.push(`Flagged by Google Safe Browsing as ${urlResult.googleSafeBrowsing.threatType || "a threat"}`);
    }

    // 4. Local heuristics (always runs — zero API cost)
    if (urlResult.heuristicScore > 0) {
        const hScore = Math.min(urlResult.heuristicScore, 30);
        totalScore += hScore;
        breakdown.heuristics = hScore;
        if (urlResult.reasons) {
            urlResult.reasons.forEach(r => { if (!reasons.includes(r)) reasons.push(r); });
        }
    }

    // 5. Brand impersonation from URL heuristics
    if (urlResult.brandImpersonation && urlResult.brandImpersonation.detected && !urlResult.heuristicScore) {
        totalScore += WEIGHTS.brandImpersonation;
        breakdown.brandImpersonation_url = WEIGHTS.brandImpersonation;
        reasons.push(`Possible impersonation of "${urlResult.brandImpersonation.brand}"`);
    }

    // 6. VirusTotal (optional free key — auto-skips if blank)
    if (vtResult.maliciousCount > 0) {
        const vtScore = Math.min(WEIGHTS.virusTotalMalicious, vtResult.maliciousCount * 5);
        totalScore += vtScore;
        breakdown.virusTotal = vtScore;
        reasons.push(`${vtResult.maliciousCount} antivirus engines flagged this URL`);
    }

    // 7. IPQualityScore (optional free key — auto-skips if blank)
    if (ipqsResult.riskScore > 75) {
        totalScore += WEIGHTS.ipqsRiskScore;
        breakdown.ipqsRisk = WEIGHTS.ipqsRiskScore;
        reasons.push(`High risk score (${ipqsResult.riskScore}/100) from IPQualityScore`);
    } else if (ipqsResult.riskScore > 50) {
        totalScore += Math.round(WEIGHTS.ipqsRiskScore / 2);
        breakdown.ipqsRisk = Math.round(WEIGHTS.ipqsRiskScore / 2);
        reasons.push(`Moderate risk score (${ipqsResult.riskScore}/100) from IPQualityScore`);
    }

    // 8. IPQS suspicious flag
    if (ipqsResult.isSuspicious) {
        totalScore += WEIGHTS.ipqsSuspicious;
        breakdown.ipqsSuspicious = WEIGHTS.ipqsSuspicious;
        reasons.push("Domain flagged as suspicious by IPQualityScore");
    }

    // 9. New domain (< 30 days old) — from IPQS or phishing module
    if (ipqsResult.isNewDomain || phishingResult.domainAgeRisk) {
        totalScore += WEIGHTS.newDomain;
        breakdown.newDomain = WEIGHTS.newDomain;
        const age = ipqsResult.domainAge || phishingResult.domainAgeDays || '?';
        reasons.push(`Domain is very new (${age} days old) — a common scam tactic`);
    }

    // 10. Suspicious login form (detected by content.js)
    if (phishingResult.hasSuspiciousForm) {
        totalScore += WEIGHTS.suspiciousForm;
        breakdown.suspiciousForm = WEIGHTS.suspiciousForm;
        reasons.push("Login form submits credentials to a foreign/suspicious server");
    }

    // 11. Brand impersonation (from phishing module page analysis)
    if (phishingResult.brandImpersonation && phishingResult.brandImpersonation.detected) {
        totalScore += WEIGHTS.brandImpersonation;
        breakdown.brandImpersonation = WEIGHTS.brandImpersonation;
        reasons.push(`Impersonating "${phishingResult.brandImpersonation.brand}" — a known brand`);
    }

    // 12. Invalid SSL
    if (phishingResult.sslInvalid) {
        totalScore += WEIGHTS.sslInvalid;
        breakdown.sslInvalid = WEIGHTS.sslInvalid;
        reasons.push("Website lacks a valid SSL/HTTPS certificate");
    }

    // Determine risk level
    let riskLevel;
    if (totalScore >= THRESHOLDS.CRITICAL) riskLevel = RISK_LEVELS.CRITICAL;
    else if (totalScore >= THRESHOLDS.HIGH) riskLevel = RISK_LEVELS.HIGH;
    else if (totalScore >= THRESHOLDS.MEDIUM) riskLevel = RISK_LEVELS.MEDIUM;
    else riskLevel = RISK_LEVELS.LOW;

    const shouldAlert = totalScore >= THRESHOLDS.HIGH;

    return { riskLevel, score: totalScore, breakdown, shouldAlert, reasons };
}


/**
 * Get a color for a risk level.
 * @param {string} riskLevel
 * @returns {string} CSS color
 */
export function getRiskColor(riskLevel) {
    const colors = {
        LOW: "#22c55e",
        MEDIUM: "#f59e0b",
        HIGH: "#ef4444",
        CRITICAL: "#7c3aed",
    };
    return colors[riskLevel] || "#6b7280";
}

/**
 * Get a user-facing label for a risk level.
 * @param {string} riskLevel
 * @returns {string}
 */
export function getRiskLabel(riskLevel) {
    const labels = {
        LOW: "Safe",
        MEDIUM: "Suspicious",
        HIGH: "Dangerous",
        CRITICAL: "Critical Threat",
    };
    return labels[riskLevel] || "Unknown";
}
