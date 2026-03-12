/**
 * scamExplainer.js — ScamDefy AI Scam Explanation Module
 *
 * Collects all risk signals from every detection module, builds a structured
 * prompt, calls Gemini via apiService.js, and returns a human-readable
 * explanation for the warning page.
 *
 * This is the "Scam Explainer" — our unique differentiating feature.
 */

import { generateScamExplanation } from '../api/apiService.js';

// ─── SCAM TYPE CLASSIFIER ──────────────────────────────────────────────────────

/**
 * Classify the type of scam based on detected signals.
 * @param {object} allSignals
 * @returns {string} scam type label
 */
function classifyScamType(allSignals) {
    const { urlResult = {}, phishingResult = {}, riskResult = {} } = allSignals;

    // Priority order — most specific first
    if (phishingResult.brandImpersonation && phishingResult.brandImpersonation.detected) {
        const brand = phishingResult.brandImpersonation.brand;
        const upperBrand = brand.charAt(0).toUpperCase() + brand.slice(1);
        return `${upperBrand} Impersonation Phishing`;
    }

    if (phishingResult.hasSuspiciousForm) {
        return 'Credential Harvesting Phishing';
    }

    if (urlResult.googleSafeBrowsing && urlResult.googleSafeBrowsing.threatType === 'MALWARE') {
        return 'Malware Distribution Site';
    }

    if (urlResult.googleSafeBrowsing && urlResult.googleSafeBrowsing.isThreat) {
        return 'Social Engineering / Phishing';
    }

    if (urlResult.phishTank && urlResult.phishTank.isPhishing) {
        return 'Known Phishing Site';
    }

    if (phishingResult.domainAgeRisk) {
        return 'Newly Registered Scam Domain';
    }

    const vtCount = allSignals.vtResult?.maliciousCount || 0;
    if (vtCount > 5) return 'Malicious Website';
    if (vtCount > 0) return 'Suspicious Website';

    return 'Suspicious Website';
}

// ─── PROMPT BUILDER ────────────────────────────────────────────────────────────

/**
 * Build a structured prompt for Gemini explaining what to explain.
 * @param {object} params
 * @param {string} params.url — the scam URL
 * @param {string} params.scamType — classified scam type
 * @param {string[]} params.reasons — all detected risk reasons
 * @param {string} params.riskLevel — LOW/MEDIUM/HIGH/CRITICAL
 * @param {number} params.score — numeric risk score
 * @returns {string} formatted prompt
 */
function buildExplanationPrompt({ url, scamType, reasons, riskLevel, score }) {
    const reasonsList = reasons.map((r, i) => `${i + 1}. ${r}`).join('\n');

    return `You are a cybersecurity assistant explaining a threat to a non-technical user.

A website has been flagged as DANGEROUS by ScamDefy's AI security system.

Website URL: ${url}
Scam Type: ${scamType}
Risk Level: ${riskLevel} (Score: ${score}/100)

Detected threat signals:
${reasonsList}

TASK: Write a clear, friendly 3-4 sentence explanation that:
1. Tells the user what TYPE of scam this is in simple language
2. Explains the most important 2-3 reasons WHY this site is dangerous  
3. States what HARM could happen if they proceed (e.g., "your banking password could be stolen")
4. Ends with a brief safety recommendation

Keep it under 100 words. Use plain language — no jargon. Be firm but not alarmist.
Do NOT start with "I" or "This website". Start with the scam type.`;
}

// ─── FALLBACK EXPLANATIONS ─────────────────────────────────────────────────────

const FALLBACK_EXPLANATIONS = {
    'Credential Harvesting Phishing':
        'This is a credential theft scam — a fake website designed to steal your login details. The login form on this page sends your username and password to criminals, not to a legitimate service. Your account could be compromised immediately if you proceed.',
    'Malware Distribution Site':
        'This site attempts to install malicious software on your device. Visiting or downloading from it could give attackers access to your files, passwords, and sensitive data. Do not proceed.',
    'Known Phishing Site':
        'This URL is a verified phishing website listed in global threat databases. It is designed to trick you into giving away personal or financial information. Block and report this site.',
    DEFAULT:
        'This site has been flagged as dangerous by multiple AI security systems. It may attempt to steal your credentials, install malware, or defraud you. We strongly recommend you go back to safety.',
};

/**
 * Get a fallback explanation if AI fails.
 * @param {string} scamType
 * @returns {string}
 */
function getFallbackExplanation(scamType) {
    return FALLBACK_EXPLANATIONS[scamType] || FALLBACK_EXPLANATIONS.DEFAULT;
}

// ─── MAIN EXPLAINER FUNCTION ───────────────────────────────────────────────────

/**
 * Generate a full scam explanation from all risk signals.
 *
 * @param {object} allSignals
 * @param {string} allSignals.url
 * @param {object} allSignals.urlResult        — from urlDetection
 * @param {object} allSignals.phishingResult   — from phishingDetection
 * @param {object} allSignals.vtResult         — from VirusTotal
 * @param {object} allSignals.riskResult       — from riskScorer
 *
 * @returns {Promise<{
 *   scamType: string,
 *   explanation: string,
 *   riskLevel: string,
 *   score: number,
 *   reasons: string[],
 *   aiGenerated: boolean
 * }>}
 */
export async function explainScam(allSignals) {
    const { url = '', riskResult = {} } = allSignals;
    const riskLevel = riskResult.riskLevel || 'HIGH';
    const score = riskResult.score || 50;
    const reasons = riskResult.reasons || [];

    // Classify the scam type
    const scamType = classifyScamType(allSignals);

    // Build prompt
    const prompt = buildExplanationPrompt({ url, scamType, reasons, riskLevel, score });

    let explanation;
    let aiGenerated = false;

    try {
        const aiExplanation = await generateScamExplanation(prompt);
        if (aiExplanation && aiExplanation.trim().length > 20) {
            explanation = aiExplanation.trim();
            aiGenerated = true;
        } else {
            explanation = getFallbackExplanation(scamType);
        }
    } catch (err) {
        console.warn('[ScamDefy] AI explanation failed, using fallback:', err);
        explanation = getFallbackExplanation(scamType);
    }

    return {
        scamType,
        explanation,
        riskLevel,
        score,
        reasons,
        aiGenerated,
    };
}
