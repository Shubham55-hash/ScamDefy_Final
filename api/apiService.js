/**
 * apiService.js — ScamDefy Centralized API Service
 *
 * FREE API STRATEGY:
 * ─────────────────────────────────────────────────────────────────
 * ✅ URLHaus (abuse.ch)      — 100% FREE, NO KEY, best malware/phishing DB
 * ✅ ThreatFox (abuse.ch)    — 100% FREE, NO KEY, IOC lookup
 * ✅ Google Safe Browsing    — FREE key (get in 2 min, 10k req/day)
 * ✅ Google Gemini           — FREE key (get in 1 min at aistudio.google.com)
 * ✅ IPQualityScore          — FREE key (5000 req/month free tier)
 * ✅ VirusTotal              — FREE key (500 req/day free tier), OPTIONAL
 *
 * HOW TO GET FREE KEYS (takes < 5 minutes):
 *   Google Safe Browsing: https://console.cloud.google.com → Enable API → Create Key
 *   Google Gemini:        https://aistudio.google.com/app/apikey
 *   IPQualityScore:       https://www.ipqualityscore.com/create-account
 *   VirusTotal (optional):https://www.virustotal.com/gui/join-us
 * ─────────────────────────────────────────────────────────────────
 */

// ─── API KEYS ─────────────────────────────────────────────────────────────────
// Replace these with your actual free keys. Leave as-is to use key-free APIs only.
const API_KEYS = {
    GOOGLE_SAFE_BROWSING: "AIzaSyAXyKJwCIgpyZVTFKBMTODooMAR4wCK1r8", // Get free: console.cloud.google.com (10k req/day free)
    VIRUSTOTAL: "a1b77b6412c4802028d23e00401de4462c0ce8038bee92d2eaebd116d2c01073", // Get free: virustotal.com/gui/join-us (500 req/day free, OPTIONAL)
    IPQUALITYSCORE: "Z5eXe0VldNwE2mchezXaUQnxUsT0xgjM", // Get free: ipqualityscore.com (5000 req/month free)
    GEMINI: "AIzaSyAe7BUVyKE8x4mSHhaH7MiYEFpJF7bTzDI", // Get free: aistudio.google.com/app/apikey (REQUIRED for AI explainer)
};

// ─── BACKEND URL (FastAPI on Render — for voice detection) ────────────────────
const BACKEND_URL = "https://your-scamdefy-backend.onrender.com";

// ─── FETCH HELPER ─────────────────────────────────────────────────────────────
async function safeFetch(url, options = {}, fallbackValue = null) {
    try {
        const response = await fetch(url, {
            ...options,
            signal: AbortSignal.timeout(8000),
        });
        if (!response.ok) {
            console.warn(`[ScamDefy] API call failed: ${response.status} — ${url.split('?')[0]}`);
            return fallbackValue;
        }
        return await response.json();
    } catch (err) {
        if (err.name === 'TimeoutError') {
            console.warn(`[ScamDefy] API timeout: ${url.split('?')[0]}`);
        } else {
            console.warn(`[ScamDefy] Fetch error: ${err.message}`);
        }
        return fallbackValue;
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  ❶ URLHAUS (abuse.ch) — 100% FREE, NO API KEY NEEDED
//  Largest open malware/phishing URL database. Updated every ~5 min.
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Check a URL against URLHaus malware database.
 * Completely free — no API key, no rate limit for lookups.
 * @param {string} url
 * @returns {Promise<{isThreat: boolean, threatType: string|null, source: string}>}
 */
export async function checkURLHaus(url) {
    const body = new URLSearchParams({ url });
    const result = await safeFetch(
        "https://urlhaus-api.abuse.ch/v1/url/",
        {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: body.toString(),
        },
        null
    );

    if (result && result.query_status === "is_online") {
        // URL is in URLHaus and is currently online (active threat)
        return {
            isThreat: true,
            threatType: result.tags ? result.tags.join(", ") : (result.threat || "malware"),
            urlStatus: result.url_status,
            firstSeen: result.date_added,
            source: "URLHaus (abuse.ch)",
        };
    }

    if (result && result.query_status === "is_offline") {
        // Was in database but now offline — still suspicious (score bump but no hard block)
        return {
            isThreat: false,
            wasListed: true,
            threatType: result.tags ? result.tags.join(", ") : null,
            source: "URLHaus (abuse.ch) — previously listed",
        };
    }

    // "no_results" or error → not in database
    return { isThreat: false, threatType: null, source: "URLHaus (abuse.ch)" };
}

// ═════════════════════════════════════════════════════════════════════════════
//  ❷ THREATFOX (abuse.ch) — 100% FREE, NO API KEY NEEDED
//  IOC (Indicator of Compromise) lookup database.
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Look up a domain or URL on ThreatFox IOC database.
 * Free, no key required.
 * @param {string} hostname
 * @returns {Promise<{isMalicious: boolean, malwareFamily: string|null, source: string}>}
 */
export async function checkThreatFox(hostname) {
    const body = JSON.stringify({ query: "search_ioc", search_term: hostname });

    const result = await safeFetch(
        "https://threatfox-api.abuse.ch/api/v1/",
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body,
        },
        null
    );

    if (result && result.query_status === "ok" && result.data && result.data.length > 0) {
        const entry = result.data[0];
        return {
            isMalicious: true,
            malwareFamily: entry.malware_printable || entry.malware || null,
            iocType: entry.ioc_type || null,
            confidence: entry.confidence_level || null,
            source: "ThreatFox (abuse.ch)",
        };
    }

    return { isMalicious: false, malwareFamily: null, source: "ThreatFox (abuse.ch)" };
}

// ═════════════════════════════════════════════════════════════════════════════
//  ❸ GOOGLE SAFE BROWSING — FREE KEY (10,000 req/day free tier)
//  Skipped automatically if no key is set.
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Check URL against Google Safe Browsing (requires free API key).
 * Get your free key: https://console.cloud.google.com → "Safe Browsing API"
 * @param {string} url
 * @returns {Promise<{isThreat: boolean, threatType: string|null, source: string}>}
 */
export async function checkGoogleSafeBrowsing(url) {
    if (!API_KEYS.GOOGLE_SAFE_BROWSING) {
        return { isThreat: false, threatType: null, source: "Google Safe Browsing (no key)" };
    }

    const body = {
        client: { clientId: "scamdefy", clientVersion: "1.0.0" },
        threatInfo: {
            threatTypes: [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }],
        },
    };

    const result = await safeFetch(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEYS.GOOGLE_SAFE_BROWSING}`,
        { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) },
        null
    );

    if (result && result.matches && result.matches.length > 0) {
        return {
            isThreat: true,
            threatType: result.matches[0].threatType,
            source: "Google Safe Browsing",
        };
    }
    return { isThreat: false, threatType: null, source: "Google Safe Browsing" };
}

// ═════════════════════════════════════════════════════════════════════════════
//  ❹ IPQUALITYSCORE — FREE KEY (5,000 req/month free tier)
//  Get free key: https://www.ipqualityscore.com/create-account
//  Skipped automatically if no key is set.
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Get domain reputation from IPQualityScore.
 * @param {string} url
 */
export async function checkIPQualityScore(url) {
    if (!API_KEYS.IPQUALITYSCORE) {
        return {
            riskScore: 0, domainAge: 9999, isMalicious: false,
            isSuspicious: false, isNewDomain: false, country: "Unknown",
            source: "IPQualityScore (no key — skipped)",
        };
    }

    const encodedUrl = encodeURIComponent(url);
    const result = await safeFetch(
        `https://www.ipqualityscore.com/api/json/url/${API_KEYS.IPQUALITYSCORE}/${encodedUrl}?strictness=1`,
        {},
        null
    );

    if (result && result.success) {
        return {
            riskScore: result.risk_score || 0,
            domainAge: result.domain_age || 9999,
            isMalicious: result.malware || result.phishing || false,
            isSuspicious: result.suspicious || false,
            isNewDomain: (result.domain_age || 9999) < 30,
            country: result.country_code || "Unknown",
            source: "IPQualityScore",
        };
    }
    return {
        riskScore: 0, domainAge: 9999, isMalicious: false,
        isSuspicious: false, isNewDomain: false, country: "Unknown",
        source: "IPQualityScore",
    };
}

// ═════════════════════════════════════════════════════════════════════════════
//  ❺ VIRUSTOTAL — FREE KEY (500 req/day, OPTIONAL)
//  Skipped automatically if no key is set.
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Scan URL with VirusTotal (optional, requires free key).
 * @param {string} url
 */
export async function checkVirusTotal(url) {
    if (!API_KEYS.VIRUSTOTAL) {
        return { maliciousCount: 0, totalEngines: 0, harmless: 0, source: "VirusTotal (no key — skipped)" };
    }

    const submitResult = await safeFetch(
        "https://www.virustotal.com/api/v3/urls",
        {
            method: "POST",
            headers: {
                "x-apikey": API_KEYS.VIRUSTOTAL,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body: `url=${encodeURIComponent(url)}`,
        },
        null
    );

    if (!submitResult || !submitResult.data) {
        return { maliciousCount: 0, totalEngines: 0, harmless: 0, source: "VirusTotal" };
    }

    await new Promise(resolve => setTimeout(resolve, 2000));

    // Use the ID from submission response
    const analysisId = submitResult.data.id;
    const report = await safeFetch(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        { headers: { "x-apikey": API_KEYS.VIRUSTOTAL } },
        null
    );

    if (report?.data?.attributes?.stats) {
        const s = report.data.attributes.stats;
        return {
            maliciousCount: s.malicious || 0,
            totalEngines: (s.malicious || 0) + (s.harmless || 0) + (s.undetected || 0),
            harmless: s.harmless || 0,
            source: "VirusTotal",
        };
    }
    return { maliciousCount: 0, totalEngines: 0, harmless: 0, source: "VirusTotal" };
}

// ═════════════════════════════════════════════════════════════════════════════
//  ❻ GEMINI AI EXPLANATION — FREE KEY (aistudio.google.com/app/apikey)
//  Falls back gracefully if no key.
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Generate scam explanation via Gemini (free key from AI Studio).
 * @param {string} prompt
 * @returns {Promise<string>}
 */
export async function generateScamExplanation(prompt) {
    if (!API_KEYS.GEMINI) {
        return null; // Triggers fallback in scamExplainer.js
    }

    const body = {
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.4, maxOutputTokens: 512, topP: 0.8 },
    };

    const result = await safeFetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${API_KEYS.GEMINI}`,
        { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) },
        null
    );

    return result?.candidates?.[0]?.content?.parts?.[0]?.text || null;
}

// ═════════════════════════════════════════════════════════════════════════════
//  ❼ VOICE DEEPFAKE BACKEND (FastAPI on Render)
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Send audio chunk to backend for HuggingFace deepfake detection.
 * @param {Blob} audioBlob
 */
export async function detectVoiceDeepfake(audioBlob) {
    const formData = new FormData();
    formData.append("audio", audioBlob, "chunk.webm");

    const result = await safeFetch(
        `${BACKEND_URL}/voice-detect`,
        { method: "POST", body: formData },
        null
    );

    if (result) {
        return {
            isDeepfake: result.label === "FAKE" || result.is_deepfake === true,
            confidence: result.confidence || 0,
            label: result.label || "UNKNOWN",
            source: "HuggingFace Voice Model",
        };
    }
    return { isDeepfake: false, confidence: 0, label: "UNKNOWN", source: "HuggingFace Voice Model" };
}

// ═════════════════════════════════════════════════════════════════════════════
//  LEGACY COMPATIBILITY (PhishTank replaced by URLHaus due to CORS blocks)
// ═════════════════════════════════════════════════════════════════════════════
/** @deprecated PhishTank blocks CORS from extensions. Use checkURLHaus instead. */
export async function checkPhishTank() {
    return { isPhishing: false, source: "PhishTank (disabled — CORS blocked)" };
}

export { API_KEYS, BACKEND_URL };
