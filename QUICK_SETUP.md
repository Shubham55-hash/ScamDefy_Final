# Quick Setup Guide - ScamDefy Risk Scoring

## Problem Summary
✗ Risk Score showing as "-/100"  
✗ Risk issues not displayed  
✗ Limited threat detection  

**Root Cause**: All API keys in `apiService.js` are empty strings

---

## Quick Fix (5 Minutes)

### Step 1: Get Free API Keys
Get these **completely free** keys (no credit card needed):

| API | Time | Link | Free Tier |
|-----|------|------|-----------|
| Google Safe Browsing | 2 min | [console.cloud.google.com](https://console.cloud.google.com) | 10k/day |
| IPQualityScore | 1 min | [ipqualityscore.com](https://www.ipqualityscore.com/create-account) | 5k/month |
| Google Gemini | 1 min | [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey) | Unlimited |
| VirusTotal | 1 min | [virustotal.com](https://www.virustotal.com/gui/join-us) | 500/day (optional) |

---

### Step 2: Add Keys to apiService.js

**Current State (Line 24-29 in apiService.js)**:
```javascript
const API_KEYS = {
    GOOGLE_SAFE_BROWSING: "",
    VIRUSTOTAL: "",
    IPQUALITYSCORE: "",
    GEMINI: "",
};
```

**After Fix**:
```javascript
const API_KEYS = {
    GOOGLE_SAFE_BROWSING: "YOUR_GOOGLE_SAFE_BROWSING_KEY",  // Get from console.cloud.google.com
    VIRUSTOTAL: "YOUR_VIRUSTOTAL_KEY",                        // Optional - get from virustotal.com
    IPQUALITYSCORE: "YOUR_IPQS_KEY",                          // Get from ipqualityscore.com
    GEMINI: "YOUR_GEMINI_KEY",                                // Get from aistudio.google.com
};
```

---

### Step 3: Reload Extension
1. Go to `chrome://extensions`
2. Find "ScamDefy" extension
3. Click refresh icon or toggle off/on

---

### Step 4: Test
1. Visit a phishing URL: [openphish.com/browse.php](https://openphish.com/browse.php) (pick any)
2. You should see:
   - ✓ Warning page triggers
   - ✓ Risk score shows (e.g., "75/100")
   - ✓ Risk issues listed
   - ✓ AI explanation generated

---

## For Production Deployment

If you want to enhance the detection further, make these optional improvements:

### Add Risk Reasons to Warning Page
This will display WHY a site was flagged.

**File**: `background.js` - Update line 207-213:

Replace:
```javascript
const warningURL = buildWarningPageURL(url, {
    riskLevel: scamExplanation.riskLevel,
    score: scamExplanation.score,
    scamType: scamExplanation.scamType,
    explanation: scamExplanation.explanation,
    logId,
});
```

With:
```javascript
const warningURL = buildWarningPageURL(url, {
    riskLevel: scamExplanation.riskLevel,
    score: scamExplanation.score,
    scamType: scamExplanation.scamType,
    explanation: scamExplanation.explanation,
    reasons: JSON.stringify(result.riskResult?.reasons || []),
    logId,
});
```

---

**File**: `apiService.js` - Update buildWarningPageURL function (line 50-60):

Replace function to include `reasons`:
```javascript
function buildWarningPageURL(originalUrl, threatInfo) {
    const warningPage = chrome.runtime.getURL('ui/warning.html');
    const params = new URLSearchParams({
        blocked: originalUrl,
        level: threatInfo.riskLevel || 'HIGH',
        score: String(threatInfo.score || 0),
        type: threatInfo.scamType || 'Suspicious Website',
        explanation: threatInfo.explanation || '',
        reasons: threatInfo.reasons || '[]',
        id: threatInfo.logId || '',
    });
    return `${warningPage}?${params.toString()}`;
}
```

---

## Troubleshooting

### Risk Score Still "-/100"?
1. Check if URL is actually phishing (try [openphish.com](https://openphish.com/) URL)
2. Check if keys are properly added
3. Check browser console (F12 → Extensions → Service Worker) for errors
4. Reload extension again

### APIs Getting Rate Limited?
Set higher API call delays in `background.js`:
```javascript
// Add delay between API calls
await new Promise(r => setTimeout(r, 500)); // 500ms delay
```

### Want Disable Certain APIs?
Leave the key empty for APIs you don't want:
```javascript
IPQUALITYSCORE: "",  // Disabled - will skip
GEMINI: "your_key",  // Enabled
```

---

## Verification

After setup, you should see in Chrome DevTools (F12 → Service Worker):
```
[ScamDefy] Scanning URL: https://example-phishing.com
[ScamDefy] Risk Score: 85/100
[ScamDefy] Threats: Phishing Website Detected
```

✓ If you see this → System is working correctly!

---

## Next Steps

1. ✓ Add API keys (5 min)
2. ✓ Test with phishing URL (1 min)  
3. ✓ Optional: Add risk reasons to warning page (5 min)
4. ✓ Deploy with confidence!

Questions? See [ISSUES_AND_SOLUTIONS.md](ISSUES_AND_SOLUTIONS.md) for full technical details.
