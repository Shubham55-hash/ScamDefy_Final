/**
 * content.js — ScamDefy Content Script
 *
 * Injected into every webpage. Responsibilities:
 * 1. Scan all links on hover — flag dangerous ones with a red border
 * 2. Detect suspicious login forms (submitting to foreign domains)
 * 3. Show warning banners directly on the page
 * 4. Communicate findings back to background.js
 */

(function () {
    'use strict';

    // ─── CONSTANTS ───────────────────────────────────────────────────────────────
    const SUSPICIOUS_TLDS = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.club', '.online', '.site'];
    const BRAND_KEYWORDS = [
        'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix', 'facebook',
        'instagram', 'twitter', 'hdfc', 'sbi', 'icici', 'axis', 'paytm', 'phonepe',
    ];

    const SCAMDEFY_STYLE_ID = 'scamdefy-content-styles';
    let bannerInjected = false;
    let hasScannedForms = false;

    // ─── INJECT STYLES ──────────────────────────────────────────────────────────
    function injectStyles() {
        if (document.getElementById(SCAMDEFY_STYLE_ID)) return;
        const style = document.createElement('style');
        style.id = SCAMDEFY_STYLE_ID;
        style.textContent = `
      .scamdefy-suspicious-link {
        outline: 2px solid #ef4444 !important;
        outline-offset: 2px !important;
        border-radius: 2px !important;
        cursor: not-allowed !important;
        position: relative !important;
      }
      .scamdefy-link-tooltip {
        position: fixed;
        background: #1a1a2e;
        color: #ef4444;
        border: 1px solid #ef4444;
        border-radius: 6px;
        padding: 6px 10px;
        font-size: 12px;
        font-family: 'Segoe UI', system-ui, sans-serif;
        z-index: 2147483647;
        pointer-events: none;
        max-width: 280px;
        box-shadow: 0 4px 20px rgba(239, 68, 68, 0.3);
        white-space: nowrap;
      }
      .scamdefy-link-tooltip::before {
        content: '⚠️ ';
      }
      .scamdefy-warning-banner {
        position: fixed !important;
        top: 0;
        left: 0;
        right: 0;
        z-index: 2147483645 !important;
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border-bottom: 3px solid #ef4444;
        padding: 12px 20px;
        display: flex;
        align-items: center;
        gap: 12px;
        font-family: 'Segoe UI', system-ui, sans-serif;
        color: #fff;
        box-shadow: 0 4px 30px rgba(239, 68, 68, 0.4);
        animation: scamdefy-slide-down 0.3s ease;
      }
      @keyframes scamdefy-slide-down {
        from { transform: translateY(-100%); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
      }
      .scamdefy-banner-icon {
        font-size: 20px;
        flex-shrink: 0;
      }
      .scamdefy-banner-text {
        flex: 1;
      }
      .scamdefy-banner-title {
        font-size: 14px;
        font-weight: 700;
        color: #ef4444;
        margin-bottom: 2px;
      }
      .scamdefy-banner-message {
        font-size: 12px;
        color: #d1d5db;
        line-height: 1.4;
      }
      .scamdefy-banner-close {
        background: none;
        border: 1px solid #374151;
        color: #9ca3af;
        width: 28px;
        height: 28px;
        border-radius: 50%;
        cursor: pointer;
        font-size: 14px;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
        transition: all 0.2s;
      }
      .scamdefy-banner-close:hover {
        background: rgba(239,68,68,0.1);
        border-color: #ef4444;
        color: #ef4444;
      }
      .scamdefy-form-warning {
        background: rgba(239, 68, 68, 0.08);
        border: 2px solid #ef4444;
        border-radius: 8px;
        padding: 10px 14px;
        margin: 8px 0;
        font-family: 'Segoe UI', system-ui, sans-serif;
        font-size: 13px;
        color: #ef4444;
        display: flex;
        align-items: center;
        gap: 8px;
      }
    `;
        document.head.appendChild(style);
    }

    // ─── LOCAL URL HEURISTICS ───────────────────────────────────────────────────
    function extractHostname(url) {
        try { return new URL(url).hostname.toLowerCase(); } catch { return null; }
    }

    function isSuspiciousURL(url) {
        if (!url || url.startsWith('#') || url.startsWith('javascript:')) return false;
        const hostname = extractHostname(url);
        if (!hostname) return false;

        const hasBadTLD = SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld));
        const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
        const hasBrandImpersonation = BRAND_KEYWORDS.some(brand => {
            if (!hostname.includes(brand)) return false;
            const isReal = hostname === `${brand}.com` || hostname.endsWith(`.${brand}.com`);
            return !isReal;
        });
        const isInsecure = url.startsWith('http://') &&
            !hostname.includes('localhost') && !hostname.includes('127.0.0.1');

        return hasBadTLD || isIP || hasBrandImpersonation || isInsecure;
    }

    function getReasonForLink(url) {
        const hostname = extractHostname(url);
        if (!hostname) return 'Suspicious link';
        if (SUSPICIOUS_TLDS.some(t => hostname.endsWith(t))) return `Suspicious domain extension`;
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return 'IP address used instead of domain';
        if (BRAND_KEYWORDS.some(b => hostname.includes(b) && hostname !== `${b}.com`)) return 'Possible brand impersonation';
        if (url.startsWith('http://')) return 'Insecure HTTP connection';
        return 'Suspicious link detected';
    }

    // ─── TOOLTIP ──────────────────────────────────────────────────────────────
    let activeTooltip = null;

    function showTooltip(text, x, y) {
        removeTooltip();
        const tip = document.createElement('div');
        tip.className = 'scamdefy-link-tooltip';
        tip.textContent = text;
        tip.style.left = `${Math.min(x + 10, window.innerWidth - 300)}px`;
        tip.style.top = `${y - 40}px`;
        document.body.appendChild(tip);
        activeTooltip = tip;
    }

    function removeTooltip() {
        if (activeTooltip) {
            activeTooltip.remove();
            activeTooltip = null;
        }
    }

    // ─── LINK SCANNING ──────────────────────────────────────────────────────────
    function scanLinks() {
        const links = document.querySelectorAll('a[href]');
        let suspiciousCount = 0;

        links.forEach(link => {
            const href = link.getAttribute('href');
            let fullURL = href;
            try { fullURL = new URL(href, window.location.href).toString(); } catch { return; }

            if (isSuspiciousURL(fullURL)) {
                link.classList.add('scamdefy-suspicious-link');
                suspiciousCount++;

                const reason = getReasonForLink(fullURL);

                link.addEventListener('mouseenter', (e) => {
                    showTooltip(`ScamDefy Warning: ${reason}`, e.clientX, e.clientY);
                }, { passive: true });
                link.addEventListener('mouseleave', removeTooltip, { passive: true });
                link.addEventListener('mousemove', (e) => {
                    if (activeTooltip) {
                        activeTooltip.style.left = `${Math.min(e.clientX + 10, window.innerWidth - 300)}px`;
                        activeTooltip.style.top = `${e.clientY - 40}px`;
                    }
                }, { passive: true });

                // Block click with a confirmation
                link.addEventListener('click', (e) => {
                    const confirmed = window.confirm(
                        `⚠️ ScamDefy Warning\n\nThis link appears suspicious.\nReason: ${reason}\n\nURL: ${fullURL}\n\nDo you still want to proceed?`
                    );
                    if (!confirmed) e.preventDefault();
                });
            }
        });

        return suspiciousCount;
    }

    // ─── FORM DETECTION ──────────────────────────────────────────────────────────
    function detectLoginForms() {
        if (hasScannedForms) return null;
        hasScannedForms = true;

        const forms = document.querySelectorAll('form');
        const pageHostname = window.location.hostname.toLowerCase();
        let foundSuspicious = false;
        let formAction = null;
        let hasLoginForm = false;

        forms.forEach(form => {
            const inputs = form.querySelectorAll('input[type="password"], input[type="email"]');
            if (inputs.length === 0) return;

            hasLoginForm = true;
            formAction = form.getAttribute('action') || '';

            // Check if the form submits to a different domain
            if (formAction && !formAction.startsWith('#') && !formAction.startsWith('javascript:')) {
                try {
                    const actionURL = new URL(formAction, window.location.href);
                    const actionHost = actionURL.hostname.toLowerCase();
                    if (actionHost && actionHost !== pageHostname && !actionHost.endsWith(`.${pageHostname}`)) {
                        foundSuspicious = true;

                        // Insert a visible warning block above the form
                        const warning = document.createElement('div');
                        warning.className = 'scamdefy-form-warning';
                        warning.innerHTML = `⚠️ <strong>ScamDefy:</strong> This form sends your data to <strong>${actionHost}</strong> — not this website. This may be a credential theft attempt.`;
                        form.insertBefore(warning, form.firstChild);
                    }
                } catch { /* relative URL — safe */ }
            }
        });

        return { hasLoginForm, formAction, hasSuspiciousForm: foundSuspicious };
    }

    // ─── WARNING BANNER ──────────────────────────────────────────────────────────
    function showWarningBanner({ riskLevel, scamType, message }) {
        if (bannerInjected) return;
        bannerInjected = true;

        const levelColors = {
            CRITICAL: '#7c3aed',
            HIGH: '#ef4444',
            MEDIUM: '#f59e0b',
        };
        const color = levelColors[riskLevel] || '#ef4444';

        const banner = document.createElement('div');
        banner.className = 'scamdefy-warning-banner';
        banner.style.borderBottomColor = color;
        banner.innerHTML = `
      <span class="scamdefy-banner-icon">🛡️</span>
      <div class="scamdefy-banner-text">
        <div class="scamdefy-banner-title" style="color: ${color}">ScamDefy: ${riskLevel} Threat — ${scamType}</div>
        <div class="scamdefy-banner-message">${message || 'This page has been flagged as potentially dangerous.'}</div>
      </div>
      <button class="scamdefy-banner-close" title="Dismiss warning">✕</button>
    `;

        // Add body padding so content isn't hidden under banner
        document.body.style.paddingTop = '60px';

        banner.querySelector('.scamdefy-banner-close').addEventListener('click', () => {
            banner.remove();
            document.body.style.paddingTop = '';
            bannerInjected = false;
        });

        document.body.prepend(banner);
    }

    // ─── MESSAGE LISTENER ────────────────────────────────────────────────────────
    chrome.runtime.onMessage.addListener((message) => {
        if (message.type === 'SHOW_BANNER') {
            showWarningBanner(message.data);
        }
    });

    // ─── MUTATION OBSERVER (for SPAs that load content dynamically) ──────────────
    const observer = new MutationObserver(() => {
        scanLinks();
        if (!hasScannedForms) detectLoginForms();
    });

    // ─── INITIALIZATION ──────────────────────────────────────────────────────────
    function initialize() {
        injectStyles();

        const suspiciousLinkCount = scanLinks();
        const formData = detectLoginForms();

        // Report signals to background.js
        if (suspiciousLinkCount > 0 || (formData && formData.hasLoginForm)) {
            chrome.runtime.sendMessage({
                type: 'CONTENT_SIGNALS',
                data: {
                    url: window.location.href,
                    formData,
                    suspiciousLinkCount,
                },
            }).catch(() => { /* background may not be ready yet — ignore */ });
        }

        // Watch for dynamic content (React/Angular/Vue SPAs)
        observer.observe(document.body, {
            childList: true,
            subtree: true,
        });
    }

    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }
})();
