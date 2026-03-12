/**
 * voiceDetection.js — ScamDefy Voice Deepfake Detection Module
 *
 * Captures audio from the tab's media stream (if available),
 * sends audio chunks to the FastAPI backend which runs the HuggingFace
 * deepfake detection model, and returns a verdict.
 *
 * NOTE: Voice detection requires explicit user permission for microphone/tab audio.
 * This module works in background.js context via chrome.tabCapture API.
 */

import { detectVoiceDeepfake } from '../api/apiService.js';

// ─── STATE ─────────────────────────────────────────────────────────────────────
let mediaRecorder = null;
let audioChunks = [];
let isRecording = false;
let analysisInterval = null;

// ─── CONSTANTS ─────────────────────────────────────────────────────────────────
const CHUNK_INTERVAL_MS = 5000;    // Analyze every 5 seconds
const MIN_CHUNK_SIZE_BYTES = 1024; // Minimum meaningful audio chunk

// ─── AUDIO STREAM CAPTURE ──────────────────────────────────────────────────────

/**
 * Start capturing audio from the active tab.
 * Uses chrome.tabCapture.capture (requires 'tabCapture' permission).
 *
 * @param {number} tabId — the active tab to capture
 * @param {function} onResult — callback called with each deepfake analysis result
 * @returns {Promise<{success: boolean, error: string|null}>}
 */
export async function startVoiceDetection(tabId, onResult) {
    if (isRecording) {
        return { success: false, error: 'Voice detection already running' };
    }

    return new Promise((resolve) => {
        chrome.tabCapture.capture(
            { audio: true, video: false },
            (stream) => {
                if (chrome.runtime.lastError || !stream) {
                    console.warn('[ScamDefy] Tab capture failed:', chrome.runtime.lastError?.message);
                    resolve({ success: false, error: chrome.runtime.lastError?.message || 'Stream unavailable' });
                    return;
                }

                try {
                    // Set up MediaRecorder
                    mediaRecorder = new MediaRecorder(stream, {
                        mimeType: 'audio/webm;codecs=opus',
                        audioBitsPerSecond: 128000,
                    });

                    audioChunks = [];
                    isRecording = true;

                    mediaRecorder.ondataavailable = (event) => {
                        if (event.data && event.data.size > 0) {
                            audioChunks.push(event.data);
                        }
                    };

                    mediaRecorder.start(CHUNK_INTERVAL_MS);

                    // Analyze accumulated audio every CHUNK_INTERVAL_MS
                    analysisInterval = setInterval(async () => {
                        if (audioChunks.length === 0) return;

                        // Combine buffered chunks into one blob
                        const blob = new Blob(audioChunks, { type: 'audio/webm' });
                        audioChunks = []; // Reset buffer

                        if (blob.size < MIN_CHUNK_SIZE_BYTES) return;

                        try {
                            const result = await detectVoiceDeepfake(blob);
                            console.log('[ScamDefy] Voice analysis result:', result);
                            if (typeof onResult === 'function') {
                                onResult(result);
                            }
                        } catch (err) {
                            console.error('[ScamDefy] Voice analysis error:', err);
                        }
                    }, CHUNK_INTERVAL_MS);

                    resolve({ success: true, error: null });
                } catch (err) {
                    console.error('[ScamDefy] MediaRecorder setup failed:', err);
                    resolve({ success: false, error: err.message });
                }
            }
        );
    });
}

/**
 * Stop voice detection and clean up resources.
 * @returns {{success: boolean}}
 */
export function stopVoiceDetection() {
    if (analysisInterval) {
        clearInterval(analysisInterval);
        analysisInterval = null;
    }

    if (mediaRecorder && mediaRecorder.state !== 'inactive') {
        mediaRecorder.stop();
        // Stop all tracks on the stream
        if (mediaRecorder.stream) {
            mediaRecorder.stream.getTracks().forEach(track => track.stop());
        }
        mediaRecorder = null;
    }

    isRecording = false;
    audioChunks = [];

    return { success: true };
}

/**
 * Check if voice detection is currently active.
 * @returns {boolean}
 */
export function isVoiceDetectionActive() {
    return isRecording;
}

// ─── RESULT INTERPRETER ────────────────────────────────────────────────────────

/**
 * Generate a user-friendly message from a voice detection result.
 * @param {{isDeepfake: boolean, confidence: number, label: string}} result
 * @returns {{
 *   title: string,
 *   message: string,
 *   severity: 'safe'|'warning'|'danger',
 *   action: string
 * }}
 */
export function interpretVoiceResult(result) {
    const confidencePct = Math.round((result.confidence || 0) * 100);

    if (!result.isDeepfake) {
        return {
            title: '🎙️ Voice Appears Real',
            message: `This voice stream appears to be genuine (${confidencePct}% confidence).`,
            severity: 'safe',
            action: 'No action required.',
        };
    }

    if (confidencePct >= 85) {
        return {
            title: '⚠️ AI Voice Deepfake Detected',
            message: `High probability (${confidencePct}%) that this voice is AI-generated or cloned. This may be a voice phishing (vishing) scam.`,
            severity: 'danger',
            action: 'Hang up immediately. Do not share personal or financial information.',
        };
    }

    return {
        title: '⚠️ Suspicious Voice Detected',
        message: `Possible AI voice manipulation detected (${confidencePct}% confidence). Proceed with caution.`,
        severity: 'warning',
        action: 'Verify the caller's identity through official channels before sharing any sensitive information.',
  };
}
