# PHISH GUARD - Chrome Extension Testing & Verification Guide

This guide details step-by-step instructions for loading, testing, and verifying the **PHISH GUARD** Chrome Extension (Manifest V3) and verifying real-time synchronization with the Flask ML Backend and Admin Dashboard.

---

## 1. Prerequisites

1. Ensure the Flask backend is running:
   ```bash
   cd PHISH-GUARD/backend
   python app.py
   ```
   Verify at `http://127.0.0.1:5000/health` that `status: healthy` and `ml_engine_loaded: true`.

2. Any Chromium-based browser (Google Chrome, Microsoft Edge, Brave, Opera).

---

## 2. Loading the Unpacked Extension into Chrome

1. Open Google Chrome.
2. Navigate to `chrome://extensions/` in the URL bar.
3. In the top-right corner, toggle **Developer mode** to **ON**.
4. Click the **Load unpacked** button in the top-left toolbar.
5. In the file picker dialog, select the `browser_extension` folder located at:
   ```
   C:\Users\ADITHYA\.gemini\antigravity\scratch\PHISH-GUARD\browser_extension
   ```
6. The extension **PHISH GUARD - ML Threat Detector** will appear in your extensions list.
7. Click the Chrome Puzzle icon (Extensions menu) in the toolbar and pin **PHISH GUARD** to the browser bar for instant visibility.

---

## 3. Testing Scenarios & Verification Matrix

### Test Case 1: Legitimate Website (Safe Classification)
* **Action:** Navigate to `https://www.wikipedia.org` or `https://github.com`.
* **Expected Badge:** Green badge displaying **`SAFE`**.
* **Expected Popup:**
  * Status: **SAFE WEBSITE** with green glowing ring (`✓`).
  * Risk Level: `Low Risk`.
  * Confidence: $\ge 90\%$.
  * Reasons: "Standard domain structure and valid HTTPS encryption", "No known phishing indicators".

### Test Case 2: Suspicious / Shortened URL
* **Action:** Navigate to a shortened link such as `https://bit.ly/3xY9zq`.
* **Expected Badge:** Yellow/Amber badge displaying **`WARN`**.
* **Expected Popup:**
  * Status: **SUSPICIOUS WEBSITE** with yellow warning ring (`⚠`).
  * Risk Level: `Medium Risk`.
  * Reasons: "Known URL shortener service used to mask final destination".

### Test Case 3: Phishing / Malicious Domain (Warning Interception)
* **Action:** In your browser URL bar, enter a known phishing pattern such as:
  `http://paypal-verification-alert-account.xyz/login.php`
* **Expected Behavior:**
  * The extension intercepts the navigation immediately.
  * Browser redirects to the full-screen **Security Alert: Phishing Detected** warning page (`warning.html`).
  * Badge displays **`DANG`** or **`CRIT`** in red.
* **Warning Page Elements:**
  * Shows targeted URL.
  * Risk Level: `High` or `Critical`.
  * Lists detection reasons (e.g. Brand impersonation: 'paypal', High-risk TLD: '.xyz', Multiple security keywords).

### Test Case 4: Temporary Bypass ("Continue Anyway")
* **Action:** On the Warning page, click the **Continue Anyway (Unsafe)** button.
* **Expected Behavior:**
  * A confirmation prompt appears warning about potential credential loss.
  * Upon confirmation, the background service worker registers the URL into `temporaryBypasses` with a 1-hour expiration timestamp.
  * The page navigates to the destination without re-triggering an infinite redirect loop.

### Test Case 5: False Positive Reporting
* **Action:** On the Warning page (or inside the Popup's "Feedback" tab), click **Report False Positive** and submit.
* **Expected Behavior:**
  * Green confirmation banner: `✓ False positive report submitted to threat database`.
  * Record is logged into the backend database.
  * Check `http://127.0.0.1:5000/dashboard` $\rightarrow$ **Threat Reports** to see the entry in the retraining queue.

### Test Case 6: Dark / Light Mode Toggle
* **Action:** Open the extension popup and click the Sun/Moon icon in the top header.
* **Expected Behavior:**
  * Instantly toggles between high-contrast Dark theme and clean Light theme.
  * Theme preference persists across tab changes and browser restarts via `chrome.storage.local`.

---

## 4. Verifying Admin Dashboard & Telemetry

1. Navigate to:
   ```
   http://127.0.0.1:5000/dashboard
   ```
2. Verify:
   * **Dashboard Overview:** Displays live total scans, safe, suspicious, and dangerous counts.
   * **Telemetry Charts:** 6 interactive Chart.js visualizations (Safe vs Phishing, Daily activity, Prediction distribution, Top suspicious domains, Confidence distribution).
   * **Scan History Table:** Real-time table showing all scans. Click the eye icon to view the full 30-feature vector modal for any URL.
   * **Blacklist Manager:** Test adding a domain (e.g., `test-block-site.xyz`) and verify that future visits are instantly blocked.
   * **Model Performance:** Displays the champion model (Gradient Boosting), benchmark table comparing all 7 algorithms, and feature importance rankings.
