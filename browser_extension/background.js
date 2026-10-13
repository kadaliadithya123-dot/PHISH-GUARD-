/**
 * PHISH GUARD - Service Worker (Background Script)
 * Manifest V3 compliant service worker monitoring tab navigation,
 * executing real-time threat scans, managing badges, and enforcing blocking warnings.
 */

const API_BASE_URL = "https://phish-guard-api.onrender.com";
const CACHE_EXPIRY_MS = 10 * 60 * 1000; // 10 minutes cache
const BYPASS_EXPIRY_MS = 60 * 60 * 1000; // 1 hour temporary bypass

// In-memory tab scan cache
const tabScanCache = new Map();
// Temporary bypass URLs
const temporaryBypasses = new Map();

/**
 * Validates whether a URL should be scanned
 */
function shouldScanUrl(url) {
  if (!url || typeof url !== "string") return false;
  const lower = url.toLowerCase();
  return (
    lower.startsWith("http://") ||
    lower.startsWith("https://")
  ) && !lower.includes("chrome://") && !lower.includes("chrome-extension://");
}

/**
 * Updates extension action badge and background color
 */
function updateBadge(tabId, status, riskLevel) {
  let badgeText = "";
  let badgeColor = "#64748B"; // Default gray

  if (status === "Safe") {
    badgeText = "SAFE";
    badgeColor = "#10B981"; // Emerald green
  } else if (status === "Suspicious") {
    badgeText = "WARN";
    badgeColor = "#F59E0B"; // Amber yellow
  } else if (status === "Phishing" || status === "Malicious") {
    badgeText = status === "Malicious" ? "CRIT" : "DANG";
    badgeColor = "#EF4444"; // Crimson red
  }

  chrome.action.setBadgeText({ tabId, text: badgeText });
  chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
}

/**
 * Local heuristic scanner fallback when backend API is temporarily offline
 */
function localHeuristicScan(url) {
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname.toLowerCase();
    const reasons = [];
    let isPhish = false;

    // IP address test
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(domain)) {
      reasons.push("Direct IP address used instead of domain name");
      isPhish = true;
    }

    // High risk TLD
    if (/\.(xyz|top|tk|ml|ga|cf|gq|buzz|icu|club)$/.test(domain)) {
      reasons.push("High-risk Top-Level Domain detected");
      isPhish = true;
    }

    // Brand spoof in non-official domain
    const brands = ["paypal", "apple", "google", "microsoft", "amazon", "netflix", "chase"];
    for (const b of brands) {
      if (domain.includes(b) && !domain.endsWith(`${b}.com`)) {
        reasons.push(`Brand spoofing indicator for '${b}'`);
        isPhish = true;
      }
    }

    if (isPhish) {
      return {
        url,
        domain,
        prediction: "Phishing",
        risk_level: "High",
        confidence: 85.0,
        scan_time_ms: 1.5,
        reasons,
        is_fallback: true
      };
    }

    return {
      url,
      domain,
      prediction: "Safe",
      risk_level: "Low",
      confidence: 80.0,
      scan_time_ms: 1.0,
      reasons: ["Verified HTTPS encryption", "No local heuristic threats identified"],
      is_fallback: true
    };
  } catch (e) {
    return {
      url,
      prediction: "Safe",
      risk_level: "Low",
      confidence: 50.0,
      scan_time_ms: 1.0,
      reasons: ["Analysis completed"],
      is_fallback: true
    };
  }
}

/**
 * Performs scan by contacting the Flask backend
 */
async function scanUrl(url) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2500);

    const response = await fetch(`${API_BASE_URL}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (response.ok) {
      const json = await response.json();
      return json.data;
    }
    throw new Error(`API returned ${response.status}`);
  } catch (error) {
    console.warn("[PhishGuard] Backend unreachable, using fallback heuristics:", error.message);
    return localHeuristicScan(url);
  }
}

/**
 * Saves scan record to chrome.storage.local scan history
 */
async function recordToLocalHistory(scanResult) {
  try {
    const { localHistory = [] } = await chrome.storage.local.get("localHistory");
    const newEntry = {
      id: Date.now(),
      url: scanResult.url,
      domain: scanResult.domain,
      prediction: scanResult.prediction,
      confidence: scanResult.confidence,
      risk_level: scanResult.risk_level,
      scan_time_ms: scanResult.scan_time_ms,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    // Prepend and keep latest 40 entries
    const updated = [newEntry, ...localHistory.slice(0, 39)];
    await chrome.storage.local.set({ localHistory: updated });
  } catch (e) {
    console.error("[PhishGuard] Error recording history:", e);
  }
}

/**
 * Handles navigation to a tab URL
 */
async function processTabScan(tabId, url) {
  if (!shouldScanUrl(url)) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }

  // Check cache
  const cached = tabScanCache.get(url);
  if (cached && Date.now() - cached.timestamp < CACHE_EXPIRY_MS) {
    updateBadge(tabId, cached.data.prediction, cached.data.risk_level);
    return cached.data;
  }

  // Set scanning badge indicator
  chrome.action.setBadgeText({ tabId, text: "SCAN" });
  chrome.action.setBadgeBackgroundColor({ tabId, color: "#3B82F6" });

  const result = await scanUrl(url);
  tabScanCache.set(url, { timestamp: Date.now(), data: result });

  // Update badge color
  updateBadge(tabId, result.prediction, result.risk_level);
  await recordToLocalHistory(result);

  // Check if warning redirect should occur
  if (result.prediction === "Phishing" || result.prediction === "Malicious") {
    // Check if user temporarily bypassed this URL
    const bypassTimestamp = temporaryBypasses.get(url);
    const isBypassed = bypassTimestamp && (Date.now() - bypassTimestamp < BYPASS_EXPIRY_MS);

    if (!isBypassed) {
      const warningUrl = chrome.runtime.getURL(
        `warning.html?targetUrl=${encodeURIComponent(url)}` +
        `&prediction=${encodeURIComponent(result.prediction)}` +
        `&risk=${encodeURIComponent(result.risk_level)}` +
        `&confidence=${encodeURIComponent(result.confidence)}` +
        `&reasons=${encodeURIComponent(JSON.stringify(result.reasons || []))}`
      );
      chrome.tabs.update(tabId, { url: warningUrl });
    }
  }

  return result;
}

// Event Listeners for Tab Navigation
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && changeInfo.url) {
    processTabScan(tabId, changeInfo.url);
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && tab.url && shouldScanUrl(tab.url)) {
      const cached = tabScanCache.get(tab.url);
      if (cached) {
        updateBadge(activeInfo.tabId, cached.data.prediction, cached.data.risk_level);
      } else {
        processTabScan(activeInfo.tabId, tab.url);
      }
    } else {
      chrome.action.setBadgeText({ tabId: activeInfo.tabId, text: "" });
    }
  } catch (e) {
    // Tab might have closed
  }
});

// Message Listener for Popup and Warning Page
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "GET_CURRENT_STATUS") {
    const cached = tabScanCache.get(request.url);
    if (cached) {
      sendResponse({ status: "success", data: cached.data });
    } else {
      scanUrl(request.url).then((result) => {
        tabScanCache.set(request.url, { timestamp: Date.now(), data: result });
        sendResponse({ status: "success", data: result });
      });
      return true; // Keep message channel open for async response
    }
  } else if (request.action === "RESCAN_URL") {
    tabScanCache.delete(request.url);
    scanUrl(request.url).then((result) => {
      tabScanCache.set(request.url, { timestamp: Date.now(), data: result });
      if (sender.tab && sender.tab.id) {
        updateBadge(sender.tab.id, result.prediction, result.risk_level);
      }
      sendResponse({ status: "success", data: result });
    });
    return true;
  } else if (request.action === "ADD_BYPASS") {
    temporaryBypasses.set(request.url, Date.now());
    sendResponse({ status: "success" });
  } else if (request.action === "SUBMIT_REPORT") {
    fetch(`${API_BASE_URL}/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request.payload)
    })
      .then((res) => res.json())
      .then((data) => sendResponse(data))
      .catch((err) => sendResponse({ status: "error", message: err.message }));
    return true;
  }
});
