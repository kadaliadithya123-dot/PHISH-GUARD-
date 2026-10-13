/**
 * PHISH GUARD - Content Script
 * Runs in the context of visited web pages to detect client-side anomalies,
 * unencrypted credential forms, and display floating safety indicators if configured.
 */

(function () {
  // Prevent duplicate execution
  if (window.__PHISH_GUARD_INJECTED__) return;
  window.__PHISH_GUARD_INJECTED__ = true;

  // Inspect page for insecure credential forms (HTTP password submissions)
  function checkInsecureForms() {
    if (window.location.protocol === "http:") {
      const passwordInputs = document.querySelectorAll('input[type="password"]');
      if (passwordInputs.length > 0) {
        console.warn("[PHISH GUARD] Security Warning: Password input detected over unencrypted HTTP connection!");
      }
    }
  }

  // Run on load
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", checkInsecureForms);
  } else {
    checkInsecureForms();
  }

  // Listen for messages from popup or background if user requests inline safety pill
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "PING_CONTENT") {
      sendResponse({ status: "alive", url: window.location.href });
    }
  });
})();
