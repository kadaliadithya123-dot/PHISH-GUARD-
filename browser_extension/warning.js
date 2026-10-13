/**
 * PHISH GUARD - Warning Page Controller Script
 * Parses URL threat parameters, displays reasons for detection,
 * handles safe navigation retreat, temporary bypass, and false positive reporting.
 */

document.addEventListener("DOMContentLoaded", () => {
  const urlParams = new URLSearchParams(window.location.search);
  const targetUrl = urlParams.get("targetUrl") || "Unknown Destination";
  const prediction = urlParams.get("prediction") || "Phishing";
  const risk = urlParams.get("risk") || "Critical";
  const confidence = urlParams.get("confidence") || "99.0";
  let reasons = [];

  try {
    reasons = JSON.parse(urlParams.get("reasons") || "[]");
  } catch (e) {
    reasons = ["Suspicious domain structure and deceptive pattern markers."];
  }

  // Populate DOM elements
  const targetUrlDisplay = document.getElementById("targetUrlDisplay");
  const threatClassification = document.getElementById("threatClassification");
  const riskLevelDisplay = document.getElementById("riskLevelDisplay");
  const confidenceDisplay = document.getElementById("confidenceDisplay");
  const warningReasonsList = document.getElementById("warningReasonsList");
  const reportStatusMsg = document.getElementById("reportStatusMsg");
  const educationalPanel = document.getElementById("educationalPanel");

  targetUrlDisplay.textContent = targetUrl;
  threatClassification.textContent = `${risk.toUpperCase()} THREAT DETECTED`;
  riskLevelDisplay.textContent = risk;
  confidenceDisplay.textContent = `${parseFloat(confidence).toFixed(1)}%`;

  // Render Reasons
  warningReasonsList.innerHTML = "";
  if (reasons.length > 0) {
    reasons.forEach((r) => {
      const li = document.createElement("li");
      li.textContent = r;
      warningReasonsList.appendChild(li);
    });
  } else {
    warningReasonsList.innerHTML = "<li>Identified as malicious URL by high-confidence ML classification.</li>";
  }

  // 1. Back to Safety
  document.getElementById("goBackBtn").addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = "https://www.google.com";
    }
  });

  // 2. Continue Anyway (Temporary Bypass)
  document.getElementById("continueAnywayBtn").addEventListener("click", () => {
    const confirmed = confirm(
      "WARNING: Proceeding may expose your credentials, financial data, or passwords to malicious actors.\n\nAre you sure you want to proceed?"
    );
    if (confirmed) {
      // Notify background service worker to temporarily bypass this URL
      chrome.runtime.sendMessage(
        { action: "ADD_BYPASS", url: targetUrl },
        () => {
          window.location.href = targetUrl;
        }
      );
    }
  });

  // 3. Report False Positive
  document.getElementById("reportFpBtn").addEventListener("click", () => {
    chrome.runtime.sendMessage(
      {
        action: "SUBMIT_REPORT",
        payload: {
          url: targetUrl,
          feedback: "false_positive",
          reported_type: "Safe",
          actual_status: prediction,
          comments: "Reported directly from Warning blocking screen."
        }
      },
      (res) => {
        reportStatusMsg.textContent = "✓ False positive report submitted to threat database. Thank you!";
      }
    );
  });

  // 4. Learn More Toggle
  document.getElementById("learnMoreBtn").addEventListener("click", () => {
    educationalPanel.classList.toggle("visible");
  });
});
