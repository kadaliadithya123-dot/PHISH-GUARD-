/**
 * PHISH GUARD - Popup Controller Script
 * Manages UI interactions, tab switching, theme toggles,
 * real-time status rendering, feature inspection, history, and threat reporting.
 */

document.addEventListener("DOMContentLoaded", async () => {
  // DOM Elements
  const themeToggleBtn = document.getElementById("themeToggleBtn");
  const rescanBtn = document.getElementById("rescanBtn");
  const rescanIcon = document.getElementById("rescanIcon");
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabPanes = document.querySelectorAll(".tab-pane");

  const targetUrlText = document.getElementById("targetUrlText");
  const protocolBadge = document.getElementById("protocolBadge");
  const statusCard = document.getElementById("statusCard");
  const statusGlyph = document.getElementById("statusGlyph");
  const statusLabel = document.getElementById("statusLabel");
  const riskBadge = document.getElementById("riskBadge");
  const confidenceVal = document.getElementById("confidenceVal");
  const latencyVal = document.getElementById("latencyVal");
  const domainVal = document.getElementById("domainVal");
  const reasonsList = document.getElementById("reasonsList");

  const featuresListContainer = document.getElementById("featuresListContainer");
  const historyList = document.getElementById("historyList");
  const clearHistoryBtn = document.getElementById("clearHistoryBtn");

  const reportForm = document.getElementById("reportForm");
  const reportFeedback = document.getElementById("reportFeedback");

  let currentTabUrl = "";
  let currentScanResult = null;

  // ==========================================
  // 1. Theme Management (Dark / Light)
  // ==========================================
  const { isLightTheme = false } = await chrome.storage.local.get("isLightTheme");
  if (isLightTheme) {
    document.body.classList.remove("dark-theme");
  } else {
    document.body.classList.add("dark-theme");
  }

  themeToggleBtn.addEventListener("click", async () => {
    const isDark = document.body.classList.toggle("dark-theme");
    await chrome.storage.local.set({ isLightTheme: !isDark });
  });

  // ==========================================
  // 2. Tab Navigation
  // ==========================================
  tabButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      tabButtons.forEach((b) => b.classList.remove("active"));
      tabPanes.forEach((p) => p.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      document.getElementById(targetId).classList.add("active");

      if (targetId === "historyTab") {
        renderLocalHistory();
      }
    });
  });

  // ==========================================
  // 3. Scan & Status Rendering
  // ==========================================
  async function loadActiveTabAndScan() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.url) {
        targetUrlText.textContent = "No active web page detected";
        return;
      }

      currentTabUrl = tab.url;
      targetUrlText.textContent = tab.url;
      targetUrlText.title = tab.url;

      // Protocol badge
      if (tab.url.startsWith("https://")) {
        protocolBadge.textContent = "HTTPS";
        protocolBadge.style.color = "#10B981";
      } else if (tab.url.startsWith("http://")) {
        protocolBadge.textContent = "HTTP";
        protocolBadge.style.color = "#F59E0B";
      } else {
        protocolBadge.textContent = "LOCAL";
      }

      // Check if internal browser page
      if (tab.url.startsWith("chrome://") || tab.url.startsWith("chrome-extension://")) {
        renderInternalPage(tab.url);
        return;
      }

      // Request scan result from background worker
      chrome.runtime.sendMessage(
        { action: "GET_CURRENT_STATUS", url: tab.url },
        (response) => {
          if (response && response.data) {
            currentScanResult = response.data;
            renderScanData(response.data);
          } else {
            targetUrlText.textContent = "Awaiting scan response...";
          }
        }
      );
    } catch (e) {
      console.error("Error loading active tab:", e);
    }
  }

  function renderInternalPage(url) {
    statusCard.className = "status-card safe";
    statusGlyph.textContent = "ℹ";
    statusLabel.textContent = "SYSTEM PAGE";
    riskBadge.textContent = "Trusted";
    confidenceVal.textContent = "100%";
    latencyVal.textContent = "0 ms";
    domainVal.textContent = "Internal";
    reasonsList.innerHTML = "<li>Browser internal settings or extension page.</li>";
  }

  function renderScanData(data) {
    const pred = data.prediction || "Safe";
    const risk = data.risk_level || "Low";
    const conf = data.confidence || 95.0;
    const latency = data.scan_time_ms || 12;
    const domain = data.domain || "--";
    const reasons = data.reasons || [];

    // Reset styles
    statusCard.className = "status-card";

    if (pred === "Safe") {
      statusCard.classList.add("safe");
      statusGlyph.textContent = "✓";
      statusLabel.textContent = "SAFE WEBSITE";
    } else if (pred === "Suspicious") {
      statusCard.classList.add("suspicious");
      statusGlyph.textContent = "⚠";
      statusLabel.textContent = "SUSPICIOUS WEBSITE";
    } else {
      statusCard.classList.add("danger");
      statusGlyph.textContent = "✕";
      statusLabel.textContent = pred === "Malicious" ? "MALICIOUS DOMAIN" : "PHISHING THREAT";
    }

    riskBadge.textContent = `${risk} Risk`;
    confidenceVal.textContent = `${conf.toFixed(1)}%`;
    latencyVal.textContent = `${latency.toFixed(1)} ms`;
    domainVal.textContent = domain;

    // Render Reasons
    reasonsList.innerHTML = "";
    if (reasons.length > 0) {
      reasons.forEach((r) => {
        const li = document.createElement("li");
        li.textContent = r;
        reasonsList.appendChild(li);
      });
    } else {
      reasonsList.innerHTML = "<li>No threat indicators identified.</li>";
    }

    // Render Features Tab
    renderFeatures(data.features);
  }

  function renderFeatures(features) {
    featuresListContainer.innerHTML = "";
    if (!features || Object.keys(features).length === 0) {
      featuresListContainer.innerHTML = "<div class='loading-placeholder'>No features extracted yet.</div>";
      return;
    }

    Object.entries(features).forEach(([key, val]) => {
      const pill = document.createElement("div");
      pill.className = "feature-pill";

      const nameSpan = document.createElement("span");
      nameSpan.className = "feature-pill-name";
      nameSpan.textContent = key.replace(/_/g, " ");

      const valSpan = document.createElement("span");
      valSpan.className = "feature-pill-val";
      valSpan.textContent = typeof val === "number" && !Number.isInteger(val) ? val.toFixed(3) : val;

      pill.appendChild(nameSpan);
      pill.appendChild(valSpan);
      featuresListContainer.appendChild(pill);
    });
  }

  // ==========================================
  // 4. Local History
  // ==========================================
  async function renderLocalHistory() {
    const { localHistory = [] } = await chrome.storage.local.get("localHistory");
    historyList.innerHTML = "";

    if (localHistory.length === 0) {
      historyList.innerHTML = "<div class='loading-placeholder'>No recent scans in history.</div>";
      return;
    }

    localHistory.forEach((item) => {
      const div = document.createElement("div");
      div.className = "history-item";

      const left = document.createElement("div");
      left.className = "history-left";

      const dom = document.createElement("span");
      dom.className = "history-domain";
      dom.textContent = item.domain || item.url;
      dom.title = item.url;

      const timeSpan = document.createElement("span");
      timeSpan.className = "history-time";
      timeSpan.textContent = `${item.timestamp} • ${item.confidence ? item.confidence.toFixed(0) : '--'}% conf`;

      left.appendChild(dom);
      left.appendChild(timeSpan);

      const badge = document.createElement("span");
      const badgeCls = item.prediction === "Safe" ? "safe" : (item.prediction === "Suspicious" ? "suspicious" : "danger");
      badge.className = `history-badge ${badgeCls}`;
      badge.textContent = item.prediction;

      div.appendChild(left);
      div.appendChild(badge);
      historyList.appendChild(div);
    });
  }

  clearHistoryBtn.addEventListener("click", async () => {
    await chrome.storage.local.set({ localHistory: [] });
    renderLocalHistory();
  });

  // ==========================================
  // 5. One-Click Rescan
  // ==========================================
  rescanBtn.addEventListener("click", () => {
    if (!currentTabUrl) return;
    rescanIcon.classList.add("spin-animation");
    chrome.runtime.sendMessage(
      { action: "RESCAN_URL", url: currentTabUrl },
      (response) => {
        setTimeout(() => {
          rescanIcon.classList.remove("spin-animation");
          if (response && response.data) {
            currentScanResult = response.data;
            renderScanData(response.data);
          }
        }, 400);
      }
    );
  });

  // ==========================================
  // 6. Threat Reporting / Feedback
  // ==========================================
  reportForm.addEventListener("submit", (e) => {
    e.preventDefault();
    if (!currentTabUrl) {
      reportFeedback.textContent = "No valid URL selected to report.";
      reportFeedback.className = "form-feedback error";
      return;
    }

    const selectedType = document.querySelector('input[name="reportType"]:checked').value;
    const comments = document.getElementById("reportComments").value;

    const payload = {
      url: currentTabUrl,
      feedback: selectedType,
      reported_type: selectedType === "false_positive" ? "Safe" : "Phishing",
      actual_status: currentScanResult ? currentScanResult.prediction : "Unknown",
      comments: comments
    };

    chrome.runtime.sendMessage(
      { action: "SUBMIT_REPORT", payload },
      (res) => {
        if (res && res.status === "success") {
          reportFeedback.textContent = "Report successfully submitted to security database!";
          reportFeedback.className = "form-feedback success";
          document.getElementById("reportComments").value = "";
        } else {
          reportFeedback.textContent = "Report logged locally.";
          reportFeedback.className = "form-feedback success";
        }
      }
    );
  });

  // Initial scan trigger
  await loadActiveTabAndScan();
});
