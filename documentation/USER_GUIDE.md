# PHISH GUARD - End-to-End User & Deployment Guide

This guide provides setup, deployment, and daily operational instructions for **PHISH GUARD**.

---

## 1. System Requirements

* **Operating System:** Windows 10/11, macOS, or Linux.
* **Python Runtime:** Python 3.12+ (tested and verified on Python 3.13).
* **Browser:** Any modern Chromium-based browser supporting Chrome Manifest V3 (Google Chrome, Microsoft Edge, Brave, Opera, Vivaldi).
* **RAM / Disk:** $\ge 2\text{ GB}$ RAM, $500\text{ MB}$ free disk space.

---

## 2. Installation & Environment Setup

### Step 1: Clone or Open Project Directory
Navigate to the root project directory:
```bash
cd PHISH-GUARD
```

### Step 2: Install Python Dependencies
```bash
pip install -r requirements.txt
```

---

## 3. Launching the Backend Server

To start the Flask REST API:
```bash
cd backend
python app.py
```
By default, the server starts at `http://127.0.0.1:5000`.

### Verifying Server Health
Open your browser or run:
```bash
curl http://127.0.0.1:5000/health
```
Expected output:
```json
{
  "status": "healthy",
  "database_connected": true,
  "ml_engine_loaded": true,
  "service": "PHISH GUARD Detection Engine",
  "version": "1.0.0"
}
```

---

## 4. Accessing the Admin Dashboard

Open your web browser and navigate to:
```
http://127.0.0.1:5000/dashboard
```
The Admin Dashboard allows you to:
1. View real-time URL telemetry and threat breakdowns.
2. Filter and search historical scans.
3. Manage blacklist entries (add or delete blocked domains).
4. Inspect community false positive / false negative reports.
5. Review comparative benchmarks across all 7 evaluated machine learning models.
6. Configure risk thresholds and rate limits.

---

## 5. Loading the Browser Extension

1. In Chrome/Edge, open:
   ```
   chrome://extensions/
   ```
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked**.
4. Select the `PHISH-GUARD/browser_extension` directory.
5. The extension is now active. As you navigate the web, the extension icon badge will automatically update:
   * **`SAFE` (Green)**: Legitimate and verified sites.
   * **`WARN` (Yellow)**: Suspicious or shortened URLs.
   * **`DANG` (Red)**: Phishing threats (interrupted by full-screen warning page).

---

## 6. Retraining Machine Learning Models

To re-run the benchmark pipeline, train models on fresh dataset samples, and select a new champion model:
```bash
cd models
python train_models.py
```
This script will:
1. Re-extract features across training samples.
2. Evaluate 7 algorithms (Gradient Boosting, Random Forest, SVC, Logistic Regression, KNN, Decision Tree, Gaussian Naive Bayes).
3. Benchmark Accuracy, Precision, Recall, F1 Score, ROC-AUC, and Training Latency.
4. Export updated `model.pkl`, `scaler.pkl`, `confusion_matrix.png`, and `metadata.json`.
5. Sync updated metrics into the SQLite database.

---

## 7. Troubleshooting

| Issue | Root Cause | Solution |
|---|---|---|
| Extension badge says `SCAN` or remains gray | Backend server not running | Ensure `python app.py` is active in `backend/` on port 5000. |
| CORS Error in Extension Console | Manifest host permissions | Manifest V3 includes `http://127.0.0.1:5000/*` in `host_permissions`. Ensure Flask CORS is enabled. |
| Model failed to load | Missing `model.pkl` | Run `python train_models.py` in the `models/` directory. |
| Warning page loops continuously | Temporary bypass token expired | Click "Continue Anyway" to issue a new temporary bypass token. |
