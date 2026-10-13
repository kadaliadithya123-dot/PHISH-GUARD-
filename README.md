# 🛡️ PHISH GUARD
### A Machine Learning-Based Browser Extension for Real-Time Phishing and Malicious URL Detection

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/framework-Flask%203.1-green.svg)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/ml-scikit--learn-orange.svg)](https://scikit-learn.org/)
[![Chrome Extension](https://img.shields.io/badge/manifest-V3-brightgreen.svg)](https://developer.chrome.com/docs/extensions/mv3/intro/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**PHISH GUARD** is an end-to-end, production-grade cybersecurity system designed to identify, block, and mitigate phishing and malicious websites in real time. It combines a **Google Chrome Manifest V3 Browser Extension**, an **Asynchronous Python Flask REST API**, a **30-Feature Lexical & Security Engine**, and a **Multi-Model Machine Learning Classifier** backed by an interactive **Security Operations Center (SOC) Admin Dashboard**.

---

## 🌟 Key Features

### 🧩 Chrome Browser Extension (Manifest V3)
* **Real-Time Automated Tab Monitoring:** Listens for navigation events and tab switches (`onUpdated`, `onActivated`) and scans visited URLs instantaneously.
* **Smart Dynamic Action Badges:**
  * 🟢 **`SAFE`** (Emerald): Legitimate, verified websites.
  * 🟡 **`WARN`** (Amber): Suspicious domains, URL shorteners, or anomalous patterns.
  * 🔴 **`DANG` / `CRIT`** (Crimson): Confirmed phishing or malicious domains.
* **Full-Screen Threat Interception (`warning.html`):** Blocks malicious web pages before rendering, presenting detected risk factors, ML confidence, and safe retreat options.
* **Temporary Bypass Mechanism:** Allows experienced users to temporarily bypass warnings with session tokens without triggering infinite reload loops.
* **30-Vector Feature Inspector:** Collapsible accordion in popup showcasing extracted URL characteristics.
* **Community Threat Feedback:** Direct reporting modal for false positives and false negatives feeding the retraining queue.
* **Dark & Light Mode:** Seamless theme toggle with persistent preferences.

### 🧠 Machine Learning Engine
* **30 Engineered Features:** Shannon entropy (DGA detection), brand impersonation markers (27+ targeted brands), IP addresses, Punycode IDN homoglyphs, deceptive subdomains, character ratios, and high-abuse TLDs.
* **Automated Multi-Algorithm Benchmarking:** Compares 7 estimators:
  * **Gradient Boosting** (Production Champion)
  * **Random Forest**
  * **Support Vector Machine (SVC)**
  * **Logistic Regression**
  * **K-Nearest Neighbors (KNN)**
  * **Decision Tree**
  * **Gaussian Naive Bayes**
* **Ultra-Low Latency:** Inference completes in under **15 ms** on consumer hardware (well below the 200 ms budget).

### 📊 SOC Admin Dashboard
* **Real-Time Telemetry:** Live dashboard cards for total scans, threats blocked, safe URLs, and average confidence.
* **6 Interactive Chart.js Visualizations:** Safe vs Phishing doughnut, daily scan velocity, weekly volume, class distribution, top suspicious domains, and confidence histograms.
* **Blacklist Rule Manager:** Instant CRUD management for custom domain and pattern blocking.
* **Historical Audit Log:** Searchable, filterable scan history with inspection modals for individual feature vectors.
* **Operational Settings:** Live tuning of classification probability thresholds and rate limits.

---

## 📁 Project Folder Structure

```
PHISH-GUARD/
├── backend/
│   ├── app.py                     # Flask REST API application & static asset server
│   ├── feature_extractor.py       # 30-feature lexical, structural, and entropy extractor
│   ├── model_service.py          # ML model loader, inference manager, and fail-safe fallback
│   ├── database_manager.py        # SQLite connection manager and parameterized CRUD
│   ├── security_utils.py          # OWASP headers, URL sanitization, and sliding-window rate limiter
│   ├── config.py                  # Thresholds, rate limits, and path configuration
│   └── logger.py                  # Structured rotating file & console logger
├── browser_extension/
│   ├── manifest.json              # Chrome Manifest V3 configuration
│   ├── popup.html / css / js      # Modern popup UI (Live scan, features, history, feedback)
│   ├── background.js              # Service worker (tab tracking, badges, warning redirection)
│   ├── content.js                 # In-page credential form audit
│   ├── warning.html / css / js    # Full-screen blocking warning page with temporary bypass
│   └── icons/                     # Extension icons (16px, 48px, 128px)
├── dataset/
│   ├── generate_dataset.py        # Synthesizes balanced legitimate and phishing URLs
│   ├── urls_dataset.csv           # Raw dataset (4,000 samples)
│   ├── features_extracted.csv     # Pre-extracted 30-feature matrix (3,725 unique samples)
│   └── data_preprocessing.py      # Cleaner, deduplicator, and dataset transformer
├── models/
│   ├── train_models.py            # Multi-algorithm training and benchmarking pipeline
│   ├── model.pkl                  # Serialized champion model (Gradient Boosting)
│   ├── scaler.pkl                 # Fitted StandardScaler
│   ├── metadata.json              # Model metrics, feature names, and benchmark JSON
│   └── confusion_matrix.png       # Generated confusion matrix plot
├── database/
│   ├── schema.sql                 # SQLite relational schema
│   ├── phishguard.db              # SQLite database pre-seeded with scans and blacklist rules
│   └── seed_data.py               # Database telemetry seeder
├── admin_dashboard/
│   ├── index.html                 # Single Page Application (SPA) dashboard
│   ├── css/dashboard.css          # Responsive SOC dashboard styling
│   └── js/
│       ├── dashboard.js           # Navigation, telemetry fetcher, and Blacklist CRUD
│       └── charts.js              # Chart.js visualizations
├── tests/
│   ├── test_feature_extractor.py  # Unit tests for feature extraction
│   ├── test_model.py              # Benchmarking and inference integration tests
│   ├── test_api.py                # REST API endpoint tests
│   └── extension_test_guide.md    # Chrome extension testing guide
├── documentation/
│   ├── ARCHITECTURE.md            # System architecture and data flow diagrams
│   ├── API_DOCUMENTATION.md       # Comprehensive REST API specifications
│   ├── FEATURE_ENGINEERING.md     # In-depth breakdown of 30 extracted features
│   ├── USER_GUIDE.md              # Installation and user operations guide
│   └── ACADEMIC_PROJECT_REPORT.md  # Final-year academic project report
├── requirements.txt               # Python package dependencies
└── README.md                      # Project documentation and quick start
```

---

## 🚀 Quick Start Guide

### 1. Installation
Clone or navigate to the repository and install requirements:
```bash
cd PHISH-GUARD
pip install -r requirements.txt
```

### 2. Start the Backend API & Dashboard
```bash
cd backend
python app.py
```
* **API Service:** Runs at `http://127.0.0.1:5000`
* **Admin Dashboard:** Open your browser at `http://127.0.0.1:5000/dashboard`
* **Health Check:** `http://127.0.0.1:5000/health`

### 3. Load the Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the `PHISH-GUARD/browser_extension` folder.
4. Pin the extension to your toolbar and visit websites to watch the real-time badges in action!

---

## 🧪 Model Performance Benchmarks

All 7 models were evaluated on the holdout test set ($N = 745$) under identical stratified conditions:

| Algorithm | Accuracy | Precision | Recall | F1 Score | ROC-AUC | Training Time |
|---|---|---|---|---|---|---|
| **Gradient Boosting (Champion)** | **100.00%** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **0.518s** |
| Random Forest | 99.87% | 0.9972 | 1.0000 | 0.9986 | 1.0000 | 0.320s |
| Support Vector Machine (SVC) | 100.00% | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.163s |
| Logistic Regression | 100.00% | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.013s |
| K-Nearest Neighbors (KNN) | 100.00% | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.002s |
| Decision Tree | 100.00% | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.012s |
| Gaussian Naive Bayes | 100.00% | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.005s |

> **Latency Benchmark:** End-to-end inference completes in **14.47 ms** per URL.

---

## 🔒 Security & Defensive Engineering

* **OWASP Headers:** Enforces Content-Security-Policy (CSP), `X-Content-Type-Options: nosniff`, and `X-Frame-Options: SAMEORIGIN`.
* **Rate Limiting:** Sliding-window in-memory limiter restricting client abuse to 120 requests/minute.
* **SQL Injection Immunity:** 100% parameterized SQLite statements across all query builders.
* **Fail-Safe Heuristic Mode:** In the event of model unavailability, fallback heuristic scoring guarantees continuous defense.

---

## 📚 Academic & Evaluation References

For academic submission, documentation, and viva preparation, refer to the following guides in the `documentation/` folder:
* [ACADEMIC_PROJECT_REPORT.md](documentation/ACADEMIC_PROJECT_REPORT.md)
* [ARCHITECTURE.md](documentation/ARCHITECTURE.md)
* [FEATURE_ENGINEERING.md](documentation/FEATURE_ENGINEERING.md)
* [API_DOCUMENTATION.md](documentation/API_DOCUMENTATION.md)
* [USER_GUIDE.md](documentation/USER_GUIDE.md)
* [Extension Testing Guide](tests/extension_test_guide.md)

---

## 📄 License
This project is licensed under the MIT License - free for academic and commercial research use.
