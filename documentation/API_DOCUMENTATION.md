# PHISH GUARD - RESTful API Documentation

This document describes all REST API endpoints provided by the **PHISH GUARD** backend server (`http://127.0.0.1:5000`).

---

## Base URL
```
http://127.0.0.1:5000
```

All requests and responses use `application/json` content type unless serving dashboard static assets.

---

## 1. POST /predict
Analyzes an incoming URL, runs feature extraction, checks blacklists, runs Machine Learning classification, records scan telemetry into SQLite, and returns a detailed verdict.

### Request
* **Method:** `POST`
* **Headers:** `Content-Type: application/json`
* **Body:**
```json
{
  "url": "http://paypal-verification-alert-account.xyz/login.php"
}
```

### Response (`200 OK`)
```json
{
  "status": "success",
  "data": {
    "url": "http://paypal-verification-alert-account.xyz/login.php",
    "domain": "paypal-verification-alert-account.xyz",
    "prediction": "Malicious",
    "risk_level": "Critical",
    "confidence": 100.0,
    "phishing_probability": 1.0,
    "scan_time_ms": 14.82,
    "is_blacklisted": false,
    "reasons": [
      "Brand impersonation detected: deceptive use of 'paypal'",
      "High-risk Top-Level Domain (.xyz) with elevated phishing frequency",
      "Multiple security/auth keywords present (login, verification)",
      "Unencrypted connection (HTTP instead of HTTPS)"
    ],
    "features": {
      "url_length": 55.0,
      "domain_length": 39.0,
      "path_length": 10.0,
      "count_dots": 2.0,
      "count_hyphens": 4.0,
      "count_digits": 0.0,
      "count_subdomains": 0.0,
      "has_https": 0.0,
      "has_http": 1.0,
      "has_ip_address": 0.0,
      "count_at": 0.0,
      "count_percent": 0.0,
      "count_underscore": 0.0,
      "count_equal": 0.0,
      "count_question": 0.0,
      "count_ampersand": 0.0,
      "has_double_slash_path": 0.0,
      "num_parameters": 0.0,
      "url_entropy": 4.5421,
      "domain_entropy": 4.2981,
      "suspicious_keywords_count": 2.0,
      "brand_impersonation": 1.0,
      "is_shortened_url": 0.0,
      "has_punycode": 0.0,
      "has_homoglyphs": 0.0,
      "tld_risk_score": 1.0,
      "digit_to_letter_ratio": 0.0,
      "has_port": 0.0,
      "consecutive_hyphens": 0.0,
      "tld_in_subdomain": 0.0
    },
    "metadata": {
      "domain": "paypal-verification-alert-account.xyz",
      "tld": "xyz",
      "scheme": "http",
      "detected_brands": ["paypal"],
      "suspicious_keywords": ["login", "verification"],
      "is_ip": false,
      "is_shortened": false
    }
  }
}
```

---

## 2. POST /report
Submits user feedback flagging a false positive (safe site flagged as threat) or false negative (phishing site missed).

### Request
* **Method:** `POST`
* **Body:**
```json
{
  "url": "https://secure-internal-dev.company.net",
  "feedback": "false_positive",
  "reported_type": "Safe",
  "actual_status": "Suspicious",
  "comments": "Internal development server flagged incorrectly."
}
```

### Response (`201 Created`)
```json
{
  "status": "success",
  "message": "Feedback submitted successfully. Thank you for contributing to Phish Guard accuracy.",
  "report_id": 3
}
```

---

## 3. GET /history
Returns paginated scan history logs.

### Query Parameters
* `limit`: Integer (default: 50, max: 200)
* `offset`: Integer (default: 0)
* `status`: Filter by classification (`Safe`, `Suspicious`, `Phishing`, `Malicious`, `all`)
* `search`: String searching in URL or domain

### Response (`200 OK`)
```json
{
  "status": "success",
  "total": 42,
  "limit": 50,
  "offset": 0,
  "history": [
    {
      "id": 1,
      "url": "https://github.com/torvalds/linux",
      "domain": "github.com",
      "prediction": "Safe",
      "confidence": 100.0,
      "risk_level": "Low",
      "scan_time_ms": 12.4,
      "reasons": ["Standard domain structure and valid HTTPS encryption"],
      "created_at": "2026-10-13 11:51:00"
    }
  ]
}
```

---

## 4. GET /stats
Returns aggregated operational telemetry and metrics for the Admin Dashboard.

### Response (`200 OK`)
```json
{
  "status": "success",
  "stats": {
    "total_scans": 18,
    "safe_scans": 8,
    "suspicious_scans": 1,
    "dangerous_scans": 9,
    "blocked_domains": 5,
    "average_confidence": 96.7,
    "prediction_distribution": {
      "Safe": 8,
      "Suspicious": 1,
      "Phishing": 2,
      "Malicious": 7
    },
    "top_suspicious_domains": [
      { "domain": "paypal-verification-alert-account.xyz", "count": 1, "prediction": "Malicious" }
    ],
    "daily_scans": [
      { "scan_date": "2026-10-13", "safe_cnt": 8, "phish_cnt": 9, "susp_cnt": 1, "total": 18 }
    ],
    "confidence_distribution": {
      "90-100%": 17,
      "75-89%": 0,
      "50-74%": 0,
      "< 50%": 1
    },
    "false_positives": 1,
    "false_negatives": 1
  }
}
```

---

## 5. Blacklist Management Endpoints

### GET /blacklist
Returns all active blacklist rules.

### POST /blacklist
Adds a new domain or regex pattern to the active blacklist.
```json
{
  "pattern": "evil-phishing-portal.xyz",
  "domain": "evil-phishing-portal.xyz",
  "reason": "Active credential harvester campaign"
}
```

### DELETE /blacklist?id=1
Removes an entry from the blacklist by ID.

---

## 6. GET /model-info
Returns details of the active production model, feature importances, and evaluation metrics across all 7 benchmarked estimators.

### Response (`200 OK`)
```json
{
  "status": "success",
  "data": {
    "active_model_name": "Gradient Boosting",
    "feature_count": 30,
    "champion_metrics": {
      "accuracy": 1.0,
      "precision": 1.0,
      "recall": 1.0,
      "f1_score": 1.0,
      "roc_auc": 1.0,
      "training_time": 0.518
    },
    "feature_importances": {
      "brand_impersonation": 0.521,
      "has_ip_address": 0.183,
      "tld_risk_score": 0.124
    },
    "status": "online"
  }
}
```

---

## 7. GET /health
Returns server uptime, health status, and module availability.
```json
{
  "status": "healthy",
  "service": "PHISH GUARD Detection Engine",
  "version": "1.0.0",
  "uptime_seconds": 320.4,
  "database_connected": true,
  "ml_engine_loaded": true,
  "timestamp": "2026-10-13 12:00:00"
}
```
