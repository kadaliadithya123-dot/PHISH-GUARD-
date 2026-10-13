"""
PHISH GUARD - Database Manager Module
Provides thread-safe SQLite connection management and parameterized CRUD operations
for ScanHistory, Blacklist, Reports, ModelMetrics, Settings, and Users.
"""

import json
import os
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

DB_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "database", "phishguard.db")
)
SCHEMA_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "database", "schema.sql")
)


def get_db_connection() -> sqlite3.Connection:
    """Creates a thread-safe connection to SQLite with row factory enabled."""
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes the database schema and seeds default data if not already present."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db_connection()
    try:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            conn.executescript(f.read())

        # Seed default admin if missing
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM Users WHERE username = ?", ("admin",))
        if not cursor.fetchone():
            cursor.execute(
                "INSERT INTO Users (username, password_hash, role) VALUES (?, ?, ?)",
                ("admin", "pbkdf2:sha256:default_hash_phishguard_2026", "admin")
            )

        # Seed default blacklist
        default_blacklist = [
            ("evil-phish-login.xyz", "evil-phish-login.xyz", "Known active credential harvester"),
            ("paypal-security-alert-update.top", "paypal-security-alert-update.top", "Brand impersonation phishing domain"),
            ("appleid-verify-session.net", "appleid-verify-session.net", "Apple ID credential phishing campaign"),
            ("198.51.100.23", "198.51.100.23", "Malicious C2 / Phishing server IP"),
            ("bankofamerica-login-confirm.com", "bankofamerica-login-confirm.com", "Financial institution phishing")
        ]
        for pattern, domain, reason in default_blacklist:
            cursor.execute(
                "INSERT OR IGNORE INTO Blacklist (pattern, domain, reason, added_by) VALUES (?, ?, ?, ?)",
                (pattern, domain, reason, "security_team")
            )

        # Seed default settings
        default_settings = [
            ("risk_threshold_phishing", "0.75", "Probability threshold for classifying as Phishing"),
            ("risk_threshold_suspicious", "0.45", "Probability threshold for classifying as Suspicious"),
            ("rate_limit_per_minute", "120", "Max requests allowed per client IP per minute"),
            ("auto_block_critical", "true", "Automatically trigger blocking warning on Critical/Phishing status"),
            ("offline_mode", "false", "Force local heuristic rule fallback")
        ]
        for key, val, desc in default_settings:
            cursor.execute(
                "INSERT OR IGNORE INTO Settings (key, value, description) VALUES (?, ?, ?)",
                (key, val, desc)
            )

        conn.commit()
    finally:
        conn.close()


# ==========================================
# Scan History Operations
# ==========================================

def log_scan(
    url: str,
    domain: str,
    prediction: str,
    confidence: float,
    risk_level: str,
    scan_time_ms: float,
    reasons: List[str],
    features: Dict[str, Any],
    client_ip: str = "127.0.0.1"
) -> int:
    """Inserts a new scan log into the database."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO ScanHistory (
                url, domain, prediction, confidence, risk_level,
                scan_time_ms, reasons, features_json, client_ip
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                url,
                domain,
                prediction,
                float(confidence),
                risk_level,
                float(scan_time_ms),
                json.dumps(reasons),
                json.dumps(features),
                client_ip
            )
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_scan_history(
    limit: int = 50,
    offset: int = 0,
    filter_status: Optional[str] = None,
    search: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], int]:
    """Retrieves paginated scan logs with optional status and search filtering."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        query = "SELECT * FROM ScanHistory WHERE 1=1"
        params = []

        if filter_status and filter_status.lower() != "all":
            query += " AND LOWER(prediction) = LOWER(?)"
            params.append(filter_status)

        if search:
            query += " AND (url LIKE ? OR domain LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])

        # Count total matches
        count_query = query.replace("SELECT *", "SELECT COUNT(*)", 1)
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]

        # Fetch page
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()

        history = []
        for r in rows:
            item = dict(r)
            item["reasons"] = json.loads(item["reasons"]) if item["reasons"] else []
            item["features"] = json.loads(item["features_json"]) if item["features_json"] else {}
            item.pop("features_json", None)
            history.append(item)

        return history, total_count
    finally:
        conn.close()


# ==========================================
# Blacklist Operations
# ==========================================

def is_blacklisted(domain: str, raw_url: str = "") -> Tuple[bool, Optional[str]]:
    """Checks whether a domain or URL matches an active blacklist entry."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        domain_clean = domain.lower().strip()
        cursor.execute(
            "SELECT reason FROM Blacklist WHERE is_active = 1 AND (LOWER(pattern) = ? OR LOWER(domain) = ?)",
            (domain_clean, domain_clean)
        )
        row = cursor.fetchone()
        if row:
            return True, row["reason"]

        # Check wildcard or substring pattern
        cursor.execute("SELECT pattern, reason FROM Blacklist WHERE is_active = 1")
        for p in cursor.fetchall():
            pat = p["pattern"].lower()
            if pat in domain_clean or (raw_url and pat in raw_url.lower()):
                return True, p["reason"]

        return False, None
    finally:
        conn.close()


def get_blacklist() -> List[Dict[str, Any]]:
    """Retrieves all active blacklist entries."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Blacklist ORDER BY id DESC")
        return [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()


def add_to_blacklist(pattern: str, domain: str, reason: str, added_by: str = "admin") -> int:
    """Adds a new domain or pattern to the blacklist."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO Blacklist (pattern, domain, reason, added_by, is_active)
            VALUES (?, ?, ?, ?, 1)
            """,
            (pattern.strip().lower(), domain.strip().lower(), reason.strip(), added_by)
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def remove_from_blacklist(blacklist_id: int) -> bool:
    """Removes a blacklist entry by ID."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM Blacklist WHERE id = ?", (blacklist_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


# ==========================================
# Reports Operations (User Feedback)
# ==========================================

def add_report(
    url: str,
    feedback: str,
    reported_type: str = "",
    actual_status: str = "",
    comments: str = ""
) -> int:
    """Logs a false positive or false negative user report."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO Reports (url, user_feedback, reported_type, actual_status, comments)
            VALUES (?, ?, ?, ?, ?)
            """,
            (url, feedback, reported_type, actual_status, comments)
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_reports() -> List[Dict[str, Any]]:
    """Retrieves all user feedback reports."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Reports ORDER BY id DESC")
        return [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()


# ==========================================
# Statistics & Analytics Operations
# ==========================================

def get_dashboard_statistics() -> Dict[str, Any]:
    """Calculates comprehensive real-time statistics for the Admin Dashboard."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        # 1. Total counts
        cursor.execute("SELECT COUNT(*) FROM ScanHistory")
        total_scans = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM ScanHistory WHERE prediction = 'Safe'")
        safe_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM ScanHistory WHERE prediction = 'Suspicious'")
        suspicious_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM ScanHistory WHERE prediction IN ('Phishing', 'Malicious')")
        dangerous_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM Blacklist WHERE is_active = 1")
        blocked_count = cursor.fetchone()[0]

        cursor.execute("SELECT AVG(confidence) FROM ScanHistory")
        avg_conf_row = cursor.fetchone()[0]
        avg_confidence = round(float(avg_conf_row), 1) if avg_conf_row else 0.0

        # 2. Prediction distribution
        cursor.execute(
            "SELECT prediction, COUNT(*) as cnt FROM ScanHistory GROUP BY prediction"
        )
        prediction_dist = {row["prediction"]: row["cnt"] for row in cursor.fetchall()}

        # Ensure all 4 classes exist in distribution
        for cls in ["Safe", "Suspicious", "Phishing", "Malicious"]:
            prediction_dist.setdefault(cls, 0)

        # 3. Top suspicious/phishing domains
        cursor.execute(
            """
            SELECT domain, COUNT(*) as count, prediction, MAX(confidence) as max_conf
            FROM ScanHistory
            WHERE prediction IN ('Phishing', 'Malicious', 'Suspicious')
            GROUP BY domain
            ORDER BY count DESC
            LIMIT 7
            """
        )
        top_suspicious = [dict(r) for r in cursor.fetchall()]

        # 4. Recent scan timeline (last 7 days / grouping)
        cursor.execute(
            """
            SELECT DATE(created_at) as scan_date,
                   SUM(CASE WHEN prediction = 'Safe' THEN 1 ELSE 0 END) as safe_cnt,
                   SUM(CASE WHEN prediction IN ('Phishing', 'Malicious') THEN 1 ELSE 0 END) as phish_cnt,
                   SUM(CASE WHEN prediction = 'Suspicious' THEN 1 ELSE 0 END) as susp_cnt,
                   COUNT(*) as total
            FROM ScanHistory
            GROUP BY DATE(created_at)
            ORDER BY scan_date DESC
            LIMIT 14
            """
        )
        daily_scans = [dict(r) for r in cursor.fetchall()]

        # 5. Confidence Distribution ranges
        cursor.execute(
            """
            SELECT
                SUM(CASE WHEN confidence >= 90 THEN 1 ELSE 0 END) as range_90_100,
                SUM(CASE WHEN confidence >= 75 AND confidence < 90 THEN 1 ELSE 0 END) as range_75_90,
                SUM(CASE WHEN confidence >= 50 AND confidence < 75 THEN 1 ELSE 0 END) as range_50_75,
                SUM(CASE WHEN confidence < 50 THEN 1 ELSE 0 END) as range_0_50
            FROM ScanHistory
            """
        )
        conf_row = cursor.fetchone()
        conf_dist = {
            "90-100%": conf_row[0] or 0,
            "75-89%": conf_row[1] or 0,
            "50-74%": conf_row[2] or 0,
            "< 50%": conf_row[3] or 0
        }

        # 6. User feedback counts
        cursor.execute("SELECT COUNT(*) FROM Reports WHERE user_feedback = 'false_positive'")
        fp_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM Reports WHERE user_feedback = 'false_negative'")
        fn_count = cursor.fetchone()[0]

        return {
            "total_scans": total_scans,
            "safe_scans": safe_count,
            "suspicious_scans": suspicious_count,
            "dangerous_scans": dangerous_count,
            "blocked_domains": blocked_count,
            "average_confidence": avg_confidence,
            "prediction_distribution": prediction_dist,
            "top_suspicious_domains": top_suspicious,
            "daily_scans": daily_scans,
            "confidence_distribution": conf_dist,
            "false_positives": fp_count,
            "false_negatives": fn_count
        }
    finally:
        conn.close()


# ==========================================
# Model Metrics & Settings Operations
# ==========================================

def save_model_benchmarks(benchmarks: Dict[str, Any], active_model_name: str):
    """Persists model comparison benchmarks into ModelMetrics table."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM ModelMetrics")  # Refresh with current benchmarks
        for name, metrics in benchmarks.items():
            cursor.execute(
                """
                INSERT INTO ModelMetrics (
                    model_name, accuracy, precision_score, recall,
                    f1, roc_auc, training_time, is_active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    metrics["accuracy"],
                    metrics["precision"],
                    metrics["recall"],
                    metrics["f1_score"],
                    metrics["roc_auc"],
                    metrics["training_time"],
                    1 if name == active_model_name else 0
                )
            )
        conn.commit()
    finally:
        conn.close()


def get_model_benchmarks() -> List[Dict[str, Any]]:
    """Returns stored benchmark metrics for all models."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM ModelMetrics ORDER BY f1 DESC")
        return [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()


def get_settings() -> Dict[str, str]:
    """Retrieves all system configuration settings."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM Settings")
        return {r["key"]: r["value"] for r in cursor.fetchall()}
    finally:
        conn.close()


def update_setting(key: str, value: str) -> bool:
    """Updates a system setting by key."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE Settings SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?",
            (value, key)
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


# Initialize database schema on load
init_db()
