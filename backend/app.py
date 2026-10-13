"""
PHISH GUARD - Flask REST API Backend
Production-grade RESTful API server for real-time URL phishing detection,
administrative analytics, blacklist management, and threat reporting.
"""

import os
import sys
import time
from typing import Any, Dict
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

# Add current directory to path
sys.path.append(os.path.dirname(__file__))

import config
import database_manager
from logger import setup_logger
from model_service import predictor_service
from security_utils import (
    add_security_headers,
    rate_limit,
    sanitize_string,
    validate_and_sanitize_url
)

logger = setup_logger("phishguard.api")

# Base directory paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DASHBOARD_DIR = os.path.join(BASE_DIR, "admin_dashboard")

app = Flask(__name__, static_folder=DASHBOARD_DIR)
CORS(app, resources={r"/*": {"origins": "*"}})

START_TIME = time.time()


@app.after_request
def apply_security_headers(response):
    """Applies security headers to every response."""
    return add_security_headers(response)


# ==========================================
# Frontend / Dashboard Routes
# ==========================================

@app.route("/", methods=["GET"])
@app.route("/dashboard", methods=["GET"])
def serve_dashboard():
    """Serves the Admin Dashboard single page application."""
    return send_from_directory(DASHBOARD_DIR, "index.html")


@app.route("/css/<path:path>", methods=["GET"])
def serve_dashboard_css(path):
    """Serves CSS assets for Admin Dashboard."""
    return send_from_directory(os.path.join(DASHBOARD_DIR, "css"), path)


@app.route("/js/<path:path>", methods=["GET"])
def serve_dashboard_js(path):
    """Serves JavaScript assets for Admin Dashboard."""
    return send_from_directory(os.path.join(DASHBOARD_DIR, "js"), path)


# ==========================================
# Core Detection & API Endpoints
# ==========================================

@app.route("/predict", methods=["POST"])
@rate_limit
def predict():
    """
    POST /predict
    Receives JSON: { "url": "https://example.com" }
    Extracts features, evaluates ML model, checks blacklist,
    and returns comprehensive threat classification.
    """
    if not request.is_json:
        return jsonify({"status": "error", "message": "Request must be JSON with 'url' field."}), 400

    data = request.get_json(silent=True) or {}
    raw_url = data.get("url")

    if not raw_url:
        return jsonify({"status": "error", "message": "Missing required field: 'url'."}), 400

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "127.0.0.1"
    client_ip = client_ip.split(",")[0].strip()

    logger.info(f"Scan requested for URL: {raw_url[:80]} from IP: {client_ip}")

    # Execute threat analysis
    result = predictor_service.predict_url(raw_url=raw_url, client_ip=client_ip)

    if not result.get("success", False):
        return jsonify({"status": "error", "message": result.get("error", "Invalid URL")}), 400

    return jsonify({
        "status": "success",
        "data": result
    }), 200


@app.route("/report", methods=["POST"])
@rate_limit
def report():
    """
    POST /report
    Receives user feedback for false positive or false negative reporting.
    JSON: {
        "url": "https://example.com",
        "feedback": "false_positive" | "false_negative",
        "reported_type": "Safe",
        "actual_status": "Phishing",
        "comments": "Optional user comment"
    }
    """
    if not request.is_json:
        return jsonify({"status": "error", "message": "Request must be JSON."}), 400

    data = request.get_json(silent=True) or {}
    raw_url = data.get("url", "").strip()
    feedback = data.get("feedback", "").strip().lower()

    if not raw_url or feedback not in ["false_positive", "false_negative"]:
        return jsonify({
            "status": "error",
            "message": "Valid 'url' and 'feedback' ('false_positive' or 'false_negative') are required."
        }), 400

    reported_type = sanitize_string(data.get("reported_type", ""))
    actual_status = sanitize_string(data.get("actual_status", ""))
    comments = sanitize_string(data.get("comments", ""))

    report_id = database_manager.add_report(
        url=raw_url,
        feedback=feedback,
        reported_type=reported_type,
        actual_status=actual_status,
        comments=comments
    )

    logger.info(f"User report filed (#{report_id}) for {raw_url} - Feedback: {feedback}")

    return jsonify({
        "status": "success",
        "message": "Feedback submitted successfully. Thank you for contributing to Phish Guard accuracy.",
        "report_id": report_id
    }), 201


@app.route("/history", methods=["GET"])
def get_history():
    """
    GET /history
    Returns paginated scan history.
    Query parameters:
        limit: int (default 50)
        offset: int (default 0)
        status: string ('Safe', 'Phishing', 'Suspicious', 'Malicious', 'all')
        search: string
    """
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        limit = 50
        offset = 0

    status = request.args.get("status")
    search = request.args.get("search")

    history, total = database_manager.get_scan_history(
        limit=limit,
        offset=offset,
        filter_status=status,
        search=search
    )

    return jsonify({
        "status": "success",
        "total": total,
        "limit": limit,
        "offset": offset,
        "history": history
    }), 200


@app.route("/stats", methods=["GET"])
def get_stats():
    """
    GET /stats
    Returns aggregated dashboard statistics, trends, and threat distributions.
    """
    stats = database_manager.get_dashboard_statistics()
    return jsonify({
        "status": "success",
        "stats": stats
    }), 200


@app.route("/blacklist", methods=["GET", "POST", "DELETE"])
def manage_blacklist():
    """
    GET /blacklist: List all blacklisted patterns
    POST /blacklist: Add pattern to blacklist { "pattern": "...", "domain": "...", "reason": "..." }
    DELETE /blacklist: Delete blacklist entry by ?id=1 or JSON { "id": 1 }
    """
    if request.method == "GET":
        items = database_manager.get_blacklist()
        return jsonify({
            "status": "success",
            "count": len(items),
            "blacklist": items
        }), 200

    elif request.method == "POST":
        data = request.get_json(silent=True) or {}
        pattern = sanitize_string(data.get("pattern", ""))
        domain = sanitize_string(data.get("domain", pattern))
        reason = sanitize_string(data.get("reason", "Added via Admin API"))

        if not pattern:
            return jsonify({"status": "error", "message": "Pattern/Domain is required."}), 400

        entry_id = database_manager.add_to_blacklist(
            pattern=pattern,
            domain=domain,
            reason=reason,
            added_by="admin"
        )
        logger.info(f"Blacklist entry added: {pattern}")
        return jsonify({
            "status": "success",
            "message": f"Successfully blacklisted '{pattern}'.",
            "id": entry_id
        }), 201

    elif request.method == "DELETE":
        item_id = request.args.get("id")
        if not item_id and request.is_json:
            item_id = (request.get_json(silent=True) or {}).get("id")

        if not item_id:
            return jsonify({"status": "error", "message": "Blacklist item 'id' is required."}), 400

        try:
            item_id = int(item_id)
        except ValueError:
            return jsonify({"status": "error", "message": "Invalid item ID."}), 400

        removed = database_manager.remove_from_blacklist(item_id)
        if removed:
            logger.info(f"Blacklist item removed: ID {item_id}")
            return jsonify({
                "status": "success",
                "message": f"Blacklist entry {item_id} removed successfully."
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": f"Blacklist entry {item_id} not found."
            }), 404


@app.route("/health", methods=["GET"])
def health():
    """
    GET /health
    Healthcheck endpoint reporting server uptime, ML model status, and DB status.
    """
    uptime_seconds = round(time.time() - START_TIME, 1)
    db_connected = True
    try:
        conn = database_manager.get_db_connection()
        conn.cursor().execute("SELECT 1")
        conn.close()
    except Exception:
        db_connected = False

    return jsonify({
        "status": "healthy" if db_connected else "degraded",
        "service": "PHISH GUARD Detection Engine",
        "version": "1.0.0",
        "uptime_seconds": uptime_seconds,
        "database_connected": db_connected,
        "ml_engine_loaded": predictor_service.model is not None,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }), 200


@app.route("/model-info", methods=["GET"])
def model_info():
    """
    GET /model-info
    Returns detailed information about the active machine learning model,
    feature count, feature importances, and benchmarks across all tested algorithms.
    """
    info = predictor_service.get_model_information()
    return jsonify({
        "status": "success",
        "data": info
    }), 200


@app.route("/reports", methods=["GET"])
def list_reports():
    """
    GET /reports
    Admin endpoint returning all user feedback and false positive reports.
    """
    reports = database_manager.get_reports()
    return jsonify({
        "status": "success",
        "count": len(reports),
        "reports": reports
    }), 200


@app.route("/api/settings", methods=["GET", "POST"])
def manage_settings():
    """
    GET /api/settings: Retrieve all settings
    POST /api/settings: Update a setting { "key": "...", "value": "..." }
    """
    if request.method == "GET":
        settings = database_manager.get_settings()
        return jsonify({"status": "success", "settings": settings}), 200

    elif request.method == "POST":
        data = request.get_json(silent=True) or {}
        key = sanitize_string(data.get("key", ""))
        value = sanitize_string(data.get("value", ""))

        if not key or not value:
            return jsonify({"status": "error", "message": "Key and value are required."}), 400

        updated = database_manager.update_setting(key, value)
        return jsonify({
            "status": "success" if updated else "error",
            "message": f"Setting '{key}' updated." if updated else f"Failed to update '{key}'."
        }), 200 if updated else 400


# ==========================================
# Error Handlers
# ==========================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({"status": "error", "message": "Resource not found"}), 404


@app.errorhandler(500)
def server_error(e):
    logger.error(f"Internal server error: {e}", exc_info=True)
    return jsonify({"status": "error", "message": "Internal server error"}), 500


if __name__ == "__main__":
    logger.info(f"Starting PHISH GUARD Backend on http://{config.HOST}:{config.PORT}")
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
