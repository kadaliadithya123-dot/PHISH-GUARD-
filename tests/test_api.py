"""
API Integration Tests for PHISH GUARD REST Endpoints
Validates /predict, /report, /history, /stats, /blacklist, /health, /model-info.
"""

import json
import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from app import app


class TestPhishGuardAPI(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def test_health_endpoint(self):
        """Verifies GET /health returns 200 and valid status."""
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data["status"], "healthy")
        self.assertTrue(data["database_connected"])
        self.assertTrue(data["ml_engine_loaded"])

    def test_predict_endpoint_safe(self):
        """Tests POST /predict with safe URL."""
        payload = {"url": "https://www.wikipedia.org"}
        resp = self.client.post("/predict", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["data"]["prediction"], "Safe")
        self.assertIn("confidence", data["data"])
        self.assertIn("scan_time_ms", data["data"])

    def test_predict_endpoint_phishing(self):
        """Tests POST /predict with phishing URL."""
        payload = {"url": "http://paypal-security-verification.top/signin.php"}
        resp = self.client.post("/predict", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn(data["data"]["prediction"], ["Phishing", "Malicious"])
        self.assertIn(data["data"]["risk_level"], ["High", "Critical"])

    def test_predict_missing_url(self):
        """Tests POST /predict error handling with invalid payload."""
        resp = self.client.post("/predict", json={})
        self.assertEqual(resp.status_code, 400)

    def test_report_endpoint(self):
        """Tests POST /report for false positive submission."""
        payload = {
            "url": "https://false-alarm-example.com",
            "feedback": "false_positive",
            "reported_type": "Safe",
            "actual_status": "Phishing",
            "comments": "This is our internal company portal."
        }
        resp = self.client.post("/report", json=payload)
        self.assertEqual(resp.status_code, 201)
        data = json.loads(resp.data)
        self.assertEqual(data["status"], "success")
        self.assertIn("report_id", data)

    def test_stats_endpoint(self):
        """Tests GET /stats returns expected metrics."""
        resp = self.client.get("/stats")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        stats = data["stats"]
        self.assertIn("total_scans", stats)
        self.assertIn("safe_scans", stats)
        self.assertIn("dangerous_scans", stats)
        self.assertIn("prediction_distribution", stats)

    def test_history_endpoint(self):
        """Tests GET /history returns scan records."""
        resp = self.client.get("/history?limit=10")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("history", data)
        self.assertIsInstance(data["history"], list)

    def test_blacklist_lifecycle(self):
        """Tests GET, POST, and DELETE on /blacklist."""
        # 1. Add item
        payload = {
            "pattern": "malicious-test-tracker.xyz",
            "domain": "malicious-test-tracker.xyz",
            "reason": "Test tracker blacklist"
        }
        post_resp = self.client.post("/blacklist", json=payload)
        self.assertEqual(post_resp.status_code, 201)
        item_id = json.loads(post_resp.data)["id"]

        # 2. Verify presence in GET
        get_resp = self.client.get("/blacklist")
        self.assertEqual(get_resp.status_code, 200)
        bl_items = json.loads(get_resp.data)["blacklist"]
        self.assertTrue(any(b["id"] == item_id for b in bl_items))

        # 3. Delete item
        del_resp = self.client.delete(f"/blacklist?id={item_id}")
        self.assertEqual(del_resp.status_code, 200)

    def test_model_info_endpoint(self):
        """Tests GET /model-info returns active model metadata."""
        resp = self.client.get("/model-info")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("active_model_name", data["data"])
        self.assertIn("all_model_benchmarks", data["data"])


if __name__ == "__main__":
    unittest.main()
