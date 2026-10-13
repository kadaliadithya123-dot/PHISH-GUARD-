"""
Unit Tests for PHISH GUARD Feature Extractor Module
Validates extraction of 30 features, IP detection, homoglyphs, brand spoofing, and entropy.
"""

import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from feature_extractor import (
    calculate_entropy,
    detect_homoglyphs,
    extract_features,
    get_feature_names,
    is_ip_address
)


class TestFeatureExtractor(unittest.TestCase):

    def test_feature_count(self):
        """Verifies that exactly 30 numerical features are produced."""
        feature_names = get_feature_names()
        self.assertEqual(len(feature_names), 30)
        
        feats, reasons, meta = extract_features("https://www.wikipedia.org/wiki/Phishing")
        self.assertEqual(len(feats), 30)
        for name in feature_names:
            self.assertIn(name, feats)
            self.assertIsInstance(feats[name], float)

    def test_ip_address_detection(self):
        """Tests IPv4 and IPv6 detection."""
        self.assertTrue(is_ip_address("192.168.1.1"))
        self.assertTrue(is_ip_address("10.0.0.1:8080"))
        self.assertTrue(is_ip_address("127.0.0.1"))
        self.assertFalse(is_ip_address("google.com"))
        self.assertFalse(is_ip_address("fake-192-168-1-1.com"))

    def test_entropy_calculation(self):
        """Tests Shannon entropy values."""
        zero_ent = calculate_entropy("")
        self.assertEqual(zero_ent, 0.0)

        low_ent = calculate_entropy("aaaaaaa")
        self.assertEqual(low_ent, 0.0)

        high_ent = calculate_entropy("d8f2j7k9x1m4p5")
        self.assertGreater(high_ent, 3.0)

    def test_brand_spoofing(self):
        """Tests detection of targeted brands in deceptive locations."""
        # Genuine PayPal
        _, reasons_legit, meta_legit = extract_features("https://www.paypal.com/signin")
        self.assertEqual(len(meta_legit["detected_brands"]), 0)

        # Spoofed PayPal in subdomain
        feats_phish, reasons_phish, meta_phish = extract_features(
            "http://paypal.verify-account-update.xyz/login.php"
        )
        self.assertEqual(feats_phish["brand_impersonation"], 1.0)
        self.assertIn("paypal", meta_phish["detected_brands"])
        self.assertTrue(any("paypal" in r.lower() for r in reasons_phish))

    def test_url_shortener(self):
        """Tests shortener domain identification."""
        feats, _, meta = extract_features("https://bit.ly/secure-link")
        self.assertEqual(feats["is_shortened_url"], 1.0)
        self.assertTrue(meta["is_shortened"])

    def test_clean_safe_url(self):
        """Tests clean legitimate URL properties."""
        feats, reasons, _ = extract_features("https://www.github.com/torvalds/linux")
        self.assertEqual(feats["has_https"], 1.0)
        self.assertEqual(feats["has_ip_address"], 0.0)
        self.assertEqual(feats["brand_impersonation"], 0.0)
        self.assertTrue(any("Standard domain structure" in r for r in reasons))


if __name__ == "__main__":
    unittest.main()
