"""
PHISH GUARD - Model Service Module
Manages model loading, real-time feature extraction, probability inference,
risk level classification (Safe, Suspicious, Phishing, Malicious),
blacklist enforcement, and database scan persistence.
"""

import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd

# Adjust paths
BACKEND_DIR = os.path.dirname(__file__)
BASE_DIR = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
MODELS_DIR = os.path.join(BASE_DIR, "models")

from config import (
    MODEL_PATH,
    SCALER_PATH,
    METADATA_PATH,
    THRESHOLD_PHISHING,
    THRESHOLD_SUSPICIOUS
)
from feature_extractor import extract_features, get_feature_names
import database_manager
from logger import setup_logger
from security_utils import validate_and_sanitize_url

logger = setup_logger("phishguard.model_service")


class PhishGuardPredictor:
    """Singleton service for loading ML models and executing URL threat analysis."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PhishGuardPredictor, cls).__new__(cls)
            cls._instance.is_initialized = False
        return cls._instance

    def __init__(self):
        if self.is_initialized:
            return
        self.model = None
        self.scaler = None
        self.metadata = {}
        self.feature_names = get_feature_names()
        self.load_artifacts()
        self.is_initialized = True

    def load_artifacts(self) -> bool:
        """Loads trained model, scaler, and metadata JSON from disk."""
        try:
            if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
                self.model = joblib.load(MODEL_PATH)
                self.scaler = joblib.load(SCALER_PATH)
                logger.info("Machine Learning model and scaler loaded successfully.")
            else:
                logger.warning(f"Model or Scaler not found at {MODEL_PATH}. Operating in heuristic fallback mode.")

            if os.path.exists(METADATA_PATH):
                with open(METADATA_PATH, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
                logger.info(f"Loaded model metadata. Active model: {self.metadata.get('active_model_name', 'Unknown')}")
            return True
        except Exception as e:
            logger.error(f"Error loading model artifacts: {e}", exc_info=True)
            return False

    def predict_url(self, raw_url: str, client_ip: str = "127.0.0.1") -> Dict[str, Any]:
        """
        Executes complete threat analysis on an input URL:
        1. Validates and sanitizes URL
        2. Checks Blacklist database
        3. Extracts 30 features & detection reasons
        4. Evaluates ML model probability
        5. Combines ML probability and heuristic flags to determine status:
           ['Safe', 'Suspicious', 'Phishing', 'Malicious']
        6. Logs result to SQLite database
        7. Returns comprehensive response dictionary
        """
        start_time = time.perf_counter()

        # Step 1: Input validation
        is_valid, sanitized_url, err_msg = validate_and_sanitize_url(raw_url)
        if not is_valid:
            return {
                "success": False,
                "error": err_msg,
                "url": raw_url,
                "prediction": "Unknown",
                "risk_level": "None"
            }

        # Step 2: Feature extraction
        features_dict, reasons, metadata = extract_features(sanitized_url)
        domain = metadata.get("domain", "")

        # Step 3: Check Blacklist (Deterministic Defense)
        blacklisted, bl_reason = database_manager.is_blacklisted(domain, sanitized_url)
        if blacklisted:
            scan_time_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            reasons.insert(0, f"Domain matches active security blacklist: {bl_reason}")
            result = {
                "success": True,
                "url": sanitized_url,
                "domain": domain,
                "prediction": "Malicious",
                "risk_level": "Critical",
                "confidence": 99.9,
                "phishing_probability": 0.999,
                "scan_time_ms": scan_time_ms,
                "is_blacklisted": True,
                "reasons": reasons,
                "features": features_dict,
                "metadata": metadata
            }
            # Log to DB
            database_manager.log_scan(
                url=sanitized_url,
                domain=domain,
                prediction="Malicious",
                confidence=99.9,
                risk_level="Critical",
                scan_time_ms=scan_time_ms,
                reasons=reasons,
                features=features_dict,
                client_ip=client_ip
            )
            return result

        # Step 4: Machine Learning Inference
        ml_probability = 0.0
        if self.model is not None and self.scaler is not None:
            try:
                # Prepare feature vector DataFrame with proper column names
                feature_row = pd.DataFrame([[features_dict[name] for name in self.feature_names]], columns=self.feature_names)
                scaled_vector = self.scaler.transform(feature_row)

                if hasattr(self.model, "predict_proba"):
                    proba = self.model.predict_proba(scaled_vector)[0]
                    # Class 1 is phishing probability
                    ml_probability = float(proba[1])
                elif hasattr(self.model, "decision_function"):
                    df = self.model.decision_function(scaled_vector)[0]
                    # Sigmoid transform decision function to [0, 1]
                    ml_probability = float(1.0 / (1.0 + np.exp(-df)))
                else:
                    pred = self.model.predict(scaled_vector)[0]
                    ml_probability = 1.0 if pred == 1 else 0.0
            except Exception as e:
                logger.error(f"Inference error with ML model: {e}")
                ml_probability = self._heuristic_fallback_probability(features_dict)
        else:
            # Fallback heuristic probability if model not yet loaded
            ml_probability = self._heuristic_fallback_probability(features_dict)

        # Step 5: Heuristic Defense-in-Depth Adjustments
        # Certain severe indicators (IP address, brand spoofing, lookalikes) guarantee elevated risk
        if features_dict.get("has_ip_address", 0) == 1.0:
            ml_probability = max(ml_probability, 0.85)
        if features_dict.get("brand_impersonation", 0) == 1.0:
            ml_probability = max(ml_probability, 0.88)
        if features_dict.get("has_homoglyphs", 0) == 1.0:
            ml_probability = max(ml_probability, 0.82)

        # Step 6: Classification & Risk Level Mapping
        if ml_probability >= THRESHOLD_PHISHING:
            if features_dict.get("has_ip_address", 0) == 1.0 or features_dict.get("brand_impersonation", 0) == 1.0:
                prediction = "Malicious"
                risk_level = "Critical"
            else:
                prediction = "Phishing"
                risk_level = "High"
            confidence = round(ml_probability * 100.0, 1)
        elif ml_probability >= THRESHOLD_SUSPICIOUS:
            prediction = "Suspicious"
            risk_level = "Medium"
            confidence = round(ml_probability * 100.0, 1)
        else:
            prediction = "Safe"
            risk_level = "Low"
            confidence = round((1.0 - ml_probability) * 100.0, 1)

        scan_time_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        # Step 7: Persist Scan Record
        try:
            database_manager.log_scan(
                url=sanitized_url,
                domain=domain,
                prediction=prediction,
                confidence=confidence,
                risk_level=risk_level,
                scan_time_ms=scan_time_ms,
                reasons=reasons,
                features=features_dict,
                client_ip=client_ip
            )
        except Exception as e:
            logger.error(f"Failed to persist scan history: {e}")

        return {
            "success": True,
            "url": sanitized_url,
            "domain": domain,
            "prediction": prediction,
            "risk_level": risk_level,
            "confidence": confidence,
            "phishing_probability": round(ml_probability, 4),
            "scan_time_ms": scan_time_ms,
            "is_blacklisted": False,
            "reasons": reasons,
            "features": features_dict,
            "metadata": metadata
        }

    def _heuristic_fallback_probability(self, features: Dict[str, float]) -> float:
        """Lightweight heuristic risk scorer when ML model is unavailable."""
        score = 0.0
        if features.get("has_ip_address", 0) == 1.0:
            score += 0.40
        if features.get("brand_impersonation", 0) == 1.0:
            score += 0.45
        if features.get("has_homoglyphs", 0) == 1.0:
            score += 0.35
        if features.get("has_punycode", 0) == 1.0:
            score += 0.30
        if features.get("tld_risk_score", 0) == 1.0:
            score += 0.25
        if features.get("is_shortened_url", 0) == 1.0:
            score += 0.20
        if features.get("suspicious_keywords_count", 0) >= 2:
            score += 0.25
        elif features.get("suspicious_keywords_count", 0) == 1:
            score += 0.10
        if features.get("has_https", 0) == 0.0:
            score += 0.15
        if features.get("count_subdomains", 0) >= 3:
            score += 0.15

        return round(min(score, 0.99), 4)

    def get_model_information(self) -> Dict[str, Any]:
        """Returns details about currently active model and comparison benchmarks."""
        benchmarks = database_manager.get_model_benchmarks()
        active_name = self.metadata.get("active_model_name", "Random Forest")
        return {
            "active_model_name": active_name,
            "feature_count": len(self.feature_names),
            "feature_names": self.feature_names,
            "champion_metrics": self.metadata.get("champion_metrics", {}),
            "feature_importances": self.metadata.get("feature_importances", {}),
            "all_model_benchmarks": benchmarks or self.metadata.get("all_model_benchmarks", {}),
            "created_at": self.metadata.get("created_at", "N/A"),
            "status": "online" if self.model is not None else "degraded (heuristic mode)"
        }


# Global predictor instance
predictor_service = PhishGuardPredictor()
