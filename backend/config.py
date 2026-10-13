"""
PHISH GUARD - Backend Configuration
Configuration parameters, thresholds, paths, and environment settings.
"""

import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Database & Models
DB_PATH = os.path.join(BASE_DIR, "database", "phishguard.db")
MODEL_PATH = os.path.join(BASE_DIR, "models", "model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "models", "scaler.pkl")
METADATA_PATH = os.path.join(BASE_DIR, "models", "metadata.json")

# Server settings
HOST = "127.0.0.1"
PORT = 5000
DEBUG = False

# Risk thresholds (calibrated probabilities from ML model)
THRESHOLD_PHISHING = 0.75     # >= 0.75 classified as Phishing
THRESHOLD_SUSPICIOUS = 0.40   # 0.40 <= prob < 0.75 classified as Suspicious
# < 0.40 classified as Safe

# Rate Limiting
RATE_LIMIT_REQUESTS = 120    # Max requests per window
RATE_LIMIT_WINDOW_SECONDS = 60  # Window in seconds

# CORS Origins
ALLOWED_ORIGINS = ["*"]
