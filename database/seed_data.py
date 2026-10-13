"""
PHISH GUARD - Database Seeder
Populates initial sample scans, reports, and blacklist rules for demonstration and testing.
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from model_service import predictor_service
import database_manager

SAMPLE_URLS = [
    # Safe
    "https://www.google.com/search?q=machine+learning+security",
    "https://github.com/torvalds/linux",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://www.python.org/downloads/release/python-3130/",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP",
    "https://www.nytimes.com/section/technology",
    "https://stackoverflow.com/questions/tagged/python",
    "https://www.microsoft.com/en-us/security",
    
    # Phishing / Malicious
    "http://paypal-verification-alert-account.xyz/login.php",
    "http://192.168.1.100/admin/auth/credential-harvest",
    "http://appleid-security-update-center.top/verify.php",
    "http://netflix-billing-reactivate-alert.buzz/signin",
    "https://chase-bank-verify-identity.xyz/auth.html",
    "http://wellsfargo-account-locked-resolution.cfd/login",
    "http://185.220.101.5/banking/signin",
    
    # Suspicious
    "https://bit.ly/3xY9zq",
    "http://free-giftcard-rewards-now.work/claim?id=4920",
    "http://system-update-speed-boost.fit/download.exe"
]

def seed_database():
    print("[*] Initializing database schema...")
    database_manager.init_db()
    
    print("[*] Running initial scans to populate real-time SOC telemetry...")
    for u in SAMPLE_URLS:
        res = predictor_service.predict_url(u)
        print(f"  + Scanned: {u[:45]}... -> {res['prediction']} ({res['confidence']}%)")

    # Add sample feedback reports
    print("[*] Seeding sample threat reports...")
    database_manager.add_report(
        url="https://secure-internal-dev.company.net",
        feedback="false_positive",
        reported_type="Safe",
        actual_status="Suspicious",
        comments="Internal staging server flagged due to uncommon domain structure."
    )
    database_manager.add_report(
        url="http://brand-new-phish-domain.xyz/login",
        feedback="false_negative",
        reported_type="Phishing",
        actual_status="Safe",
        comments="Newly registered domain mimicking banking page."
    )
    
    print("[+] Seeding completed successfully.")

if __name__ == "__main__":
    seed_database()
