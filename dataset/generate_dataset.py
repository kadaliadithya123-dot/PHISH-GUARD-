"""
PHISH GUARD - Dataset Generator
Generates a comprehensive, realistic, and diverse dataset of legitimate,
suspicious, and phishing URLs for training and evaluating machine learning models.
"""

import csv
import os
import random
from typing import List, Tuple

# Output dataset file path
OUTPUT_CSV = os.path.join(os.path.dirname(__file__), "urls_dataset.csv")

# 1. Legitimate base domains across domains & sectors
LEGITIMATE_BASE_DOMAINS = [
    # Search & Tech Giants
    "google.com", "microsoft.com", "apple.com", "amazon.com", "meta.com",
    "github.com", "gitlab.com", "stackoverflow.com", "wikipedia.org", "mozilla.org",
    "python.org", "npmjs.com", "docker.com", "cloudflare.com", "digitalocean.com",
    "oracle.com", "ibm.com", "intel.com", "cisco.com", "salesforce.com",
    # Finance & Banking
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "paypal.com",
    "stripe.com", "visa.com", "mastercard.com", "americanexpress.com", "fidelity.com",
    "schwab.com", "vanguard.com", "capitalone.com", "goldmansachs.com", "bloomberg.com",
    # E-Commerce & Retail
    "ebay.com", "walmart.com", "target.com", "bestbuy.com", "aliexpress.com",
    "etsy.com", "shopify.com", "ikea.com", "homedepot.com", "costco.com",
    # News & Media
    "nytimes.com", "bbc.com", "cnn.com", "reuters.com", "theguardian.com",
    "washingtonpost.com", "forbes.com", "wsj.com", "nature.com", "medium.com",
    # Social & Communication
    "linkedin.com", "reddit.com", "twitter.com", "instagram.com", "slack.com",
    "discord.com", "zoom.us", "quora.com", "pinterest.com", "twitch.tv",
    # Education & Government
    "mit.edu", "stanford.edu", "harvard.edu", "ox.ac.uk", "berkeley.edu",
    "nih.gov", "nasa.gov", "cdc.gov", "who.int", "un.org"
]

LEGIT_SUBDOMAINS = [
    "www", "docs", "api", "support", "developer", "blog", "cloud",
    "mail", "portal", "status", "store", "app", "dashboard", "help"
]

LEGIT_PATHS = [
    "",
    "/about",
    "/contact-us",
    "/products",
    "/services/enterprise",
    "/documentation/getting-started",
    "/api/v2/reference",
    "/articles/2026/03/technology-update",
    "/blog/engineering-insights",
    "/careers/open-positions",
    "/terms-of-service",
    "/privacy-policy",
    "/help/kb/article-1029",
    "/downloads/releases/version-3.4",
    "/community/forum/topic/45892",
    "/resources/whitepapers/cloud-security",
    "/events/annual-summit-2026",
    "/newsroom/press-releases"
]

LEGIT_PARAMS = [
    "",
    "?lang=en",
    "?id=84920&page=2",
    "?query=machine+learning+tutorial",
    "?ref=home_hero",
    "?utm_source=newsletter&utm_medium=email",
    "?tab=overview&view=grid",
    "?sort=newest&filter=active",
    "?category=software&subcat=tools"
]

# 2. Phishing components for synthetic malicious patterns
SPOOFED_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "chase", "wellsfargo", "bankofamerica", "coinbase", "binance",
    "metamask", "outlook", "icloud", "yahoo", "steam", "roblox", "ebay"
]

PHISH_KEYWORDS = [
    "login", "signin", "verify", "secure", "verification", "account-update",
    "wallet-recovery", "banking-portal", "confirm-identity", "unlock-account",
    "security-alert", "session-expired", "auth-token", "kyc-update", "password-reset",
    "billing-statement", "invoice-pdf", "urgent-notice", "bonus-claim"
]

SUSPICIOUS_TLDS = [
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club",
    "work", "fit", "icu", "click", "rest", "cam", "loan", "men",
    "stream", "download", "racing", "win", "bid", "vip", "monster",
    "casa", "surf", "cfd", "sbs"
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "tiny.cc"
]


def generate_legitimate_urls(count: int = 2000) -> List[Tuple[str, int, str]]:
    """Generates legitimate URLs with proper domains, protocols, and standard structures."""
    urls = []
    random.seed(42)

    for _ in range(count):
        base = random.choice(LEGITIMATE_BASE_DOMAINS)
        use_sub = random.random() < 0.45
        sub = random.choice(LEGIT_SUBDOMAINS) if use_sub else ""
        
        domain = f"{sub}.{base}" if sub else base
        path = random.choice(LEGIT_PATHS)
        param = random.choice(LEGIT_PARAMS)
        protocol = "https" if random.random() < 0.96 else "http"
        
        url = f"{protocol}://{domain}{path}{param}"
        urls.append((url, 0, "safe"))

    return urls


def generate_phishing_urls(count: int = 2000) -> List[Tuple[str, int, str]]:
    """Generates varied phishing URLs covering different attack vectors."""
    urls = []
    random.seed(1337)

    templates = [
        # 1. Brand spoof in subdomain on untrusted domain
        lambda: (
            f"http://{random.choice(SPOOFED_BRANDS)}-{random.choice(PHISH_KEYWORDS)}."
            f"{random.choice(['free-hosting', 'secureserver', 'myweb', 'dynamic-dns', 'net-portal', 'auth-check'])}."
            f"{random.choice(SUSPICIOUS_TLDS)}/{random.choice(PHISH_KEYWORDS)}.php?session={random.randint(10000, 99999)}",
            "phishing"
        ),
        # 2. Brand impersonation with high-risk TLD
        lambda: (
            f"https://{random.choice(SPOOFED_BRANDS)}-{random.choice(PHISH_KEYWORDS)}.{random.choice(SUSPICIOUS_TLDS)}/"
            f"auth/{random.choice(PHISH_KEYWORDS)}?token={random.randint(100000, 999999)}",
            "phishing"
        ),
        # 3. Direct IP address based phishing URL
        lambda: (
            f"http://{random.randint(100, 220)}.{random.randint(10, 250)}.{random.randint(1, 250)}.{random.randint(1, 250)}/"
            f"{random.choice(SPOOFED_BRANDS)}/{random.choice(PHISH_KEYWORDS)}.html",
            "malicious"
        ),
        # 4. Punycode (IDN homograph) phishing
        lambda: (
            f"https://xn--{random.choice(['appl', 'microsft', 'gogle', 'paypl', 'amazn'])}-83k.{random.choice(['com', 'net', 'xyz'])}/"
            f"{random.choice(PHISH_KEYWORDS)}",
            "phishing"
        ),
        # 5. Excessive subdomains mimicking secure infrastructure
        lambda: (
            f"http://{random.choice(PHISH_KEYWORDS)}.{random.choice(SPOOFED_BRANDS)}.com.{random.choice(['attacker', 'gate-sys', 'cdn-relay'])}."
            f"{random.choice(SUSPICIOUS_TLDS)}/{random.choice(PHISH_KEYWORDS)}/index.php",
            "phishing"
        ),
        # 6. Deceptive @ sign URL routing trick
        lambda: (
            f"https://{random.choice(LEGITIMATE_BASE_DOMAINS)}@{random.choice(['harvest-login', 'credential-checker', 'phish-node'])}."
            f"{random.choice(SUSPICIOUS_TLDS)}/{random.choice(PHISH_KEYWORDS)}",
            "phishing"
        ),
        # 7. URL shortener concealing malicious destination
        lambda: (
            f"http://{random.choice(SHORTENER_DOMAINS)}/{random.choice(['xY79Q', '9L01p', 'secAcc', 'bAnk9', '2PqxZ', 'LgIn7'])}",
            "suspicious"
        ),
        # 8. High-entropy DGA domain with phishing path
        lambda: (
            f"http://{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(14, 24)))}."
            f"{random.choice(SUSPICIOUS_TLDS)}/{random.choice(PHISH_KEYWORDS)}",
            "malicious"
        ),
        # 9. Double slash redirect / path deception
        lambda: (
            f"http://{random.choice(['login-verify-service', 'account-notification-alert', 'secure-cloud-center'])}."
            f"{random.choice(SUSPICIOUS_TLDS)}//{random.choice(LEGITIMATE_BASE_DOMAINS)}/{random.choice(PHISH_KEYWORDS)}",
            "phishing"
        ),
        # 10. Legitimate TLD in subdomain deception
        lambda: (
            f"http://{random.choice(SPOOFED_BRANDS)}.com.security-verification-{random.randint(10, 99)}.{random.choice(SUSPICIOUS_TLDS)}/index.html",
            "phishing"
        )
    ]

    for _ in range(count):
        template_func = random.choice(templates)
        url, cat = template_func()
        urls.append((url, 1, cat))

    return urls


def create_dataset(output_path: str = OUTPUT_CSV, total_samples: int = 4000) -> str:
    """Generates balanced dataset and writes to CSV file."""
    half = total_samples // 2
    print(f"[*] Generating {half} legitimate URLs...")
    legit_samples = generate_legitimate_urls(half)
    
    print(f"[*] Generating {half} phishing and malicious URLs...")
    phish_samples = generate_phishing_urls(half)
    
    all_samples = legit_samples + phish_samples
    random.shuffle(all_samples)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label", "category"])
        for url, label, category in all_samples:
            writer.writerow([url, label, category])

    print(f"[+] Dataset successfully created at: {output_path}")
    print(f"[+] Total samples: {len(all_samples)} (Safe: {half}, Phishing/Malicious: {half})")
    return output_path


if __name__ == "__main__":
    create_dataset()
