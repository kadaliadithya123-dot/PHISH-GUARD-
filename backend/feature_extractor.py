"""
PHISH GUARD - Feature Extractor Module
Extracts 30+ lexical, structural, statistical, and security features from URLs
for Machine Learning classification and rule-based threat assessment.
"""

import math
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlparse

# High-profile brands frequently targeted by phishing campaigns
TARGETED_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "twitter", "linkedin",
    "binance", "coinbase", "metamask", "chase", "wellsfargo",
    "bankofamerica", "citibank", "dropbox", "adobe", "yahoo",
    "outlook", "icloud", "steam", "roblox", "ebay", "walmart"
]

# Suspicious keywords commonly found in credential-harvesting & phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "banking", "confirm", "confirmation",
    "password", "credential", "wallet", "recover", "authenticate",
    "auth", "validation", "support", "billing", "invoice", "payment",
    "service", "alert", "notification", "free", "bonus", "reward",
    "suspended", "unlock", "ebayisapi", "webscr", "securelogin"
]

# Known URL shortener service domains
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "shorte.st",
    "tiny.cc", "bc.vc", "rb.gy", "trib.al", "s.id", "v.gd"
}

# High-risk Top-Level Domains according to Spamhaus & APWG statistics
HIGH_RISK_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club",
    "work", "fit", "icu", "click", "rest", "cam", "loan", "men",
    "stream", "download", "racing", "win", "bid", "vip", "monster",
    "casa", "surf", "cfd", "sbs"
}

# Common legitimate TLDs for deceptive subdomain checking
COMMON_TLDS = {"com", "org", "net", "edu", "gov", "co", "io", "info", "biz"}


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string to detect randomized or algorithmic generation (DGA).
    Returns a float representing entropy in bits per character.
    """
    if not text:
        return 0.0
    prob_dist = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob_dist])
    return round(entropy, 4)


def is_ip_address(domain: str) -> bool:
    """
    Check if domain is an IPv4 or IPv6 address.
    """
    # Clean domain of port
    clean_domain = domain.split(":")[0]

    # IPv4 regex
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, clean_domain):
        parts = clean_domain.split(".")
        return all(0 <= int(part) <= 255 for part in parts)

    # IPv6 regex
    ipv6_pattern = r"^[0-9a-fA-F:]+$"
    if ":" in clean_domain and re.match(ipv6_pattern, clean_domain):
        return True

    return False


def detect_homoglyphs(domain: str) -> bool:
    """
    Check if domain uses lookalike characters, mixed alphabets, or numbers substituting letters.
    E.g. 'g00gle', 'paypa1', 'micros0ft', or non-ASCII characters.
    """
    # Check for non-ASCII characters in domain
    try:
        domain.encode("ascii")
    except UnicodeEncodeError:
        return True

    # Check for common number substitutions in suspicious contexts
    substitutions = [
        r"p[a@]yp[a@][1l]",
        r"g[0o]{2}gle",
        r"m[i1]cr[0o]s[0o]ft",
        r"[a@][p1]{2}le",
        r"[a@]m[a@]z[0o]n",
        r"netfl[i1]x",
        r"f[a@]ceb[0o]{2}k"
    ]
    domain_lower = domain.lower()
    for pattern in substitutions:
        if re.search(pattern, domain_lower):
            # Check if it is the genuine name or spoofed
            clean_name = re.sub(r"[^a-z]", "", domain_lower)
            if any(b in clean_name for b in ["paypal", "google", "microsoft", "apple", "amazon", "netflix", "facebook"]):
                # If numbers were present in original domain where letters should be
                if re.search(r"[0-9]", domain_lower):
                    return True

    return False


def extract_features(raw_url: str) -> Tuple[Dict[str, float], List[str], Dict[str, Any]]:
    """
    Extracts all 30 numerical features and human-readable detection reasons from a URL.
    Returns:
        (features_dict, detection_reasons, metadata_dict)
    """
    # Ensure scheme for proper urlparse handling
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        # Default parse assumption for analysis
        parsed = urlparse("http://" + url)
        has_scheme = False
    else:
        parsed = urlparse(url)
        has_scheme = True

    scheme = parsed.scheme.lower() if has_scheme else ""
    netloc = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment

    # Clean domain (remove port if present)
    domain = netloc.split(":")[0] if ":" in netloc else netloc
    
    # Domain parts and TLD extraction
    domain_parts = domain.split(".") if domain else []
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""
    subdomains = domain_parts[:-2] if len(domain_parts) > 2 else []
    num_subdomains = len(subdomains)

    # 1. Length features
    url_length = len(url)
    domain_length = len(domain)
    path_length = len(path)

    # 2. Character counts
    count_dots = url.count(".")
    count_hyphens = url.count("-")
    count_digits = sum(c.isdigit() for c in url)
    count_at = url.count("@")
    count_percent = url.count("%")
    count_underscore = url.count("_")
    count_equal = url.count("=")
    count_question = url.count("?")
    count_ampersand = url.count("&")
    
    # 3. Protocol features
    has_https = 1.0 if scheme == "https" else 0.0
    has_http = 1.0 if scheme == "http" else 0.0

    # 4. Security & IP detection
    has_ip = 1.0 if is_ip_address(domain) else 0.0

    # 5. Path anomalies
    # Check for // in path portion (often used to redirect or hide true target)
    has_double_slash_path = 1.0 if "//" in path else 0.0

    # 6. Parameters
    num_parameters = float(len(parse_qs(query))) if query else 0.0

    # 7. Entropy
    url_entropy = calculate_entropy(url)
    domain_entropy = calculate_entropy(domain)

    # 8. Suspicious keywords count
    url_lower = url.lower()
    suspicious_kw_found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    suspicious_keywords_count = float(len(suspicious_kw_found))

    # 9. Brand impersonation detection
    # Check if a known brand is present in subdomains or path, but NOT the registered root domain
    brand_impersonation = 0.0
    detected_brand_spoof = []
    registered_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain

    for brand in TARGETED_BRANDS:
        # If brand in URL but root domain is NOT brand + standard TLD
        if brand in url_lower:
            is_official = any(
                registered_domain == f"{brand}.{known_tld}" or registered_domain == f"{brand}.co.{known_tld}"
                for known_tld in ["com", "org", "net", "io", "co", "uk", "de", "fr", "ca", "jp", "au", "in"]
            )
            if not is_official:
                # Brand found in subdomain, fake domain, or path of non-official site
                if (brand in domain and registered_domain != f"{brand}.com") or (brand in path):
                    brand_impersonation = 1.0
                    detected_brand_spoof.append(brand)

    # 10. URL Shortener detection
    is_shortened = 1.0 if (domain in KNOWN_SHORTENERS or any(domain.endswith("." + s) for s in KNOWN_SHORTENERS)) else 0.0

    # 11. Punycode detection (IDN Homograph attack indicator)
    has_punycode = 1.0 if "xn--" in domain.lower() else 0.0

    # 12. Homoglyph / Lookalike detection
    has_homoglyphs = 1.0 if detect_homoglyphs(domain) else 0.0

    # 13. TLD risk score
    tld_risk_score = 1.0 if tld in HIGH_RISK_TLDS else 0.0

    # 14. Digit to letter ratio
    alpha_count = sum(c.isalpha() for c in url)
    digit_ratio = (count_digits / alpha_count) if alpha_count > 0 else 0.0
    digit_ratio = round(min(digit_ratio, 10.0), 4)

    # 15. Port presence in netloc
    has_port = 1.0 if (":" in netloc and not is_ip_address(domain)) else 0.0

    # 16. Consecutive hyphens in domain
    consecutive_hyphens = 1.0 if "--" in domain else 0.0

    # 17. TLD in subdomain or path (e.g., paypal.com.attacker.com)
    tld_in_subdomain = 0.0
    for com_tld in COMMON_TLDS:
        token = f".{com_tld}."
        if token in domain:
            tld_in_subdomain = 1.0
            break

    # 18. Domain length vs Path length ratio
    domain_to_path_ratio = (domain_length / (path_length + 1))

    # Compile the 30 numerical features dictionary
    features = {
        "url_length": float(url_length),
        "domain_length": float(domain_length),
        "path_length": float(path_length),
        "count_dots": float(count_dots),
        "count_hyphens": float(count_hyphens),
        "count_digits": float(count_digits),
        "count_subdomains": float(num_subdomains),
        "has_https": has_https,
        "has_http": has_http,
        "has_ip_address": has_ip,
        "count_at": float(count_at),
        "count_percent": float(count_percent),
        "count_underscore": float(count_underscore),
        "count_equal": float(count_equal),
        "count_question": float(count_question),
        "count_ampersand": float(count_ampersand),
        "has_double_slash_path": has_double_slash_path,
        "num_parameters": num_parameters,
        "url_entropy": float(url_entropy),
        "domain_entropy": float(domain_entropy),
        "suspicious_keywords_count": suspicious_keywords_count,
        "brand_impersonation": brand_impersonation,
        "is_shortened_url": is_shortened,
        "has_punycode": has_punycode,
        "has_homoglyphs": has_homoglyphs,
        "tld_risk_score": tld_risk_score,
        "digit_to_letter_ratio": float(digit_ratio),
        "has_port": has_port,
        "consecutive_hyphens": consecutive_hyphens,
        "tld_in_subdomain": tld_in_subdomain
    }

    # Generate human-readable reasons for detection
    reasons: List[str] = []
    if has_ip == 1.0:
        reasons.append("Raw IP address used instead of legitimate domain name")
    if brand_impersonation == 1.0 and detected_brand_spoof:
        brands_str = ", ".join(set(detected_brand_spoof))
        reasons.append(f"Brand impersonation detected: deceptive use of '{brands_str}'")
    if has_punycode == 1.0:
        reasons.append("Punycode (IDN) detected; potential homograph spoofing attempt")
    if has_homoglyphs == 1.0:
        reasons.append("Lookalike characters or character substitutions detected in domain")
    if is_shortened == 1.0:
        reasons.append("Known URL shortener service used to mask final destination")
    if tld_risk_score == 1.0:
        reasons.append(f"High-risk Top-Level Domain (.{tld}) with elevated phishing frequency")
    if count_at > 0:
        reasons.append("Presence of '@' symbol; may be used to mislead browser URL routing")
    if has_double_slash_path == 1.0:
        reasons.append("Double slash '//' found in URL path; potential open redirect")
    if num_subdomains >= 3:
        reasons.append(f"Excessive subdomain depth ({num_subdomains} subdomains)")
    if suspicious_keywords_count >= 2:
        reasons.append(f"Multiple security/auth keywords present ({', '.join(suspicious_kw_found[:3])})")
    elif suspicious_keywords_count == 1:
        reasons.append(f"Suspicious keyword '{suspicious_kw_found[0]}' found in URL")
    if domain_entropy > 4.2:
        reasons.append(f"High domain entropy ({domain_entropy:.2f}); likely generated algorithmically (DGA)")
    if url_length > 100:
        reasons.append(f"Abnormally long URL ({url_length} characters)")
    if has_https == 0.0:
        reasons.append("Unencrypted connection (HTTP instead of HTTPS)")
    if tld_in_subdomain == 1.0:
        reasons.append("Deceptive domain structure: legitimate TLD embedded in subdomain")
    if digit_ratio > 0.4:
        reasons.append("Unusually high ratio of digits to letters in URL")

    # If no negative reasons were found, indicate clean URL properties
    if not reasons:
        reasons.append("Standard domain structure and valid HTTPS encryption")
        reasons.append("No known phishing indicators, deceptive brands, or anomalies found")

    metadata = {
        "domain": domain,
        "tld": tld,
        "scheme": scheme,
        "num_subdomains": num_subdomains,
        "detected_brands": list(set(detected_brand_spoof)),
        "suspicious_keywords": suspicious_kw_found,
        "is_ip": bool(has_ip),
        "is_shortened": bool(is_shortened)
    }

    return features, reasons, metadata


def get_feature_names() -> List[str]:
    """
    Returns ordered list of feature names matching the numerical vector.
    """
    return [
        "url_length",
        "domain_length",
        "path_length",
        "count_dots",
        "count_hyphens",
        "count_digits",
        "count_subdomains",
        "has_https",
        "has_http",
        "has_ip_address",
        "count_at",
        "count_percent",
        "count_underscore",
        "count_equal",
        "count_question",
        "count_ampersand",
        "has_double_slash_path",
        "num_parameters",
        "url_entropy",
        "domain_entropy",
        "suspicious_keywords_count",
        "brand_impersonation",
        "is_shortened_url",
        "has_punycode",
        "has_homoglyphs",
        "tld_risk_score",
        "digit_to_letter_ratio",
        "has_port",
        "consecutive_hyphens",
        "tld_in_subdomain"
    ]


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=machine+learning",
        "http://paypal-verification-account-security.xyz/update-login.php?user=123",
        "http://192.168.1.1/admin/login",
        "https://bit.ly/3xY9zq",
        "https://xn--pple-43d.com/support"
    ]
    for u in test_urls:
        feats, rzns, meta = extract_features(u)
        print(f"\n--- URL: {u} ---")
        print(f"Domain: {meta['domain']} | IP: {meta['is_ip']} | Brand spoof: {meta['detected_brands']}")
        print(f"Reasons ({len(rzns)}): {rzns}")
        print(f"Feature vector length: {len(feats)}")
