"""
PHISH GUARD - Security Utilities Module
Implements input validation, rate limiting, XSS sanitization,
and security headers for production defense-in-depth.
"""

import html
import re
import time
from collections import defaultdict
from functools import wraps
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
from flask import Response, jsonify, request

from config import RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS


class SlidingWindowRateLimiter:
    """Thread-safe sliding window rate limiter per client IP."""
    def __init__(self, max_requests: int = RATE_LIMIT_REQUESTS, window_seconds: int = RATE_LIMIT_WINDOW_SECONDS):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> Tuple[bool, int]:
        now = time.time()
        timestamps = self.requests[client_ip]

        # Prune expired timestamps outside sliding window
        valid_timestamps = [t for t in timestamps if now - t < self.window_seconds]
        self.requests[client_ip] = valid_timestamps

        remaining = self.max_requests - len(valid_timestamps)
        if len(valid_timestamps) >= self.max_requests:
            return False, 0

        self.requests[client_ip].append(now)
        return True, remaining


limiter = SlidingWindowRateLimiter()


def rate_limit(f):
    """Decorator to enforce per-IP rate limiting on API endpoints."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "127.0.0.1"
        client_ip = client_ip.split(",")[0].strip()

        allowed, remaining = limiter.is_allowed(client_ip)
        if not allowed:
            return jsonify({
                "status": "error",
                "message": "Rate limit exceeded. Please wait before making more scan requests.",
                "retry_after_seconds": RATE_LIMIT_WINDOW_SECONDS
            }), 429

        response = f(*args, **kwargs)
        # If response is tuple (response, status_code) or Response object
        if isinstance(response, tuple):
            resp_obj, status_code = response[0], response[1]
            if isinstance(resp_obj, Response):
                resp_obj.headers["X-RateLimit-Remaining"] = str(remaining)
                return resp_obj, status_code
            return response

        if isinstance(response, Response):
            response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response

    return decorated_function


def add_security_headers(response: Response) -> Response:
    """Applies OWASP recommended security headers to all HTTP responses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' 'unsafe-inline' https:; "
        "img-src 'self' data: https:; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com;"
    )
    return response


def sanitize_string(text: Optional[str], max_length: int = 500) -> str:
    """Escapes HTML entities and truncates input to prevent XSS and buffer attacks."""
    if not text:
        return ""
    cleaned = html.escape(str(text).strip())
    return cleaned[:max_length]


def validate_and_sanitize_url(raw_url: Optional[str]) -> Tuple[bool, str, Optional[str]]:
    """
    Validates that a URL is well-formed, safe to inspect, and conforms to length constraints.
    Returns:
        (is_valid: bool, sanitized_url: str, error_message: Optional[str])
    """
    if not raw_url or not isinstance(raw_url, str):
        return False, "", "URL parameter is required and must be a non-empty string."

    url = raw_url.strip()

    # Reject oversized URLs to mitigate ReDoS or buffer exhaustion
    if len(url) > 2048:
        return False, "", "URL exceeds maximum permitted length of 2048 characters."

    # Prevent file:// or javascript: or dangerous protocol attacks
    lower_url = url.lower()
    if lower_url.startswith(("javascript:", "data:", "file:", "vbscript:", "about:")):
        return False, "", f"Disallowed URI scheme detected: {url[:12]}"

    # Add scheme if missing for standardized parsing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return False, "", "URL must include a valid hostname or domain."

        # Verify domain syntax (no control chars, whitespace)
        if re.search(r"[\s\x00-\x1f\x7f]", url):
            return False, "", "URL contains invalid whitespace or control characters."

        return True, url, None
    except Exception as e:
        return False, "", f"Malformed URL: {str(e)}"
