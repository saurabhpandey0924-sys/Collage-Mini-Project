import re
import math
import urllib.parse

# List of known URL shortening services
SHORTENING_SERVICES = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "shorte.st", "tiny.cc",
    "bc.vc", "v.gd", "qr.ae", "trib.al", "u.to", "x.co"
}

# Suspicious high-risk or free top-level domains commonly abused by phishers
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "club", "work",
    "loan", "click", "fit", "surf", "date", "racing", "review", "country",
    "kim", "cricket", "science", "party", "gdn", "mom", "vip", "men"
}

# Suspicious keywords frequently used in phishing attacks
PHISHING_KEYWORDS = [
    "login", "verify", "verification", "secure", "security", "account",
    "update", "banking", "authenticate", "signin", "sign-in", "password",
    "confirm", "confirmation", "recover", "recovery", "suspend", "suspended",
    "unlock", "wallet", "billing", "invoice", "payment", "support", "service",
    "appleid", "paypal", "microsoft", "google", "netflix", "chase", "wellsfargo"
]

def calculate_entropy(text):
    """Calculates the Shannon Entropy of a string to detect randomized/DGA domain names."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 3)

def is_ip_address(netloc):
    """Checks if netloc is an IPv4 or IPv6 address."""
    # Strip port if present
    host = netloc.split(':')[0]
    # IPv4 regex
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if re.match(ipv4_pattern, host):
        return True
    # Hex or Octal IP check
    if re.match(r'^0x[0-9a-fA-F]+', host):
        return True
    return False

def extract_features(raw_url):
    """
    Extracts 16 key lexical, structural, and heuristic features from a given URL.
    Returns:
        feature_vector: list of numeric values aligned with the ML classification model
        feature_details: list of detailed explanation dicts for UI rendering
    """
    url = raw_url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ''
    path = parsed.path or ''
    query = parsed.query or ''
    netloc = parsed.netloc or ''
    url_lower = url.lower()
    host_lower = hostname.lower()

    # 1. IP Address in URL (-1: Safe, 1: Phishing)
    has_ip = is_ip_address(netloc)
    f_ip = 1 if has_ip else -1

    # 2. URL Length (-1: <54 Safe, 0: 54-75 Suspicious, 1: >75 Phishing)
    url_len = len(url)
    if url_len < 54:
        f_len = -1
    elif url_len <= 75:
        f_len = 0
    else:
        f_len = 1

    # 3. Shortening Service (1: Phishing, -1: Safe)
    is_shortened = any(host_lower == svc or host_lower.endswith('.' + svc) for svc in SHORTENING_SERVICES)
    f_short = 1 if is_shortened else -1

    # 4. Having '@' Symbol in URL (1: Phishing, -1: Safe)
    has_at = '@' in url
    f_at = 1 if has_at else -1

    # 5. Double Slash Redirecting in Path (1: Phishing, -1: Safe)
    # The first '//' is at http:// or https:// (position 5-7). Look after index 7.
    has_double_slash = '//' in url[8:]
    f_slash = 1 if has_double_slash else -1

    # 6. Prefix/Suffix '-' in Domain (1: Phishing, -1: Safe)
    has_prefix_suffix = '-' in hostname
    f_prefix = 1 if has_prefix_suffix else -1

    # 7. Subdomain Count (-1: 1 or no subdomain, 0: 2 subdomains, 1: >2 subdomains)
    domain_parts = hostname.split('.')
    if len(domain_parts) <= 2:
        f_subdomain = -1
    elif len(domain_parts) == 3:
        f_subdomain = 0
    else:
        f_subdomain = 1

    # 8. HTTPS / SSL State (-1: HTTPS, 1: HTTP without SSL)
    is_https = parsed.scheme.lower() == 'https'
    f_ssl = -1 if is_https else 1

    # 9. HTTPS Token in Domain Part (1: Phishing, -1: Safe)
    has_https_in_domain = 'https' in host_lower
    f_https_token = 1 if has_https_in_domain else -1

    # 10. Non-Standard Port (1: Phishing, -1: Safe)
    has_custom_port = False
    if parsed.port and parsed.port not in (80, 443):
        has_custom_port = True
    f_port = 1 if has_custom_port else -1

    # 11. Suspicious TLD (1: Phishing, -1: Safe)
    tld = domain_parts[-1] if domain_parts else ""
    is_suspicious_tld = tld in SUSPICIOUS_TLDS
    f_tld = 1 if is_suspicious_tld else -1

    # 12. Shannon Entropy of Domain
    entropy = calculate_entropy(hostname)
    # Entropy > 3.8 typically indicates automated algorithmically generated domains (DGA)
    f_entropy = 1 if entropy > 3.85 else (-1 if entropy < 3.2 else 0)

    # 13. Suspicious Keyword Count
    keyword_matches = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
    kw_count = len(keyword_matches)
    if kw_count == 0:
        f_keywords = -1
    elif kw_count <= 2:
        f_keywords = 0
    else:
        f_keywords = 1

    # 14. Digit Count in Domain
    digits_in_host = sum(c.isdigit() for c in hostname)
    f_digits = 1 if digits_in_host > 4 else (-1 if digits_in_host == 0 else 0)

    # 15. Path Depth (number of subdirectories)
    path_segments = [p for p in path.split('/') if p]
    depth = len(path_segments)
    f_depth = 1 if depth >= 4 else (-1 if depth <= 1 else 0)

    # 16. Special Characters in URL (? & = % _ -)
    special_chars = sum(url.count(c) for c in ['?', '=', '&', '%', '_', '~', ';'])
    f_special = 1 if special_chars > 5 else (-1 if special_chars <= 1 else 0)

    # Feature Vector (16 features in standard order for ML Model)
    feature_vector = [
        f_ip, f_len, f_short, f_at, f_slash, f_prefix, f_subdomain,
        f_ssl, f_https_token, f_port, f_tld, f_entropy, f_keywords,
        f_digits, f_depth, f_special
    ]

    feature_names = [
        "IP Address in URL",
        "URL Length",
        "Shortening Service",
        "Having '@' Symbol",
        "Double Slash Redirect",
        "Prefix/Suffix '-' in Domain",
        "Subdomain Depth",
        "SSL / Protocol Security",
        "HTTPS Token in Domain",
        "Non-Standard Port",
        "Suspicious TLD",
        "Domain Shannon Entropy",
        "Phishing Keyword Density",
        "Numeric Digits in Domain",
        "URL Path Depth",
        "Special Character Count"
    ]

    # Human-readable breakdown for the frontend
    feature_details = [
        {
            "name": "IP Address Usage",
            "val": "Raw IP Detected" if has_ip else "Valid Domain Name",
            "status": "danger" if has_ip else "safe",
            "risk": 15 if has_ip else 0,
            "desc": "Legitimate organizations rarely use raw IP addresses directly in website URLs."
        },
        {
            "name": "URL Length",
            "val": f"{url_len} characters",
            "status": "danger" if f_len == 1 else ("suspicious" if f_len == 0 else "safe"),
            "risk": 15 if f_len == 1 else (5 if f_len == 0 else 0),
            "desc": "Excessively long URLs are often used to conceal malicious redirects and token parameters."
        },
        {
            "name": "URL Shortener",
            "val": "Shortener Detected" if is_shortened else "Direct Domain",
            "status": "danger" if is_shortened else "safe",
            "risk": 15 if is_shortened else 0,
            "desc": "Shortened links (e.g., bit.ly, tinyurl) mask the true destination of phishing landings."
        },
        {
            "name": "Authentication '@' Symbol",
            "val": "Found '@' Symbol" if has_at else "Clean",
            "status": "danger" if has_at else "safe",
            "risk": 10 if has_at else 0,
            "desc": "The '@' symbol in URLs causes browsers to ignore preceding text and redirect to subsequent domains."
        },
        {
            "name": "Path Double Slash Redirect",
            "val": "Double Slash Detected" if has_double_slash else "Standard Path",
            "status": "danger" if has_double_slash else "safe",
            "risk": 10 if has_double_slash else 0,
            "desc": "Using '//' inside the resource path is a common trick to redirect victims to external attack servers."
        },
        {
            "name": "Domain Hyphen (Prefix-Suffix)",
            "val": "Hyphenated Domain" if has_prefix_suffix else "No Hyphens",
            "status": "suspicious" if has_prefix_suffix else "safe",
            "risk": 10 if has_prefix_suffix else 0,
            "desc": "Phishers use hyphens (e.g., 'paypal-security.com') to create convincing lookalike domains."
        },
        {
            "name": "Subdomain Hierarchy",
            "val": f"{len(domain_parts)} domain levels",
            "status": "danger" if f_subdomain == 1 else ("suspicious" if f_subdomain == 0 else "safe"),
            "risk": 15 if f_subdomain == 1 else (5 if f_subdomain == 0 else 0),
            "desc": "Multiple nested subdomains often disguise a fraudulent host beneath a legitimate-looking name."
        },
        {
            "name": "SSL / Encryption Protocol",
            "val": "HTTPS Encrypted" if is_https else "Insecure HTTP",
            "status": "safe" if is_https else "danger",
            "risk": 10 if not is_https else 0,
            "desc": "Modern legitimate login pages require HTTPS. Unencrypted HTTP is a major red flag."
        },
        {
            "name": "HTTPS Token Spoofing",
            "val": "HTTPS Used in Domain Name" if has_https_in_domain else "Clean Domain",
            "status": "danger" if has_https_in_domain else "safe",
            "risk": 15 if has_https_in_domain else 0,
            "desc": "Embedding 'https' inside the domain (e.g. 'https-verify-apple.com') tries to deceive users."
        },
        {
            "name": "Port Specification",
            "val": f"Port {parsed.port}" if has_custom_port else "Standard (80/443)",
            "status": "danger" if has_custom_port else "safe",
            "risk": 10 if has_custom_port else 0,
            "desc": "Attackers frequently host quick phishing servers on non-standard ports like 8080 or 8888."
        },
        {
            "name": "Top-Level Domain (TLD) Risk",
            "val": f".{tld} (High-Risk TLD)" if is_suspicious_tld else f".{tld} (Standard)",
            "status": "danger" if is_suspicious_tld else "safe",
            "risk": 15 if is_suspicious_tld else 0,
            "desc": "Abused or free TLDs (.tk, .ml, .ga, .top, .xyz) are statistical hotbeds for short-lived phishing sites."
        },
        {
            "name": "Domain Randomness (Entropy)",
            "val": f"{entropy} bits (High Randomness)" if f_entropy == 1 else f"{entropy} bits (Normal)",
            "status": "danger" if f_entropy == 1 else ("suspicious" if f_entropy == 0 else "safe"),
            "risk": 10 if f_entropy == 1 else 0,
            "desc": "High Shannon entropy indicates algorithmically generated random strings (DGA) common in malware."
        },
        {
            "name": "Phishing Keyword Triggers",
            "val": f"{kw_count} trigger words ({', '.join(keyword_matches[:3])})" if kw_count > 0 else "None",
            "status": "danger" if f_keywords == 1 else ("suspicious" if f_keywords == 0 else "safe"),
            "risk": 20 if f_keywords == 1 else (10 if f_keywords == 0 else 0),
            "desc": "Presence of high-risk keywords like 'verify', 'banking', 'secure-login' in unverified URLs."
        }
    ]

    return {
        "url": url,
        "hostname": hostname,
        "feature_vector": feature_vector,
        "feature_names": feature_names,
        "feature_details": feature_details
    }
