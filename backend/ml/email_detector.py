import re
from .model_trainer import predict_url

# Regex to extract URLs from text
URL_REGEX = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*\??[/\w\.-=&%]*'

# NLP Risk Keyword Categories
LEXICAL_PATTERNS = {
    "Urgency & Panic": {
        "weight": 25,
        "desc": "Uses urgent deadlines to manipulate victims into hasty decisions without verification.",
        "keywords": [
            "immediate action", "urgently", "urgent notice", "24 hours", "48 hours",
            "account suspended", "terminate your account", "action required immediately",
            "final warning", "unauthorized access detected", "within 12 hours"
        ]
    },
    "Credential Harvesting": {
        "weight": 30,
        "desc": "Solicits sensitive user credentials, passwords, or verification codes.",
        "keywords": [
            "verify your password", "confirm your password", "update your credentials",
            "enter your password", "confirm your pin", "security questions", "re-authenticate",
            "validate your identity", "login to restore", "unlock your account"
        ]
    },
    "Financial Coercion & Wire Fraud": {
        "weight": 30,
        "desc": "Directs fraudulent money transfers, gift cards, or crypto transactions.",
        "keywords": [
            "wire transfer", "gift cards", "bitcoin", "crypto payment", "unpaid invoice",
            "overdue payment", "bank transfer", "swift code", "remittance advice", "ach transfer"
        ]
    },
    "Executive & Authority Impersonation (BEC)": {
        "weight": 25,
        "desc": "Impersonates top executives (CEO, CFO) or government authority to bypass standard procedures.",
        "keywords": [
            "from the desk of", "strictly confidential", "keep this between us", "do not call me",
            "i am in a meeting", "internal audit", "tax department", "irs notice", "legal action",
            "subpoena", "fbi notice"
        ]
    },
    "TOAD Callback Scam": {
        "weight": 20,
        "desc": "Instructs user to call a fraudulent phone number to cancel a fake charge.",
        "keywords": [
            "call customer support", "toll free", "call us immediately at", "helpline number",
            "call to cancel", "dispute this charge"
        ]
    }
}

def analyze_headers(headers_text):
    """Parses and grades email security headers (SPF, DKIM, DMARC)."""
    if not headers_text:
        return {"risk": 0, "status": "No headers provided", "flags": []}

    h_lower = headers_text.lower()
    flags = []
    header_risk = 0

    # SPF
    if "spf=fail" in h_lower or "spf=softfail" in h_lower:
        flags.append("SPF Check Failed (Sender server unauthorized)")
        header_risk += 30
    elif "spf=pass" in h_lower:
        flags.append("SPF Check Passed")
    else:
        flags.append("No SPF verification found")
        header_risk += 10

    # DKIM
    if "dkim=fail" in h_lower:
        flags.append("DKIM Signature Invalid (Email tampered in transit)")
        header_risk += 30
    elif "dkim=pass" in h_lower:
        flags.append("DKIM Signature Valid")
    else:
        flags.append("No DKIM signature found")
        header_risk += 10

    # DMARC
    if "dmarc=fail" in h_lower:
        flags.append("DMARC Policy Violation")
        header_risk += 35
    elif "dmarc=pass" in h_lower:
        flags.append("DMARC Policy Passed")

    return {
        "risk": min(100, header_risk),
        "flags": flags
    }

def analyze_email(sender, reply_to, subject, body, headers=""):
    """
    Comprehensive Email Threat Analysis:
    1. NLP/Lexical triage on subject & body
    2. Header authenticity check (SPF/DKIM/DMARC)
    3. Sender vs Reply-To mismatch inspection
    4. URL extraction & ML Model classification on all embedded links
    """
    combined_text = f"{subject} {body}".lower()
    red_flags = []
    lexical_score = 0

    # 1. Sender & Reply-To inspection
    sender_clean = (sender or "").strip().lower()
    reply_to_clean = (reply_to or "").strip().lower()

    if reply_to_clean and sender_clean:
        sender_domain = sender_clean.split('@')[-1] if '@' in sender_clean else ""
        reply_domain = reply_to_clean.split('@')[-1] if '@' in reply_to_clean else ""
        if sender_domain and reply_domain and sender_domain != reply_domain:
            red_flags.append({
                "category": "Sender / Reply-To Domain Mismatch",
                "desc": f"Responses will be sent to '{reply_domain}', differing from sender '{sender_domain}'.",
                "severity": "high"
            })
            lexical_score += 25

    # 2. Check Display Name Impersonation
    trusted_brands = ["microsoft", "paypal", "google", "apple", "amazon", "netflix", "chase", "bank of america", "irs", "dhl", "fedex"]
    for brand in trusted_brands:
        if brand in sender_clean and not sender_clean.endswith(f"@{brand}.com"):
            red_flags.append({
                "category": f"Brand Impersonation ({brand.capitalize()})",
                "desc": f"Sender claims to represent {brand.capitalize()} but does not originate from official @{brand}.com domain.",
                "severity": "critical"
            })
            lexical_score += 30
            break

    # 3. NLP / Lexical Scan
    for category, info in LEXICAL_PATTERNS.items():
        matched_words = [kw for kw in info["keywords"] if kw in combined_text]
        if matched_words:
            red_flags.append({
                "category": category,
                "desc": f"{info['desc']} (Triggers: {', '.join(matched_words[:3])})",
                "severity": "high" if info["weight"] >= 25 else "medium"
            })
            lexical_score += info["weight"]

    # 4. Header Analysis
    header_res = analyze_headers(headers)
    header_score = header_res["risk"]

    # 5. Extract and Analyze Embedded URLs using URL ML Model
    found_urls = re.findall(URL_REGEX, body or "")
    # Also look in subject
    found_urls += re.findall(URL_REGEX, subject or "")
    found_urls = list(set(found_urls))

    url_scan_results = []
    max_url_risk = 0
    for u in found_urls[:5]: # Scan up to 5 unique URLs
        url_pred = predict_url(u)
        url_scan_results.append({
            "url": u,
            "verdict": url_pred["verdict"],
            "risk_score": url_pred["risk_score"],
            "confidence": url_pred["confidence"],
            "features_flagged": [f["name"] for f in url_pred["feature_details"] if f["status"] == "danger"]
        })
        if url_pred["risk_score"] > max_url_risk:
            max_url_risk = url_pred["risk_score"]

    if max_url_risk >= 65:
        red_flags.append({
            "category": "Malicious Link Detected (ML Model)",
            "desc": f"Contains links classified as Phishing by the URL Machine Learning Classifier (Highest URL risk: {max_url_risk}%).",
            "severity": "critical"
        })

    # Composite Risk Calculation
    # Weight: 40% URLs (if present), 40% NLP/lexical, 20% Headers
    if found_urls:
        total_risk = int(round(0.45 * max_url_risk + 0.40 * min(100, lexical_score) + 0.15 * header_score))
    else:
        total_risk = int(round(0.75 * min(100, lexical_score) + 0.25 * header_score))

    total_risk = min(100, max(0, total_risk))

    if total_risk >= 55:
        verdict = "Phishing Email"
        confidence = round(75 + (total_risk - 55) * 0.5, 1)
    elif total_risk >= 30:
        verdict = "Suspicious Email"
        confidence = round(65 + (total_risk - 30) * 0.3, 1)
    else:
        verdict = "Legitimate Email"
        confidence = round(95 - total_risk * 0.8, 1)

    return {
        "verdict": verdict,
        "risk_score": total_risk,
        "confidence": confidence,
        "red_flags": red_flags,
        "header_analysis": header_res["flags"],
        "embedded_urls_scanned": url_scan_results,
        "urls_count": len(found_urls),
        "lexical_score": min(100, lexical_score),
        "header_score": header_score
    }
