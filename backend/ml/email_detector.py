import re
from .model_trainer import predict_url
from .threat_apis import live_dns_lookup, extract_domain
from .cache_manager import scan_cache

# Regex to extract URLs from text
URL_REGEX = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*\??[/\w\.-=&%]*'

# Proprietary Behavioral Patterns (Categorized for enterprise security intelligence)
# Specific triggers and internal heuristics are strictly concealed from client output
PROPRIETARY_PATTERNS = {
    "Urgent Psychological Coercion": {
        "weight": 25,
        "classification": "Social Engineering & Urgency Manipulation",
        "description": "Linguistic patterns detected characteristic of artificial time pressure designed to compel unverified action.",
        "keywords": [
            "immediate action", "urgently", "urgent notice", "24 hours", "48 hours",
            "account suspended", "terminate your account", "action required immediately",
            "final warning", "unauthorized access detected", "within 12 hours", "within 24 hours"
        ]
    },
    "Credential Harvesting Signature": {
        "weight": 30,
        "classification": "Identity & Credential Exfiltration",
        "description": "Semantic patterns attempting to solicit account credentials, authentication PINs, or sensitive session keys.",
        "keywords": [
            "verify your password", "confirm your password", "update your credentials",
            "enter your password", "confirm your pin", "security questions", "re-authenticate",
            "validate your identity", "login to restore", "unlock your account", "reset your password"
        ]
    },
    "Financial Coercion & Wire Fraud": {
        "weight": 30,
        "classification": "Financial Redirection & Payment Scam",
        "description": "Directives instructing anomalous wire disbursements, payment updates, or subscription renewals.",
        "keywords": [
            "wire transfer", "gift cards", "bitcoin", "crypto payment", "unpaid invoice",
            "overdue payment", "payment overdue", "subscription renewal", "auto-renewal", "refund",
            "bank transfer", "swift code", "remittance advice", "ach transfer", "charge will be final"
        ]
    },
    "Executive & Authority Impersonation": {
        "weight": 25,
        "classification": "Business Email Compromise (BEC)",
        "description": "Language mimicking executive authority or government regulatory bodies to bypass established verification protocols.",
        "keywords": [
            "from the desk of", "strictly confidential", "keep this between us", "do not call me",
            "i am in a meeting", "internal audit", "tax department", "irs notice", "legal action",
            "subpoena", "fbi notice", "arrest warrant"
        ]
    },
    "TOAD Callback Vector": {
        "weight": 25,
        "classification": "Telephone-Oriented Attack Delivery (TOAD)",
        "description": "Directives instructing recipient to establish outbound voice communication with an unverified telephone helpline.",
        "keywords": [
            "call customer support", "customer care number", "toll free", "call us immediately", "helpline number",
            "call to cancel", "dispute this charge", "call within", "1-800-", "1-888-"
        ]
    }
}

def analyze_headers(headers_text):
    """Parses and evaluates email cryptographic headers (SPF, DKIM, DMARC)."""
    if not headers_text:
        return {"risk": 0, "status": "No raw headers supplied", "flags": []}

    h_lower = headers_text.lower()
    flags = []
    header_risk = 0

    # SPF
    if "spf=fail" in h_lower or "spf=softfail" in h_lower:
        flags.append("SPF Authentication Discrepancy (Origin IP unauthorized by sending domain)")
        header_risk += 30
    elif "spf=pass" in h_lower:
        flags.append("SPF Cryptographic Verification Verified")
    else:
        flags.append("SPF Verification Unconfirmed")
        header_risk += 10

    # DKIM
    if "dkim=fail" in h_lower:
        flags.append("DKIM Digital Signature Invalid (Message integrity compromised in transit)")
        header_risk += 30
    elif "dkim=pass" in h_lower:
        flags.append("DKIM Cryptographic Signature Intact")
    else:
        flags.append("DKIM Signature Missing")
        header_risk += 10

    # DMARC
    if "dmarc=fail" in h_lower:
        flags.append("DMARC Enforcement Policy Violation")
        header_risk += 35
    elif "dmarc=pass" in h_lower:
        flags.append("DMARC Alignment Policy Confirmed")

    return {
        "risk": min(100, header_risk),
        "flags": flags
    }

def analyze_email(sender, reply_to, subject, body, headers=""):
    """
    Enterprise Email Threat Analysis:
    1. Proprietary Semantic & Linguistic Analysis (zero keyword leakage)
    2. Real-time Live DNS / MX / SPF / DMARC Inspection
    3. Return-Path / Display Name Impersonation Analysis
    4. Multi-URL Machine Learning Extraction and Sandboxing
    """
    cache_key = f"email_scan:{hash((sender, reply_to, subject, body[:100]))}"
    cached = scan_cache.get(cache_key)
    if cached:
        return cached

    combined_text = f"{subject} {body}".lower()
    threat_indicators = []
    semantic_score = 0

    sender_clean = (sender or "").strip().lower()
    reply_to_clean = (reply_to or "").strip().lower()
    sender_domain = extract_domain(sender_clean)
    reply_domain = extract_domain(reply_to_clean)

    # 1. Live DNS & Mail Exchanger Inspection (Live Network Verification)
    dns_intel = None
    if sender_domain:
        dns_intel = live_dns_lookup(sender_domain)
        if dns_intel and dns_intel.get("valid"):
            if not dns_intel.get("has_mx", True):
                threat_indicators.append({
                    "category": "DNS Infrastructure Discrepancy",
                    "desc": f"Sender domain '{sender_domain}' lacks active Mail Exchange (MX) records on public DNS.",
                    "severity": "critical"
                })
                semantic_score += 35
            elif not dns_intel.get("spf"):
                threat_indicators.append({
                    "category": "Unverified Sender Infrastructure",
                    "desc": f"Domain '{sender_domain}' lacks public SPF authorization records, facilitating spoofing.",
                    "severity": "medium"
                })
                semantic_score += 15

    # 2. Sender vs Reply-To Mismatch
    if sender_domain and reply_domain and sender_domain != reply_domain:
        threat_indicators.append({
            "category": "Return-Path Domain Mismatch",
            "desc": f"Outbound replies are redirected to '{reply_domain}', differing from sender origin '{sender_domain}'.",
            "severity": "high"
        })
        semantic_score += 25

    # 3. Brand Authority Impersonation Check
    trusted_brands = ["microsoft", "paypal", "google", "apple", "amazon", "netflix", "chase", "bank of america", "irs", "dhl", "fedex"]
    for brand in trusted_brands:
        if brand in sender_clean and not sender_clean.endswith(f"@{brand}.com") and not sender_clean.endswith(f"<{brand}.com>"):
            threat_indicators.append({
                "category": f"Brand Authority Impersonation ({brand.capitalize()})",
                "desc": f"Sender identifier references {brand.capitalize()} without originating from authentic infrastructure.",
                "severity": "critical"
            })
            semantic_score += 30
            break

    # 3b. Typosquatting / Deceptive Lookalike Domain Check
    typo_patterns = [
        (r'microso[f]{2,}', "Microsoft"),
        (r'rnicrosoft', "Microsoft"),
        (r'micros0ft', "Microsoft"),
        (r'paypa[l1i]', "PayPal"),
        (r'amaz[o0]n', "Amazon"),
        (r'arnazon', "Amazon"),
        (r'netf[l1i]x', "Netflix"),
        (r'app[l1i]e', "Apple"),
        (r'g[o0]{2}gle', "Google"),
        (r'gmai[l1i]', "Gmail")
    ]
    for pattern, brand_name in typo_patterns:
        if sender_domain and re.search(pattern, sender_domain):
            legit = f"{brand_name.lower()}.com"
            if sender_domain != legit and not sender_domain.endswith(f".{legit}"):
                threat_indicators.append({
                    "category": f"Deceptive Lookalike / Typosquatting Domain ({brand_name})",
                    "desc": f"Sender domain '{sender_domain}' employs character manipulation or typosquatting mimicking {brand_name}.",
                    "severity": "critical"
                })
                semantic_score += 35
                break

    # 3c. Deceptive Brand Keywords in Domain
    for brand in ["microsoft", "paypal", "google", "apple", "amazon", "netflix"]:
        if sender_domain and brand in sender_domain and not (sender_domain == f"{brand}.com" or sender_domain.endswith(f".{brand}.com")):
            threat_indicators.append({
                "category": f"Deceptive Brand Keyword in Domain ({brand.capitalize()})",
                "desc": f"Sender domain '{sender_domain}' embeds brand name '{brand}' on unauthorized non-official infrastructure.",
                "severity": "high"
            })
            semantic_score += 25
            break

    # 4. Proprietary Semantic Analysis (Obfuscated — zero keyword leaks)
    negations = ["no immediate action", "not immediate action", "no action is required", "no action required", "not required", "no urgency"]
    for category, info in PROPRIETARY_PATTERNS.items():
        matched = False
        for kw in info["keywords"]:
            if kw in combined_text:
                # Check for negation if kw is "immediate action" or similar
                if kw in ["immediate action", "action required immediately", "urgently", "urgent notice"] and any(neg in combined_text for neg in negations):
                    continue
                matched = True
                break
        if matched:
            threat_indicators.append({
                "category": category,
                "desc": info["description"],
                "severity": "high" if info["weight"] >= 25 else "medium"
            })
            semantic_score += info["weight"]

    # 5. Header Inspection
    header_res = analyze_headers(headers)
    header_score = header_res["risk"]

    # 6. Extract and Sandbox Embedded URLs
    found_urls = re.findall(URL_REGEX, body or "")
    found_urls += re.findall(URL_REGEX, subject or "")
    found_urls = list(set(found_urls))

    url_scan_results = []
    max_url_risk = 0
    for u in found_urls[:5]:
        url_pred = predict_url(u)
        url_scan_results.append({
            "url": u,
            "verdict": url_pred["verdict"],
            "risk_score": url_pred["risk_score"],
            "confidence": url_pred["confidence"]
        })
        if url_pred["risk_score"] > max_url_risk:
            max_url_risk = url_pred["risk_score"]

    if max_url_risk >= 65:
        threat_indicators.append({
            "category": "High-Risk Embedded Destination",
            "desc": f"Neural classifier flagged destination URL as malicious infrastructure (Risk: {max_url_risk}%).",
            "severity": "critical"
        })

    # Composite Risk Calculation
    if found_urls:
        total_risk = int(round(0.45 * max_url_risk + 0.40 * min(100, semantic_score) + 0.15 * header_score))
    else:
        total_risk = int(round(0.75 * min(100, semantic_score) + 0.25 * header_score))

    total_risk = min(100, max(0, total_risk))

    if total_risk >= 55:
        verdict = "Phishing Email"
        confidence = round(78 + (total_risk - 55) * 0.45, 1)
    elif total_risk >= 30:
        verdict = "Suspicious Email"
        confidence = round(68 + (total_risk - 30) * 0.3, 1)
    else:
        verdict = "Legitimate Email"
        confidence = round(96 - total_risk * 0.7, 1)

    result = {
        "verdict": verdict,
        "risk_score": total_risk,
        "confidence": confidence,
        "threat_indicators": threat_indicators,
        "red_flags": threat_indicators, # backwards compatibility
        "header_analysis": header_res["flags"],
        "embedded_urls_scanned": url_scan_results,
        "urls_count": len(found_urls),
        "dns_intelligence": dns_intel
    }

    scan_cache.set(cache_key, result, ttl_seconds=3600)
    return result
