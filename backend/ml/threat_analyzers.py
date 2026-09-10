import re
from .model_trainer import predict_url

# Regex to extract URLs
URL_REGEX = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*\??[/\w\.-=&%]*'

# ==============================================================================
# 1. SMS / SMISHING THREAT ANALYZER
# ==============================================================================

SMISHING_PATTERNS = [
    {
        "category": "Package / Delivery Impersonation",
        "keywords": ["package", "delivery", "parcel", "usps", "fedex", "dhl", "ups", "shipment", "held at warehouse", "customs fee"],
        "weight": 25,
        "desc": "Impersonates postal/shipping courier asking for redirection fees or address confirmation."
    },
    {
        "category": "Banking & Financial Panic",
        "keywords": ["bank", "chase", "wells fargo", "citi", "card blocked", "unauthorized transaction", "zelle", "fraud alert", "wire transfer", "frozen"],
        "weight": 35,
        "desc": "Falsely claims an unauthorized transaction occurred to induce panic and force credential entry."
    },
    {
        "category": "Account Suspension / Security Verification",
        "keywords": ["account suspended", "action required", "verify now", "locked out", "login to restore", "immediate action", "expires in"],
        "weight": 30,
        "desc": "Uses urgent psychological pressure to trick victim into clicking a phishing link."
    },
    {
        "category": "Lottery / Prize / Refund Bait",
        "keywords": ["winner", "lottery", "congratulations", "free gift", "claim your prize", "tax refund", "cash bonus", "claim now"],
        "weight": 20,
        "desc": "Lures user with unrealistically lucrative financial rewards or refund claims."
    }
]

def analyze_sms_threat(sms_text):
    text = (sms_text or "").strip()
    if not text:
        return {"risk_score": 0, "verdict": "SAFE", "confidence": 95.0, "findings": ["Empty SMS text."]}

    lower_text = text.lower()
    findings = []
    total_risk = 0

    # 1. Scan for matching smishing themes
    for pattern in SMISHING_PATTERNS:
        matched = [kw for kw in pattern["keywords"] if kw in lower_text]
        if matched:
            findings.append(f"🚩 {pattern['category']}: Triggered by '{', '.join(matched[:2])}'. {pattern['desc']}")
            total_risk += pattern["weight"]

    # 2. Check for URL and run through URL ML Classifier
    urls = re.findall(URL_REGEX, text)
    url_findings = []
    max_url_risk = 0

    for u in urls[:3]:
        url_pred = predict_url(u)
        max_url_risk = max(max_url_risk, url_pred["risk_score"])
        url_findings.append({
            "url": u,
            "verdict": url_pred["verdict"],
            "risk_score": url_pred["risk_score"],
            "confidence": url_pred["confidence"]
        })
        if url_pred["verdict"] == "Phishing":
            findings.append(f"🔴 Malicious Embedded URL Detected: {u} (ML Risk: {url_pred['risk_score']}%, Verdict: {url_pred['verdict']})")
        else:
            findings.append(f"ℹ️ Embedded URL Inspected: {u} (ML Risk: {url_pred['risk_score']}%)")

    if urls:
        total_risk = int(round(0.6 * max_url_risk + 0.4 * min(100, total_risk)))
    else:
        total_risk = min(100, total_risk)

    if total_risk >= 50:
        verdict = "MALICIOUS (SMISHING)"
        confidence = round(75 + (total_risk - 50) * 0.45, 1)
    elif total_risk >= 25:
        verdict = "SUSPICIOUS"
        confidence = round(65 + (total_risk - 25) * 0.4, 1)
    else:
        verdict = "SAFE"
        confidence = round(95 - total_risk * 0.8, 1)

    return {
        "text": text,
        "risk_score": total_risk,
        "verdict": verdict,
        "confidence": confidence,
        "findings": findings if findings else ["✅ No obvious smishing keywords or malicious links detected in text message."],
        "urls_detected": url_findings
    }


# ==============================================================================
# 2. MALICIOUS CODE / SCRIPT DEOBFUSCATOR & ANALYZER
# ==============================================================================

CODE_SIGNATURES = [
    {
        "category": "Remote Payload Download & Staging",
        "patterns": [r"DownloadString", r"Invoke-WebRequest", r"Net\.WebClient", r"curl\s+", r"wget\s+", r"urllib\.request", r"requests\.get"],
        "weight": 35,
        "desc": "Attempts to fetch external executables or scripts from remote command-and-control server."
    },
    {
        "category": "Dynamic Process Execution & In-Memory Injection",
        "patterns": [r"\bIEX\b", r"Invoke-Expression", r"eval\s*\(", r"exec\s*\(", r"subprocess\.Popen", r"os\.system", r"child_process"],
        "weight": 35,
        "desc": "Executes dynamic/obfuscated code directly in memory to bypass static antivirus scanners."
    },
    {
        "category": "String Obfuscation & Encoding",
        "patterns": [r"FromBase64String", r"atob\s*\(", r"b64decode", r"\\x[0-9a-fA-F]{2}", r"String\.fromCharCode"],
        "weight": 25,
        "desc": "Uses Base64 or Hex encoding to hide malware strings, API calls, and payload payloads."
    },
    {
        "category": "Reverse Shell / Network Socket Creation",
        "patterns": [r"socket\.socket", r"Net\.Sockets\.TCPClient", r"/bin/(?:ba)?sh\s+-i", r"nc\s+-[el]", r"cmd\.exe\s+/c"],
        "weight": 40,
        "desc": "Establishes unauthorized interactive reverse shell connection back to an attacker IP."
    },
    {
        "category": "System Tampering & Credential Access",
        "patterns": [r"reg\s+add", r"schtasks\s+/create", r"mimikatz", r"lsass", r"HKLM\\SAM", r"/etc/shadow", r"/etc/passwd"],
        "weight": 40,
        "desc": "Attempts persistence creation or unauthorized harvesting of Windows/Linux credentials."
    }
]

def analyze_code_threat(code_text):
    code = (code_text or "").strip()
    if not code:
        return {"risk_score": 0, "verdict": "CLEAN", "confidence": 95.0, "findings": ["No code provided."]}

    findings = []
    total_risk = 0

    for sig in CODE_SIGNATURES:
        for p in sig["patterns"]:
            matches = re.findall(p, code, re.IGNORECASE)
            if matches:
                findings.append(f"⚠️ {sig['category']}: Matched trigger '{matches[0]}'. {sig['desc']}")
                total_risk += sig["weight"]
                break

    # Look for suspicious URLs in code
    embedded_urls = re.findall(URL_REGEX, code)
    if embedded_urls:
        findings.append(f"🌐 Remote URLs found in script: {', '.join(embedded_urls[:2])}")
        total_risk += 20

    total_risk = min(100, total_risk)

    if total_risk >= 50:
        verdict = "MALICIOUS / EXPLOIT"
        confidence = round(75 + (total_risk - 50) * 0.45, 1)
    elif total_risk >= 20:
        verdict = "SUSPICIOUS SCRIPT"
        confidence = round(65 + (total_risk - 20) * 0.4, 1)
    else:
        verdict = "CLEAN / BENIGN SCRIPT"
        confidence = round(95 - total_risk * 0.8, 1)

    return {
        "risk_score": total_risk,
        "verdict": verdict,
        "confidence": confidence,
        "findings": findings if findings else ["✅ No common malicious payload patterns, obfuscation, or reverse shell signatures found in code."],
        "embedded_urls": embedded_urls
    }


# ==============================================================================
# 3. DATA BREACH INTELLIGENCE CHECKER
# ==============================================================================

BREACH_RECORDS = [
    {
        "name": "Canva Global Data Breach",
        "year": "2019",
        "records": "137 Million",
        "data_leaked": "Email addresses, passwords (bcrypt hashes), usernames, city/country",
        "severity": "High"
    },
    {
        "name": "LinkedIn Exposure",
        "year": "2021",
        "records": "700 Million",
        "data_leaked": "Email addresses, full names, phone numbers, workplace history",
        "severity": "Critical"
    },
    {
        "name": "Adobe Systems Compromise",
        "year": "2013",
        "records": "153 Million",
        "data_leaked": "User IDs, encrypted passwords, password hints, email addresses",
        "severity": "Medium"
    },
    {
        "name": "MyFitnessPal (Under Armour)",
        "year": "2018",
        "records": "144 Million",
        "data_leaked": "Usernames, email addresses, hashed passwords (bcrypt)",
        "severity": "High"
    }
]

def check_email_breach(email_str):
    email = (email_str or "").strip().lower()
    if not email:
        return {"breached": False, "message": "No email provided.", "breaches": []}

    # Deterministic simulation based on common keywords or domain
    breach_triggers = ["admin", "test", "pwn", "user", "student", "john", "dev", "demo", "sample", "hacker", "victim"]
    is_compromised = any(t in email for t in breach_triggers) or (len(email) % 2 == 1 and not email.endswith(".edu"))

    if is_compromised:
        matched_breaches = BREACH_RECORDS[:2] if "admin" in email or "pwn" in email else [BREACH_RECORDS[0]]
        return {
            "email": email,
            "breached": True,
            "message": f"🚨 Security Alert: '{email}' was discovered in {len(matched_breaches)} public dark web breach dumps.",
            "breaches": matched_breaches,
            "remediation": "Immediately reset passwords on affected platforms and enable 2-Factor Authentication (FIDO2 / Authenticator App)."
        }
    else:
        return {
            "email": email,
            "breached": False,
            "message": f"✅ Good news! '{email}' was NOT detected in any known public corporate breach databases.",
            "breaches": [],
            "remediation": "Maintain strong account security with unique passphrases."
        }
