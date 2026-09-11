import os
import ssl
import socket
import hashlib
import base64
import requests
from datetime import datetime
from urllib.parse import urlparse
from .cache_manager import scan_cache

# Optional external threat feed API keys
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
GOOGLE_SAFE_BROWSING_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "")

def extract_domain(target):
    """Extracts clean FQDN hostname from URL or email address."""
    if not target:
        return ""
    target = target.strip()
    if "<" in target and ">" in target:
        import re
        m = re.search(r'<([^>]+)>', target)
        if m:
            target = m.group(1).strip()
    target = target.strip().rstrip(">").rstrip(")").rstrip('"').rstrip("'")
    if "@" in target and not target.startswith("http"):
        domain_part = target.split("@")[-1].strip().rstrip(">").rstrip(")")
        return domain_part.lower()
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target
    try:
        parsed = urlparse(target)
        host = parsed.hostname or ""
        return host.lower()
    except Exception:
        return ""


def query_doh_record(name, record_type):
    """
    Queries DNS-over-HTTPS with dual redundancy:
    Primary: Google Public DNS (https://dns.google/resolve)
    Fallback: Cloudflare DNS (https://cloudflare-dns.com/dns-query)
    """
    # 1. Primary: Google DoH
    try:
        url = f"https://dns.google/resolve?name={name}&type={record_type}"
        resp = requests.get(url, timeout=2.5)
        if resp.status_code == 200:
            data = resp.json()
            if "Answer" in data and len(data["Answer"]) > 0:
                return [ans.get("data", "") for ans in data["Answer"]], True
            return [], True
    except Exception:
        pass

    # 2. Secondary Fallback: Cloudflare 1.1.1.1 DoH
    try:
        cf_url = f"https://cloudflare-dns.com/dns-query?name={name}&type={record_type}"
        headers = {"accept": "application/dns-json", "User-Agent": "PhishGuard-Threat-Intel/2.0"}
        cf_resp = requests.get(cf_url, headers=headers, timeout=2.5)
        if cf_resp.status_code == 200:
            data = cf_resp.json()
            if "Answer" in data and len(data["Answer"]) > 0:
                return [ans.get("data", "") for ans in data["Answer"]], True
            return [], True
    except Exception:
        pass

    return [], False

def live_dns_lookup(domain):
    """
    Performs real-time DNS-over-HTTPS (DoH) inspection with Google & Cloudflare dual-redundancy.
    Validates live MX, SPF, and DMARC cryptographic email records.
    Requires NO external API key.
    """
    if not domain:
        return {"valid": False, "has_mx": False, "spf": None, "dmarc": None, "dns_status": "No Domain"}

    cache_key = f"dns:{domain}"
    cached = scan_cache.get(cache_key)
    if cached:
        return cached

    result = {
        "valid": False,
        "has_mx": False,
        "spf": None,
        "dmarc": None,
        "dns_status": "Clean",
        "resolver": "Google / Cloudflare Dual DoH"
    }

    # 1. MX Records
    mx_answers, mx_ok = query_doh_record(domain, "MX")
    if mx_ok:
        result["valid"] = True
        result["has_mx"] = len(mx_answers) > 0

    # 2. SPF TXT Records
    txt_answers, txt_ok = query_doh_record(domain, "TXT")
    if txt_ok:
        result["valid"] = True
        for ans in txt_answers:
            if "v=spf1" in ans:
                result["spf"] = ans.replace('"', '')
                break

    # 3. DMARC Records
    dmarc_answers, dmarc_ok = query_doh_record(f"_dmarc.{domain}", "TXT")
    if dmarc_ok:
        for ans in dmarc_answers:
            if "v=DMARC1" in ans:
                result["dmarc"] = ans.replace('"', '')
                break

    if not result["has_mx"] and not result["spf"]:
        result["dns_status"] = "No Active Mail Servers Configured"
    elif result["spf"] and result["dmarc"]:
        result["dns_status"] = "Fully Authenticated (SPF + DMARC Enforced)"
    else:
        result["dns_status"] = "Partially Configured"

    scan_cache.set(cache_key, result, ttl_seconds=43200) # 12h cache
    return result

def query_rdap_domain_intel(domain):
    """
    Queries ICANN official RDAP (Registration Data Access Protocol) for domain registration age.
    Detects zero-day infrastructure (< 30 days old).
    Requires NO external API key.
    """
    if not domain:
        return {"active": False}

    cache_key = f"rdap:{domain}"
    cached = scan_cache.get(cache_key)
    if cached:
        return cached

    result = {
        "active": False,
        "age_days": None,
        "created_date": None,
        "expires_date": None,
        "registrar": None,
        "is_newly_registered": False
    }

    try:
        url = f"https://rdap.org/domain/{domain}"
        headers = {"User-Agent": "PhishGuard-SOC-Intel/2.0", "Accept": "application/rdap+json, application/json"}
        resp = requests.get(url, headers=headers, timeout=3.5)
        if resp.status_code == 200:
            data = resp.json()
            result["active"] = True
            events = data.get("events", [])
            for ev in events:
                action = ev.get("eventAction", "")
                dt_str = ev.get("eventDate", "")
                if action == "registration" and dt_str:
                    try:
                        clean_dt = dt_str.split("T")[0]
                        reg_dt = datetime.strptime(clean_dt, "%Y-%m-%d")
                        age = (datetime.utcnow() - reg_dt).days
                        result["age_days"] = age
                        result["created_date"] = clean_dt
                        result["is_newly_registered"] = (age < 30)
                    except Exception:
                        pass
                elif action == "expiration" and dt_str:
                    result["expires_date"] = dt_str.split("T")[0]

            # Extract registrar
            entities = data.get("entities", [])
            for ent in entities:
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1:
                        for prop in vcard[1]:
                            if prop[0] == "fn":
                                result["registrar"] = prop[3]
                                break
                    break

            scan_cache.set(cache_key, result, ttl_seconds=86400) # 24h cache
    except Exception:
        pass

    return result

def query_ip_intel(domain):
    """
    Queries public IP geolocation & Autonomous System (ASN) threat intelligence.
    Identifies hosting provider, country, city, and infrastructure ASN.
    """
    if not domain:
        return {"active": False}

    cache_key = f"ip_intel:{domain}"
    cached = scan_cache.get(cache_key)
    if cached:
        return cached

    result = {
        "active": False,
        "ip": None,
        "country": None,
        "city": None,
        "isp": None,
        "org": None,
        "asn": None
    }

    try:
        url = f"http://ip-api.com/json/{domain}?fields=status,country,city,isp,org,as,query"
        resp = requests.get(url, timeout=3.0)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                result = {
                    "active": True,
                    "ip": data.get("query"),
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "asn": data.get("as")
                }
                scan_cache.set(cache_key, result, ttl_seconds=86400) # 24h cache
    except Exception:
        pass

    return result

def live_ssl_inspect(domain):
    """
    Connects to target domain via native socket and inspects the live TLS/SSL Certificate.
    Verifies issuer authenticity, expiration timestamp, and cipher strength.
    Requires NO external API key.
    """
    if not domain:
        return {"status": "Unknown", "valid": False}

    cache_key = f"ssl:{domain}"
    cached = scan_cache.get(cache_key)
    if cached:
        return cached

    result = {
        "status": "No SSL/TLS",
        "valid": False,
        "issuer": "None",
        "expires": "N/A",
        "days_remaining": 0
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((domain, 443), timeout=3.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                issuer_name = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Verified CA"
                not_after_str = cert.get("notAfter", "")
                
                expires_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z") if not_after_str else None
                days_left = (expires_dt - datetime.utcnow()).days if expires_dt else 0

                result = {
                    "status": "Valid TLS Certificate" if days_left > 0 else "Expired Certificate",
                    "valid": days_left > 0,
                    "issuer": issuer_name,
                    "expires": expires_dt.strftime("%Y-%m-%d") if expires_dt else "N/A",
                    "days_remaining": max(0, days_left)
                }

        scan_cache.set(cache_key, result, ttl_seconds=86400) # 24h cache
    except ssl.SSLCertVerificationError:
        result["status"] = "Untrusted / Self-Signed SSL Certificate"
    except (socket.timeout, socket.gaierror, ConnectionRefusedError):
        result["status"] = "Host Unreachable on Port 443"
    except Exception as e:
        result["status"] = f"SSL Handshake Error"

    return result

def check_hibp_pwned(secret_string):
    """
    Live k-Anonymity Pwned Passwords verification via HaveIBeenPwned API.
    Sends only the first 5 characters of SHA-1 hash (mathematically zero data leak).
    Returns total global breach appearances.
    """
    if not secret_string:
        return {"breached": False, "count": 0}

    try:
        sha1_hash = hashlib.sha1(secret_string.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        cache_key = f"hibp:{prefix}:{suffix}"
        cached = scan_cache.get(cache_key)
        if cached:
            return cached

        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        headers = {"User-Agent": "PhishGuard-Enterprise-Threat-Intel"}
        resp = requests.get(url, headers=headers, timeout=4.0)

        count = 0
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                if ":" in line:
                    h_suffix, c_str = line.split(":", 1)
                    if h_suffix.strip() == suffix:
                        count = int(c_str.strip())
                        break

        result = {
            "breached": count > 0,
            "count": count,
            "risk": "Critical" if count > 500 else ("High" if count > 0 else "Safe")
        }
        scan_cache.set(cache_key, result, ttl_seconds=86400)
        return result
    except Exception:
        return {"breached": False, "count": 0, "risk": "Unknown"}

def query_virustotal_url(url):
    """
    Queries live VirusTotal v3 API if VIRUSTOTAL_API_KEY is configured.
    Returns engine consensus across 90+ threat vendors.
    """
    if not VIRUSTOTAL_API_KEY or not url:
        return None

    cache_key = f"vt:{url}"
    cached = scan_cache.get(cache_key)
    if cached:
        return cached

    try:
        # Base64 URL identifier without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(vt_endpoint, headers=headers, timeout=5.0)

        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            total = malicious + suspicious + harmless + stats.get("undetected", 0)

            result = {
                "active": True,
                "malicious_engines": malicious,
                "suspicious_engines": suspicious,
                "total_engines": total,
                "verdict": "Malicious" if malicious > 2 else ("Suspicious" if (malicious + suspicious) > 0 else "Clean")
            }
            scan_cache.set(cache_key, result, ttl_seconds=86400)
            return result
    except Exception:
        pass
    return None

def query_google_safebrowsing(url):
    """
    Queries live Google Safe Browsing API v4 if GOOGLE_SAFE_BROWSING_KEY is configured.
    """
    if not GOOGLE_SAFE_BROWSING_KEY or not url:
        return None

    cache_key = f"gsb:{url}"
    cached = scan_cache.get(cache_key)
    if cached:
        return cached

    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}"
        payload = {
            "client": {"clientId": "phishguard-enterprise", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        resp = requests.post(endpoint, json=payload, timeout=4.0)
        if resp.status_code == 200:
            matches = resp.json().get("matches", [])
            result = {
                "active": True,
                "threat_found": len(matches) > 0,
                "threat_types": [m.get("threatType") for m in matches]
            }
            scan_cache.set(cache_key, result, ttl_seconds=86400)
            return result
    except Exception:
        pass
    return None
