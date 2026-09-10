import os
import sqlite3
import hashlib
import json

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishing_database.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Scans Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        module TEXT NOT NULL,
        target TEXT NOT NULL,
        riskScore INTEGER NOT NULL,
        verdict TEXT NOT NULL,
        confidence REAL DEFAULT 0.0,
        details_json TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # Feedback / Reported Threats Table (College Mini Project requirement)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reported_threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        target TEXT NOT NULL,
        threat_type TEXT NOT NULL,
        notes TEXT,
        status TEXT DEFAULT 'Verified Phishing',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # Seed demo user if no users exist
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        demo_pass = hash_password("admin123")
        cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                       ("admin", demo_pass, "admin@cybersec.local"))
        cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                       ("student", hash_password("college2026"), "student@college.edu"))

    # Seed demo scans if empty
    cursor.execute("SELECT COUNT(*) FROM scans")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO scans (user_id, module, target, riskScore, verdict, confidence, details_json)
        VALUES (1, 'url_ml', 'http://paypal-security-update.account-verify.tk/login.php', 94, 'Phishing', 97.2, ?)
        """, (json.dumps({"reason": "Abusive TLD, suspicious subdomains, phishing keywords detected"}),))
        
        cursor.execute("""
        INSERT INTO scans (user_id, module, target, riskScore, verdict, confidence, details_json)
        VALUES (1, 'url_ml', 'https://www.github.com/explore', 5, 'Legitimate', 98.4, ?)
        """, (json.dumps({"reason": "Verified domain, valid SSL, clean structure"}),))

    # Seed demo reports if empty
    cursor.execute("SELECT COUNT(*) FROM reported_threats")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO reported_threats (user_id, target, threat_type, notes, status)
        VALUES (1, 'http://chase-bank-verify-mfa.xyz', 'phishing_missed', 'Fake login page impersonating Chase Bank MFA.', 'Confirmed Phishing')
        """)

    conn.commit()
    conn.close()
    print("[DB] SQLite database initialized successfully.")

def register_user(username, password, email=""):
    conn = get_db()
    cursor = conn.cursor()
    try:
        pw_hash = hash_password(password)
        cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                       (username.strip(), pw_hash, email.strip()))
        conn.commit()
        user_id = cursor.lastrowid
        return {"success": True, "user_id": user_id, "username": username}
    except sqlite3.IntegrityError:
        return {"success": False, "error": "Username already exists."}
    finally:
        conn.close()

def authenticate_user(username, password):
    conn = get_db()
    cursor = conn.cursor()
    pw_hash = hash_password(password)
    cursor.execute("SELECT id, username FROM users WHERE username = ? AND password_hash = ?",
                   (username.strip(), pw_hash))
    user = cursor.fetchone()
    conn.close()
    if user:
        return {"success": True, "user": {"id": user["id"], "username": user["username"]}}
    return {"success": False, "error": "Invalid username or password."}

def save_scan(user_id, module, target, risk_score, verdict, confidence=0.0, details=None):
    conn = get_db()
    cursor = conn.cursor()
    details_str = json.dumps(details or {})
    cursor.execute("""
    INSERT INTO scans (user_id, module, target, riskScore, verdict, confidence, details_json)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, module, target, risk_score, verdict, confidence, details_str))
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id

def get_user_scans(user_id=None, limit=50):
    conn = get_db()
    cursor = conn.cursor()
    if user_id:
        cursor.execute("""
        SELECT id, module, target, riskScore, verdict, confidence, details_json, timestamp
        FROM scans WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?
        """, (user_id, limit))
    else:
        cursor.execute("""
        SELECT id, module, target, riskScore, verdict, confidence, details_json, timestamp
        FROM scans ORDER BY timestamp DESC LIMIT ?
        """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "module": r["module"],
            "target": r["target"],
            "riskScore": r["riskScore"],
            "verdict": r["verdict"],
            "confidence": r["confidence"],
            "details": json.loads(r["details_json"]) if r["details_json"] else {},
            "timestamp": r["timestamp"]
        })
    return results

def save_threat_report(user_id, target, threat_type, notes):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO reported_threats (user_id, target, threat_type, notes)
    VALUES (?, ?, ?, ?)
    """, (user_id, target, threat_type, notes))
    conn.commit()
    report_id = cursor.lastrowid
    conn.close()
    return report_id

def get_all_reports(limit=50):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT r.id, r.target, r.threat_type, r.notes, r.status, r.created_at, u.username
    FROM reported_threats r
    LEFT JOIN users u ON r.user_id = u.id
    ORDER BY r.created_at DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]
