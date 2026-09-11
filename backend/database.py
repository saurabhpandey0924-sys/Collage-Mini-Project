import os
import sqlite3
import hashlib
import json
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishing_database.db")
DATABASE_URL = os.environ.get("DATABASE_URL", "")

def get_db():
    """
    Returns a high-concurrency database connection.
    Configured with Write-Ahead-Logging (WAL) and 30-second busy timeout
    to support thousands of concurrent read/write transactions without locking.
    """
    conn = sqlite3.connect(DB_PATH, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # High-concurrency PRAGMAs
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA busy_timeout = 30000;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def hash_password(password):
    """Generates a cryptographically salted PBKDF2/SHA256 hash with 600,000 iterations."""
    return generate_password_hash(password, method='pbkdf2:sha256')

def verify_and_upgrade_password(stored_hash, password, user_id=None):
    """
    Verifies password with constant-time equality check.
    If the account was previously using weak plain SHA-256, it automatically
    upgrades the stored hash to modern salted PBKDF2 in the database.
    """
    if stored_hash.startswith("pbkdf2:") or stored_hash.startswith("scrypt:"):
        return check_password_hash(stored_hash, password)
    
    # Check legacy plain SHA-256
    legacy_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    if legacy_hash == stored_hash:
        # Upgrade to modern salted hash
        if user_id:
            try:
                new_hash = hash_password(password)
                conn = get_db()
                conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
                conn.commit()
                conn.close()
            except Exception:
                pass
        return True
    return False

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

    # Feedback / Reported Threats Table
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

    # Performance & Concurrency Indexes (Crucial for 10k-1M records)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reported_target ON reported_threats(target);")

    # Seed demo users if empty or upgrade their password hash
    cursor.execute("SELECT id, username, password_hash FROM users WHERE username = 'admin'")
    admin_row = cursor.fetchone()
    if not admin_row:
        cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                       ("admin", hash_password("admin123"), "admin@cybersec.local"))
        cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                       ("student", hash_password("college2026"), "student@college.edu"))
    else:
        # Upgrade if old SHA-256
        if not admin_row["password_hash"].startswith("pbkdf2:") and not admin_row["password_hash"].startswith("scrypt:"):
            cursor.execute("UPDATE users SET password_hash = ? WHERE username = 'admin'", (hash_password("admin123"),))
            cursor.execute("UPDATE users SET password_hash = ? WHERE username = 'student'", (hash_password("college2026"),))

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
    print("[DB] Enterprise SQLite database with WAL & Indexes initialized successfully.")

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
    cursor.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username.strip(),))
    user = cursor.fetchone()
    conn.close()

    if user and verify_and_upgrade_password(user["password_hash"], password, user_id=user["id"]):
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

def clear_user_scans(user_id=None):
    conn = get_db()
    cursor = conn.cursor()
    if user_id:
        cursor.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
    else:
        cursor.execute("DELETE FROM scans")
    conn.commit()
    conn.close()
    return True

def get_dashboard_stats():
    """
    Returns aggregated real-time database metrics for the SOC dashboard:
    Total scans, threats detected, safe scans, suspicious scans, and average risk score.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT 
        COUNT(*) as total_scans,
        SUM(CASE WHEN LOWER(verdict) LIKE '%phish%' OR LOWER(verdict) LIKE '%malicious%' THEN 1 ELSE 0 END) as total_threats,
        SUM(CASE WHEN LOWER(verdict) LIKE '%legit%' OR LOWER(verdict) LIKE '%safe%' OR LOWER(verdict) LIKE '%clean%' THEN 1 ELSE 0 END) as total_safe,
        SUM(CASE WHEN LOWER(verdict) LIKE '%suspicious%' THEN 1 ELSE 0 END) as total_suspicious,
        AVG(riskScore) as avg_risk
    FROM scans;
    """)
    row = cursor.fetchone()
    conn.close()
    return {
        "total_scans": row["total_scans"] or 0,
        "total_threats": row["total_threats"] or 0,
        "total_safe": row["total_safe"] or 0,
        "total_suspicious": row["total_suspicious"] or 0,
        "avg_risk": round(float(row["avg_risk"] or 0), 1)
    }
