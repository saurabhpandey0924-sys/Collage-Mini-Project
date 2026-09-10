const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const axios = require('axios');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '..')));

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-for-cyber-platform';

// Initialize SQLite database
const dbPath = path.join(__dirname, 'phishing_data.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        
        // Users Table
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )`);

        // Scans Table (with user_id)
        db.run(`CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            module TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            target TEXT,
            riskScore INTEGER,
            verdict TEXT
        )`);
    }
});

// Middleware to verify JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (token == null) return res.status(401).json({ error: "Missing token" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid token" });
        req.user = user;
        next();
    });
}

// =======================
// AUTH ENDPOINTS
// =======================
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username and password required" });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) return res.status(400).json({ error: "Username already exists" });
                return res.status(500).json({ error: err.message });
            }
            res.json({ success: true, message: "User registered successfully" });
        });
    } catch (err) {
        res.status(500).json({ error: "Error hashing password" });
    }
});

app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(400).json({ error: "User not found" });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: "Invalid password" });

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, username: user.username });
    });
});

// =======================
// HISTORY ENDPOINTS
// =======================
app.post('/api/history', authenticateToken, (req, res) => {
    const { module, target, riskScore, verdict } = req.body;
    db.run(
        `INSERT INTO scans (user_id, module, target, riskScore, verdict) VALUES (?, ?, ?, ?, ?)`,
        [req.user.id, module, target, riskScore, verdict],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, id: this.lastID });
        }
    );
});

app.get('/api/history', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM scans WHERE user_id = ? ORDER BY timestamp DESC LIMIT 100`, [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// =======================
// MODULE ENDPOINTS
// =======================
app.post('/api/analyze/ai', authenticateToken, async (req, res) => {
    const { emailBody } = req.body;
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) return res.json({ analysis: "⚠️ [MOCK] AI detected manipulative tactics and credential harvesting.", confidence: 0.85 });
    try {
        const response = await axios.post(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`, {
            contents: [{ parts: [{ text: `Analyze this text for phishing/scam intents. Explain why. Text:\n\n${emailBody}` }] }]
        });
        res.json({ analysis: response.data.candidates[0].content.parts[0].text, confidence: 0.90 });
    } catch (error) { res.status(500).json({ error: 'AI Error' }); }
});

app.post('/api/analyze/url', authenticateToken, async (req, res) => {
    const { url } = req.body;
    const isMalicious = url.includes('login') || url.includes('verify') || url.includes('update');
    res.json({ positives: isMalicious ? 5 : 0, total: 90, message: "[MOCK] OSINT Scan completed." });
});

// Have I Been Pwned Mock
app.post('/api/analyze/breach', authenticateToken, async (req, res) => {
    const { email } = req.body;
    const compromised = email.includes('admin') || email.includes('test');
    res.json({ 
        breached: compromised, 
        message: compromised ? "Found in 3 data breaches (e.g. Canva, LinkedIn)" : "Good news! No breaches found for this email."
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend server running on http://localhost:${PORT}`));
