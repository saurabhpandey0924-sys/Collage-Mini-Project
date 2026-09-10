# 🛡️ Advanced Phishing Website & Email Detection Using Machine Learning

[![Python 3.13](https://img.shields.io/badge/Python-3.13+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org/)
[![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/HTML)
[![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/CSS)
[![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![Model Accuracy](https://img.shields.io/badge/RF_Accuracy-99.57%25-2ed573?style=for-the-badge)](#-machine-learning-evaluation-metrics)
[![Status](https://img.shields.io/badge/Status-Complete_&_Verified-blue?style=for-the-badge)](#)

> **College Academic Mini-Project**  
> **Topic:** Advanced Phishing Website & Email Detection Using Machine Learning  
> **Author:** Saurabh P Pandey  
> **Repository:** [Collage-Mini-Project](https://github.com/saurabhpandey0924-sys/Collage-Mini-Project)

---

## 📌 Project Overview

Phishing remains the number one vector for cyberattacks, credential theft, and ransomware deployment. Traditional static security tools rely heavily on **blacklists** (e.g., DNS blocklists), which completely fail against zero-day, newly registered domains, and modern evasive attack tactics.

**Advanced Phishing Website & Email Detection Using Machine Learning** is a full-stack cybersecurity platform that moves beyond static blacklists toward **dynamic, feature-based pattern recognition**. By extracting 16 lexical, structural, and cryptographic features from URLs and analyzing email content through NLP intent classification and automated embedded link scanning, the system provides real-time threat verdicts with high statistical confidence.

---

## ✨ Key Features & Core Modules

### 1. 🌐 URL & Website Phishing Detection (Machine Learning Engine)
- **16-Feature Extraction Engine**: Ingests raw URLs and inspects lexical structure, host anomalies, and obfuscation tricks.
- **Random Forest Classifier**: High-precision ensemble model delivering an accuracy of **99.57%**.
- **Real-Time Result Dashboard**: Displays Safe vs. Phishing verdicts, risk meter (0–100), ML confidence percentage, and an interactive grid of color-coded feature explanation cards.
- **Preloaded Test Scenarios**: One-click test cases for PayPal phishing, IP address attacks, typosquatting domains, and verified legitimate sites.

### 2. 📧 Email Phishing & Threat Triage (NLP + Embedded Link ML)
- **Header Security Verification**: Inspects raw email headers for SPF, DKIM, and DMARC policy compliance.
- **Domain Spoofing & Reply-To Mismatch**: Catches domain impersonation when From and Reply-To domains disagree.
- **NLP & Lexical Intent Scoring**: Evaluates psychological manipulation patterns (urgency, panic, wire-fraud requests, credential harvesting, authority pressure).
- **Automated Embedded Link Extraction**: Extracts all hyperlinks from the email body and passes them into the URL ML Classifier to calculate a unified risk score.

### 3. 📊 Model Performance Analytics Dashboard (College Evaluation Center)
- **Algorithm Benchmark Comparison**: Side-by-side performance metrics for **Random Forest**, **Logistic Regression**, and **Decision Trees**.
- **Confusion Matrix & Precision/Recall Metrics**: Visual validation of false positive and false negative rates.
- **Top Feature Importances Bar Chart**: Ranking of the most predictive features in the Random Forest model.
- **Scan History Table**: Searchable, filterable audit log of past scans with instant **CSV export**.

### 4. 📢 Community Feedback & Threat Reporting System
- Allows users and analysts to report missed phishing sites or false positives.
- Stores user-contributed intelligence into SQLite to simulate continuous model feedback and threat updates.

### 5. 🔐 User Authentication & Session Security
- Full user registration and login system with SHA-256 hashed password storage in SQLite and token-based session protection.

---

## 🔬 Feature Extraction Engine (16 URL Features)

The feature extraction engine (`backend/ml/feature_extractor.py`) inspects 16 key attributes:

| # | Feature Name | Description | Threat Indicator |
|---|--------------|-------------|------------------|
| 1 | **IP Address Usage** | Detects raw IPv4/IPv6 addresses bypassing DNS | High risk |
| 2 | **URL Length** | Categorizes normal (<54), suspicious (54–75), and long (>75) | Concealed redirects |
| 3 | **Shortening Service** | Detects bit.ly, tinyurl, t.co, is.gd, etc. | Masked destinations |
| 4 | **Authentication `@` Symbol** | Checks for `@` symbol causing browser redirection | Basic auth exploits |
| 5 | **Double Slash `//` Redirect** | Flags `//` inside path after protocol (index > 7) | Open redirect trick |
| 6 | **Prefix / Suffix `-`** | Detects hyphens in domain (e.g. `paypal-security.com`) | Lookalike domains |
| 7 | **Subdomain Depth** | Counts nested dots in hostname | Multi-level spoofing |
| 8 | **SSL / Encryption Protocol** | Checks for valid HTTPS vs unencrypted HTTP | Insecure transport |
| 9 | **HTTPS Token in Domain** | Detects `'https'` inside domain text (`https-verify.com`) | Brand deception |
| 10 | **Port Specification** | Flags non-standard ports (e.g. `:8080`, `:8888`) | Ad-hoc phishing hosts |
| 11 | **Suspicious TLD** | Matches against abusive free/low-cost TLDs (`.tk`, `.xyz`, etc.)| Short-lived domains |
| 12 | **Domain Shannon Entropy** | Calculates mathematical randomness of domain string | DGA / Algorithm hosts |
| 13 | **Phishing Keyword Density**| Scans for triggers (`login`, `verify`, `banking`, `secure`) | Credential baiting |
| 14 | **Numeric Digits in Host** | Counts numeric characters in the hostname | Random host strings |
| 15 | **URL Path Depth** | Measures directory complexity of the resource path | Obfuscated structure |
| 16 | **Special Character Count** | Tallies `?`, `=`, `&`, `%`, `_`, `~` in query strings | Token obfuscation |

---

## 🧠 Machine Learning Evaluation Metrics

The classification models were trained and validated on a balanced benchmark dataset of **3,500 samples** representing features from the UCI Phishing Websites Dataset and live PhishTank feeds:

| Algorithm | Accuracy | Precision | Recall | F1-Score | Status |
|-----------|----------|-----------|--------|----------|--------|
| **Random Forest Classifier** | **99.57%** | **99.57%** | **99.57%** | **99.57%** | 🏆 **Production Model** |
| **Logistic Regression** | 99.71% | 99.71% | 99.71% | 99.71% | Evaluated |
| **Decision Tree Classifier** | 97.57% | 97.54% | 97.60% | 97.57% | Evaluated |

### Top Predictive Features (Random Forest Feature Importances)
1. **Phishing Keyword Density** (~18.5% importance)
2. **SSL / Protocol Security** (~15.2% importance)
3. **Subdomain Depth** (~14.1% importance)
4. **Prefix/Suffix `-` in Domain** (~11.4% importance)
5. **URL Length** (~9.8% importance)
6. **Top-Level Domain (TLD) Risk** (~8.6% importance)
7. **Shortening Service Detection** (~7.3% importance)
8. **Domain Shannon Entropy** (~5.7% importance)

---

## 🛠️ Technology Stack

- **Machine Learning & Data Science**:
  - `scikit-learn` — Model training, cross-validation, and inference (Random Forest, Logistic Regression, Decision Tree)
  - `pandas` & `numpy` — Feature vector manipulation and statistical datasets
  - `joblib` — Binary model serialization (`phishing_rf_model.pkl`)
- **Backend & APIs**:
  - `Python 3.13` — Core execution environment
  - `Flask` & `flask-cors` — RESTful API architecture and static file serving
  - `SQLite3` — Relational database for scans, user auth, and threat reports
- **Frontend Architecture**:
  - `HTML5` & `Vanilla CSS3` — Responsive glassmorphism interface with dark-mode palette
  - `JavaScript (ES6+)` — Dynamic asynchronous DOM updates and API clients

---

## 📂 Project Structure

```bash
Collage-Mini-Project/
├── index.html                    # Platform home & core modules dashboard
├── link-scanner.html             # Machine Learning URL & Website Phishing Detector
├── email-analyzer.html           # Email threat triage & embedded link ML analyzer
├── dashboard.html                # Model evaluation metrics & scan history analytics
├── login.html                    # User authentication (Login / Register)
├── sms-analyzer.html             # SMS / Smishing threat detector
├── data-breach.html              # Dark-web credential breach checker
├── code-analyzer.html            # Script and payload analyzer
├── style.css                     # Global UI design system, glassmorphism, animations
├── script.js                     # Client-side validation, API communication, triage logic
├── package.json                  # Root npm project launcher
├── .gitignore                    # Git exclusions (.venv, node_modules, secrets)
├── README.md                     # Comprehensive project documentation
│
└── backend/
    ├── app.py                    # Flask REST API server & static asset host
    ├── database.py               # SQLite schema (users, scans, reported_threats)
    ├── requirements.txt          # Python dependencies specification
    ├── package.json              # Backend script runner
    ├── phishing_database.db      # SQLite database file
    │
    └── ml/
        ├── __init__.py           # ML package initializer
        ├── feature_extractor.py  # 16-Feature extraction engine
        ├── model_trainer.py      # Random Forest trainer, evaluator & predictor
        ├── email_detector.py     # NLP lexical & header security engine
        ├── phishing_rf_model.pkl # Serialized trained Random Forest model
        └── model_metrics.json    # Benchmark evaluation metrics & feature importances
```

---

## 🚀 Quick Start & Installation Guide

### Prerequisites
- [Python 3.10+](https://python.org) installed
- [Node.js](https://nodejs.org) (optional, for `npm start`)
- Git installed

### 1. Clone the Repository
```bash
git clone https://github.com/saurabhpandey0924-sys/Collage-Mini-Project.git
cd Collage-Mini-Project
```

### 2. Set Up Python Virtual Environment
```bash
cd backend
python -m venv .venv

# On Windows (PowerShell):
.\.venv\Scripts\activate

# On macOS / Linux:
source .venv/bin/activate

# Install required packages
pip install -r requirements.txt
```

### 3. Run the Application

**Option A: Using npm (from project root or backend)**:
```bash
npm start
```

**Option B: Using Python directly**:
```bash
cd backend
.\.venv\Scripts\python app.py
```

### 4. Access the Web Application
Open your browser and navigate to:
👉 **[http://localhost:3000](http://localhost:3000)**

**Default Credentials**:
- Username: `admin` | Password: `admin123`
- Username: `student` | Password: `college2026`
*(Or click "Register here" on the login screen to create a new user profile)*

---

## 📡 REST API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/predict/url` | Extract 16 features & predict URL legitimacy via ML | Yes (Bearer Token) |
| `POST` | `/api/predict/email` | Comprehensive email NLP triage & embedded link scan | Yes (Bearer Token) |
| `GET`  | `/api/model-info` | Scikit-Learn accuracy, confusion matrix & feature weights | No |
| `GET`  | `/api/history` | Retrieve logged user scan history | Yes (Bearer Token) |
| `POST` | `/api/history` | Log a manual threat scan | Yes (Bearer Token) |
| `POST` | `/api/report` | Submit community threat feedback / false positive | Yes (Bearer Token) |
| `GET`  | `/api/reports` | List community verified threat reports | No |
| `POST` | `/api/auth/register` | Register new user account | No |
| `POST` | `/api/auth/login` | Authenticate credentials and return session token | No |
| `GET`  | `/api/auth/me` | Verify active session status | Yes (Bearer Token) |

---

## 🎓 College Viva / Project Q&A

**Q1: Why use Machine Learning instead of static domain blacklists?**  
> *Blacklists only block known domains that have already caused damage. Phishers register thousands of disposable domains daily that remain active for only a few hours. Our ML model evaluates 16 intrinsic structural and lexical features to detect zero-day attacks even if the domain was created minutes ago.*

**Q2: Why was Random Forest chosen as the primary classifier?**  
> *Random Forest is an ensemble of decision trees that minimizes overfitting through bagging and feature randomness. It performs exceptionally well on tabular URL feature vectors, delivering 99.57% accuracy and providing clear feature importance rankings.*

**Q3: How does Shannon Entropy detect malicious websites?**  
> *Legitimate brand domains (like `google.com` or `chase.com`) have low entropy because they use dictionary words. Algorithmically generated domains (DGAs) used by botnets and bulletproof hosts contain high randomness, which produces an elevated Shannon entropy score (>3.8 bits).*

**Q4: How does the system handle email phishing?**  
> *The email engine performs multi-layered triage: it checks cryptographic headers (SPF, DKIM, DMARC), scans for domain mismatches between sender and reply-to, flags psychological urgency words, and automatically extracts hyperlinks to classify them using the URL ML model.*

---

## 👨‍💻 Author & Acknowledgments

- **Developer:** Saurabh P Pandey
- **GitHub:** [@saurabhpandey0924-sys](https://github.com/saurabhpandey0924-sys)
- **Academic Context:** College Mini-Project Submission (2026)
- **Dataset Reference:** UCI Machine Learning Repository & PhishTank Community Feeds
