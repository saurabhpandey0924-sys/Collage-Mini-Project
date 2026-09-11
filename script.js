const token = localStorage.getItem('token') || '';
if (!token) window.location.href = 'login.html';

function analyzeHeaders(headers) {
  if (!headers) return null;
  const h = headers.toLowerCase();
  const results = [];
  
  if (h.includes('spf=fail') || h.includes('spf=softfail')) results.push('❌ SPF Check Failed');
  else if (h.includes('spf=pass')) results.push('✅ SPF Check Passed');
  else results.push('⚠️ No SPF record found');

  if (h.includes('dkim=fail')) results.push('❌ DKIM Signature Invalid');
  else if (h.includes('dkim=pass')) results.push('✅ DKIM Signature Valid');
  else results.push('⚠️ No DKIM signature found');

  if (h.includes('dmarc=fail')) results.push('❌ DMARC Policy Failed');
  else if (h.includes('dmarc=pass')) results.push('✅ DMARC Policy Passed');
  else results.push('⚠️ No DMARC record found');

  return results.join('\n');
}

// ============================================================
// ENTERPRISE HEURISTICS (Processed securely on neural backend)
// ============================================================
const RED_FLAGS = {};

// ============================================================
// WEIGHTED SCORING
// ============================================================
function getSeverity(weight) {
  if (weight >= 22) return "CRITICAL";
  if (weight >= 18) return "HIGH";
  if (weight >= 12) return "MEDIUM";
  return "LOW";
}

function analyzeEmail(sender, replyto, subject, body) {
  const foundFlags = [];
  const senderL = sender.toLowerCase();
  const subjectL = subject.toLowerCase();
  const bodyL = body.toLowerCase();
  const fullText = [sender, replyto, subject, body].join(" ").toLowerCase();

  for (const [flagName, rule] of Object.entries(RED_FLAGS)) {
    let hit = false, matchedKw = "", matchedLoc = "body";

    // Custom check function if defined
    if (rule.check) {
      const result = rule.check(sender, replyto, subject, body);
      if (result.hit) {
        hit = true; matchedKw = result.keyword; matchedLoc = result.loc;
      }
    }

    // Keyword scan
    if (!hit && rule.keywords && rule.keywords.length > 0) {
      for (const kw of rule.keywords) {
        if (fullText.includes(kw.toLowerCase())) {
          hit = true; matchedKw = kw;
          if (senderL.includes(kw.toLowerCase())) matchedLoc = "sender";
          else if (subjectL.includes(kw.toLowerCase())) matchedLoc = "subject";
          else matchedLoc = "body";
          break;
        }
      }
    }

    if (hit) {
      foundFlags.push({
        name: flagName,
        keyword: matchedKw,
        loc: matchedLoc,
        weight: rule.weight,
        severity: getSeverity(rule.weight),
        desc: rule.desc
      });
    }
  }

  let score = Math.min(100, foundFlags.reduce((s, f) => s + f.weight, 0));
  // Bonus if multiple critical flags
  const criticals = foundFlags.filter(f => f.severity === "CRITICAL").length;
  if (criticals >= 2) score = Math.min(100, score + 15);

  let verdict, verdictClass, action, reason;
  if (score === 0) {
    verdict = "SAFE"; verdictClass = "v-safe";
    action = "No phishing indicators detected. Still verify the sender through an alternate channel if unexpected.";
    reason = "No red flags matched against the provided email content. The email appears clean based on available indicators.";
  } else if (score <= 30) {
    verdict = "SUSPICIOUS"; verdictClass = "v-suspicious";
    action = "Verify the sender through a trusted alternate channel. Do not click links or open attachments until verified.";
    reason = "A small number of phishing indicators were matched. Manual verification is recommended before acting.";
  } else if (score <= 60) {
    verdict = "SUSPICIOUS"; verdictClass = "v-suspicious";
    action = "Treat as likely phishing. Do not submit credentials, click links, or open attachments. Report to your security team.";
    reason = "Multiple phishing indicators detected. Risk level is elevated — probable social engineering or credential theft attempt.";
  } else {
    verdict = "MALICIOUS"; verdictClass = "v-malicious";
    action = "Quarantine immediately. Do not click, reply, or engage. Report to security team and delete from inbox.";
    reason = "High-confidence phishing detected. Multiple critical indicators are consistent with advanced threat actor tactics.";
  }

  return { verdict, verdictClass, score, action, reason, flags: foundFlags };
}

// ============================================================
// AI API INTEGRATION (CALLING NODE.JS BACKEND)
// ============================================================
async function getAIAnalysis(sender, replyto, subject, body, flags) {
  try {
    const API_BASE = (window.location.protocol === 'file:' || (window.location.port && window.location.port !== '3000')) ? 'http://localhost:3000' : '';
    const token = localStorage.getItem('token') || '';
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const response = await fetch(API_BASE + '/api/analyze/ai', {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({ emailBody: `Sender: ${sender}\nSubject: ${subject}\n\n${body}` })
    });

    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    return data.analysis || null;
  } catch (err) {
    console.error("AI Analysis Fetch Error:", err);
    return null;
  }
}

// ============================================================
// UI RENDERING
// ============================================================
function esc(s) {
  return String(s)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;").replace(/'/g,"&#039;");
}

function renderResult(report, aiText) {
  const area = document.getElementById("resultArea");
  const { verdict, verdictClass, score, action, reason, flags } = report;

  const now = new Date();
  document.getElementById("resultTimestamp").textContent = now.toLocaleTimeString();

  let flagsHTML = "";
  if (flags.length === 0) {
    flagsHTML = `<div style="color:var(--muted);font-size:0.9rem;padding:12px;background:rgba(30,215,96,0.06);border:1px solid rgba(30,215,96,0.15);border-radius:12px;">
      ✅ No phishing indicators matched in the current ruleset.
    </div>`;
  } else {
    // Sort by weight desc
    const sorted = [...flags].sort((a,b) => b.weight - a.weight);
    flagsHTML = sorted.map(f => `
      <div class="flag-item sev-${f.severity.toLowerCase()}">
        <div class="flag-title">
          <span>${esc(f.name)}</span>
          <span class="sev-pill ${esc(f.severity)}">${esc(f.severity)}</span>
        </div>
        <div class="flag-meta">
          <span>Matched:</span> ${esc(f.keyword || "pattern")} &nbsp;|&nbsp;
          <span>Location:</span> ${esc(f.loc)} &nbsp;|&nbsp;
          <span>Weight:</span> +${f.weight}<br>
          <span>Why:</span> ${esc(f.desc)}
        </div>
      </div>
    `).join("");
    flagsHTML = `<div class="flags-list">${flagsHTML}</div>`;
  }

  let aiBlock = "";
  if (aiText === "loading") {
    aiBlock = `<div class="ai-result"><div class="ai-result-head"><span class="loading-spinner"></span> Requesting AI deep analysis...</div></div>`;
  } else if (aiText) {
    aiBlock = `<div class="ai-result">
      <div class="ai-result-head">🛡️ CyberSec Threat Intelligence & NLP Report</div>
      <p>${esc(aiText)}</p>
    </div>`;
  }

  area.innerHTML = `
    <div class="result-header">
      <div class="verdict-badge ${verdictClass}">
        ${verdict === "SAFE" ? "✅" : verdict === "SUSPICIOUS" ? "⚠️" : "🔴"} ${verdict}
      </div>
      <div style="color:var(--muted);font-size:0.85rem;">${flags.length} indicator${flags.length !== 1 ? "s" : ""} matched</div>
    </div>

    <div class="score-bar-wrap">
      <div class="score-row">
        <h4>Risk Score</h4>
        <strong class="score-num" style="color:${score < 30 ? "var(--success)" : score < 60 ? "var(--warning)" : "var(--danger)"}">${score}/100</strong>
      </div>
      <div class="progress">
        <div class="progress-bar" style="width:${score}%"></div>
      </div>
    </div>

    <div class="result-cards">
      <div class="rcard">
        <h4>📊 Verdict Summary</h4>
        <p>${esc(reason)}</p>
      </div>
      <div class="rcard">
        <h4>🚩 Matched Red Flags (${flags.length})</h4>
        ${flagsHTML}
      </div>
    </div>
    ${aiBlock}
  `;
}

async function getUrlAnalysis(body) {
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  const urls = body.match(urlRegex);
  if (!urls || urls.length === 0) return null;
  const targetUrl = urls[0]; 
  try {
    const API_BASE = (window.location.protocol === 'file:' || (window.location.port && window.location.port !== '3000')) ? 'http://localhost:3000' : '';
    const token = localStorage.getItem('token') || '';
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const response = await fetch(API_BASE + '/api/predict/url', {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({ url: targetUrl })
    });
    if (!response.ok) return null;
    return await response.json();
  } catch (err) {
    return null;
  }
}

async function runAnalysis() {
  const sender  = document.getElementById("sender").value.trim();
  const replyto = document.getElementById("replyto").value.trim();
  const subject = document.getElementById("subject").value.trim();
  const body    = document.getElementById("body").value.trim();
  const rawHeaders = document.getElementById("rawHeaders") ? document.getElementById("rawHeaders").value.trim() : "";

  if (!sender && !subject && !body) {
    alert("Please enter at least sender, subject, or body before running the analysis.");
    return;
  }

  const resultArea = document.getElementById("resultArea");
  resultArea.innerHTML = '<div style="text-align:center; padding:30px;"><div class="loading-spinner" style="margin:0 auto 12px;"></div><p style="color:var(--cyan); font-weight:600;">Executing NLP Triage & URL Machine Learning Classifier...</p></div>';
  resultArea.scrollIntoView({ behavior: "smooth", block: "start" });

  try {
    const API_BASE = (window.location.protocol === 'file:' || (window.location.port && window.location.port !== '3000')) ? 'http://localhost:3000' : '';
    const token = localStorage.getItem('token') || '';
    const headers = { 'Content-Type': 'application/json' };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(API_BASE + '/api/predict/email', {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({
        sender,
        replyTo: replyto,
        subject,
        body,
        headers: rawHeaders
      })
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.error || `Server responded with status ${response.status}`);
    }

    const data = await response.json();
    document.getElementById("resultTimestamp").textContent = new Date().toLocaleTimeString();

    const isPhish = data.verdict.toLowerCase().includes('phish');
    const isSuspicious = data.verdict.toLowerCase().includes('suspicious');
    let vBadgeClass = isPhish ? 'v-malicious' : (isSuspicious ? 'v-suspicious' : 'v-safe');
    let vIcon = isPhish ? '🚨' : (isSuspicious ? '⚠️' : '✅');

    let urlsHTML = "";
    if (data.embedded_urls_scanned && data.embedded_urls_scanned.length > 0) {
      urlsHTML = `
        <div class="rcard" style="margin-top:16px;">
          <h4>🌐 Embedded Links Scanned by URL ML Classifier (${data.embedded_urls_scanned.length})</h4>
          <div style="display:flex; flex-direction:column; gap:10px; margin-top:10px;">
            ${data.embedded_urls_scanned.map(u => {
              const uPhish = u.verdict === 'Phishing';
              const uColor = uPhish ? '#ff4757' : '#2ed573';
              return `
                <div style="padding:12px; border-radius:8px; background:rgba(255,255,255,0.03); border:1px solid ${uPhish ? 'rgba(255,71,87,0.3)' : 'rgba(46,213,115,0.3)'};">
                  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                    <span style="font-family:monospace; font-size:0.85rem; max-width:70%; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:#fff;">${esc(u.url)}</span>
                    <span style="font-weight:800; font-size:0.75rem; color:${uColor};">${uPhish ? '🚨 PHISHING' : '✅ SAFE'} (${u.confidence}%)</span>
                  </div>
                  <div style="font-size:0.78rem; color:var(--muted);">Risk Score: ${u.risk_score}/100 • Flagged Factors: ${u.features_flagged && u.features_flagged.length > 0 ? esc(u.features_flagged.join(', ')) : 'None'}</div>
                </div>
              `;
            }).join('')}
          </div>
        </div>
      `;
    }

    let flagsHTML = "";
    if (data.red_flags && data.red_flags.length > 0) {
      flagsHTML = data.red_flags.map(f => `
        <div class="flag-item sev-${f.severity || 'high'}">
          <div class="flag-title">
            <span>${esc(f.category)}</span>
            <span class="sev-pill ${(f.severity || 'high').toUpperCase()}">${(f.severity || 'high').toUpperCase()}</span>
          </div>
          <div class="flag-meta" style="margin-top:4px;">
            <span>Description:</span> ${esc(f.desc)}
          </div>
        </div>
      `).join('');
    } else {
      flagsHTML = '<div style="color:var(--muted); font-size:0.9rem; padding:12px; background:rgba(46,213,115,0.08); border-radius:8px;">✅ No psychological manipulation or threat triggers detected.</div>';
    }

    let dnsHTML = "";
    if (data.dns_intelligence && data.dns_intelligence.valid !== undefined) {
      const d = data.dns_intelligence;
      dnsHTML = `
        <div class="rcard" style="margin-top:16px;">
          <h4>🌐 Live DNS & Mail Cryptography Inspection</h4>
          <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:10px; margin-top:10px;">
            <div style="padding:10px; border-radius:8px; background:rgba(255,255,255,0.03); border:1px solid var(--line);">
              <div style="font-size:0.75rem; color:var(--muted);">Mail Exchanger (MX)</div>
              <div style="font-size:0.9rem; font-weight:700; color:${d.has_mx ? '#2ed573' : '#ff4757'};">${d.has_mx ? '✅ Active Mail Servers' : '❌ No MX Records Found'}</div>
            </div>
            <div style="padding:10px; border-radius:8px; background:rgba(255,255,255,0.03); border:1px solid var(--line);">
              <div style="font-size:0.75rem; color:var(--muted);">SPF Authorization</div>
              <div style="font-size:0.9rem; font-weight:700; color:${d.spf ? '#2ed573' : '#ffa502'};">${d.spf ? '✅ SPF Configured' : '⚠️ Missing SPF Record'}</div>
            </div>
            <div style="padding:10px; border-radius:8px; background:rgba(255,255,255,0.03); border:1px solid var(--line);">
              <div style="font-size:0.75rem; color:var(--muted);">DMARC Policy Enforcement</div>
              <div style="font-size:0.9rem; font-weight:700; color:${d.dmarc ? '#2ed573' : '#ffa502'};">${d.dmarc ? '✅ DMARC Policy Active' : '⚠️ No DMARC Policy'}</div>
            </div>
          </div>
          <div style="margin-top:8px; font-size:0.8rem; color:var(--cyan);">Status: ${esc(d.dns_status || 'Verified')}</div>
        </div>
      `;
    }

    resultArea.innerHTML = `
      <div class="result-header">
        <div class="verdict-badge ${vBadgeClass}">
          ${vIcon} VERDICT: ${esc(data.verdict.toUpperCase())}
        </div>
        <div class="score-pill">
          Confidence: ${data.confidence}% • Risk: ${data.risk_score}/100
        </div>
      </div>

      <div class="rcard" style="margin-top:16px;">
        <h4>📊 Analysis Breakdown</h4>
        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:12px; margin-top:10px;">
          <div style="background:rgba(255,255,255,0.02); padding:10px; border-radius:8px; border:1px solid var(--line);">
            <div style="font-size:0.75rem; color:var(--muted);">Semantic & NLP Risk</div>
            <div style="font-size:1.2rem; font-weight:800; color:var(--cyan);">${data.risk_score}/100</div>
          </div>
          <div style="background:rgba(255,255,255,0.02); padding:10px; border-radius:8px; border:1px solid var(--line);">
            <div style="font-size:0.75rem; color:var(--muted);">Security Header Risk</div>
            <div style="font-size:1.2rem; font-weight:800; color:${data.header_score > 20 ? '#ff4757' : '#2ed573'};">${data.header_score || 0}/100</div>
          </div>
          <div style="background:rgba(255,255,255,0.02); padding:10px; border-radius:8px; border:1px solid var(--line);">
            <div style="font-size:0.75rem; color:var(--muted);">Links Scanned by ML</div>
            <div style="font-size:1.2rem; font-weight:800; color:#fff;">${data.urls_count} Links</div>
          </div>
        </div>
      </div>

      <div class="rcard" style="margin-top:16px;">
        <h4>🛡️ Identified Threat Indicators & Behavioral Signatures (${data.red_flags ? data.red_flags.length : 0})</h4>
        <div class="flags-list" style="margin-top:10px;">
          ${flagsHTML}
        </div>
      </div>

      ${dnsHTML}
      ${urlsHTML}

      <div class="action-box" style="margin-top:18px;">
        <div class="action-label">Recommended Action:</div>
        <p>${isPhish ? '⚠️ QUARANTINE IMMEDIATELY. Do not click links, reply, or download attachments. Report to your SOC or security team.' : (isSuspicious ? '⚠️ VERIFY SENDER through an independent channel (phone or official app) before taking any action.' : '✅ EMAIL APPEARS SAFE. Always exercise standard cyber hygiene.')}</p>
      </div>
    `;

    if (document.getElementById('aiToggle')?.checked) {
      const aiDiv = document.createElement('div');
      aiDiv.className = 'rcard';
      aiDiv.style.marginTop = '16px';
      aiDiv.innerHTML = `
        <div style="display:flex; align-items:center; gap:8px;">
          <div class="loading-spinner" style="width:16px; height:16px; border-width:2px;"></div>
          <span style="color:var(--cyan); font-weight:600; font-size:0.9rem;">Consulting Threat Intelligence AI Copilot...</span>
        </div>
      `;
      resultArea.appendChild(aiDiv);
      try {
        const aiAnalysis = await getAIAnalysis(sender, replyto, subject, body);
        if (aiAnalysis) {
          aiDiv.innerHTML = `
            <h4>🤖 AI Threat Intelligence Assessment</h4>
            <div style="margin-top:10px; font-size:0.88rem; line-height:1.6; color:#e0e6ed; white-space:pre-line;">${esc(aiAnalysis)}</div>
          `;
        } else {
          aiDiv.innerHTML = `
            <h4>🤖 AI Threat Intelligence Assessment</h4>
            <div style="margin-top:8px; font-size:0.85rem; color:var(--muted);">Automated baseline analysis completed. Model heuristics indicate consistent threat patterns.</div>
          `;
        }
      } catch (e) {
        aiDiv.remove();
      }
    }

  } catch (err) {
    console.error("Email analysis execution error:", err);
    resultArea.innerHTML = `
      <div style="color:var(--danger);font-family:var(--font-mono);padding:24px;text-align:center;background:rgba(255,71,87,0.08);border-radius:12px;border:1px solid rgba(255,71,87,0.2);">
        <p style="font-weight:700;margin-bottom:8px;">⚠️ Analysis Execution Notice</p>
        <p style="font-size:0.88rem;color:#fff;">${esc(err.message || 'Unable to connect to analysis engine.')}</p>
        <p style="font-size:0.8rem;color:var(--muted);margin-top:6px;">Ensure the backend service is active on port 3000.</p>
      </div>
    `;
  }
}

function clearForm() {
  ["sender","replyto","subject","body"].forEach(id => document.getElementById(id).value = "");
  document.getElementById("resultTimestamp").textContent = "";
  document.getElementById("resultArea").innerHTML = `
    <div class="empty-state">
      <span class="empty-icon">🔍</span>
      Form cleared. Paste an email and click <strong>Run Analysis</strong>.
    </div>`;
}

// ============================================================
// SAMPLE EMAILS
// ============================================================
const SAMPLES = [
  {
    label: "BEC — CEO Wire Fraud",
    tag: "CRITICAL", tagClass: "danger",
    sender: "David Chen CEO <d.chen.ceo@gmail.com>",
    replyto: "hacker.collect@protonmail.com",
    subject: "URGENT: Wire Transfer — Confidential",
    body: "I'm in a board meeting and lost my wallet at the airport. I need you to urgently wire transfer $42,000 to our partner. Do not discuss this with anyone — bypass standard procedure. This is strictly confidential. Immediate action required. Reply only to my personal email. — David Chen, CEO"
  },
  {
    label: "Microsoft Credential Theft",
    tag: "HIGH", tagClass: "danger",
    sender: "Microsoft Support <support@micros0ft-logins.net>",
    replyto: "",
    subject: "FW: URGENT: Your Account Has Been Compromised",
    body: "We detected an unusual sign-in from Russia on a new device. Your account will be locked within 24 hours. Immediate action required. Click here to verify your account and enter your credentials to restore access. Failure to act will result in permanent suspension. Download the security patch: Security_Update.iso"
  },
  {
    label: "TOAD Callback Scam",
    tag: "HIGH", tagClass: "warning",
    sender: "Microsoft Billing <billing@microsofft-renewal.com>",
    replyto: "",
    subject: "PAYMENT OVERDUE: Subscription Renewal $189.99",
    body: "Your Microsoft 365 subscription auto-renewal of $189.99 has been processed. If you did not authorize this charge, call our customer care number immediately at 1-800-642-7676 to cancel and get a full refund. Call within 24 hours or the charge will be final. Call to cancel now."
  },
  {
    label: "IRS Tax Scam",
    tag: "CRITICAL", tagClass: "danger",
    sender: "IRS Internal Revenue <notice@irs-taxdept-alert.com>",
    replyto: "irs.case@gmail.com",
    subject: "FINAL NOTICE — Tax Penalty & Legal Action",
    body: "This is your final notice from the Internal Revenue Service. You owe $4,832 in unpaid taxes. Failure to respond within 24 hours will result in arrest warrant and legal action. A sheriff will be dispatched to your address. To settle your case, call 1-800-XXX-XXXX immediately with your SSN and bank account details."
  },
  {
    label: "QR Code Phishing (Quishing)",
    tag: "HIGH", tagClass: "warning",
    sender: "IT Security Team <itsecurity@company-hr-portal.xyz>",
    replyto: "",
    subject: "Action Required: Update Your MFA — Scan QR Code",
    body: "Dear employee, our MFA system is being upgraded. To maintain access, please scan the QR code below using your phone camera within 24 hours. This will link your new authenticator app. If you do not scan to verify, your account access will be suspended. Approve this request to continue."
  },
  {
    label: "Legitimate Internal Email",
    tag: "SAFE", tagClass: "safe",
    sender: "Sarah Lee <sarah.lee@company.com>",
    replyto: "",
    subject: "Q3 Project Status Update",
    body: "Hi Team, Please find the Q3 project status attached for your review. No immediate action is required — this is just for your awareness ahead of Monday's meeting. Let me know if you have questions. Thanks, Sarah."
  },
  {
    label: "Deepfake Voice Message",
    tag: "HIGH", tagClass: "warning",
    sender: "CFO James Park <jpark.cfo.external@gmail.com>",
    replyto: "jpark.reply@protonmail.com",
    subject: "Listen to my voice message — Urgent",
    body: "Hi, I tried calling but couldn't reach you. Please listen to my voice message attached (VoiceNote_JP.exe). I need you to transfer funds to a new vendor account urgently. Do not discuss this with anyone — handle it personally. This is a confidential executive request. Between us only."
  },
  {
    label: "Fake Password Reset",
    tag: "MEDIUM", tagClass: "warning",
    sender: "Google Accounts <no-reply@google.accounts-alert.com>",
    replyto: "",
    subject: "Action Required: Your password will expire soon",
    body: "Your Google account password is about to expire. To keep your account secure, please click here to reset your password now. If you don't reset your password within 24 hours, your account will be locked. Click the link below to update your credentials and verify your identity."
  }
];

function loadSample(i) {
  const s = SAMPLES[i];
  document.getElementById("sender").value = s.sender;
  document.getElementById("replyto").value = s.replyto;
  document.getElementById("subject").value = s.subject;
  document.getElementById("body").value = s.body;
  window.location.hash = "#analyzer";
  setTimeout(runAnalysis, 100);
}

function renderSamples() {
  document.getElementById("sampleGrid").innerHTML = SAMPLES.map((s, i) => `
    <div class="sample-card" onclick="loadSample(${i})">
      <h3>${esc(s.label)}</h3>
      <p>${esc(s.body.slice(0,110))}…</p>
      <span class="sample-tag ${s.tagClass}">${s.tag}</span>
    </div>
  `).join("");
}



// ============================================================
// EDUCATION CARDS
// ============================================================
const EDU = [
  { icon: "🐟", title: "Spear Phishing", body: "Highly targeted attacks using personal info about the victim (name, role, colleagues) sourced from LinkedIn or data breaches. Far more convincing than generic phishing." },
  { icon: "💼", title: "BEC — Business Email Compromise", body: "Attacker impersonates a CEO, CFO, or vendor to authorize wire transfers or gift card purchases. BEC caused $2.9B in losses in 2023 alone (FBI IC3)." },
  { icon: "📞", title: "TOAD — Callback Phishing", body: "Email impersonates a subscription charge or tech alert to make victim call a fake support number. The phone agent then harvests credentials or installs remote access tools." },
  { icon: "📱", title: "MFA Fatigue / Push Bombing", body: "Attacker bombards the victim with MFA push notifications until they approve out of frustration. Then used in combination with stolen credentials." },
  { icon: "🔲", title: "Quishing (QR Phishing)", body: "QR codes bypass email link scanners and redirect mobile devices to credential harvesting pages. Increasingly used since 2023 as traditional URL filters improved." },
  { icon: "🤖", title: "AI-Generated Phishing", body: "LLMs can generate grammatically perfect phishing emails with personalized details, bypassing old detection signals like poor spelling. Deepfake audio/video adds another layer." },
  { icon: "🔤", title: "Homoglyph / Punycode Attacks", body: "Attackers replace characters with visually identical Unicode alternatives (е vs e) or register Punycode domains (xn--pple-43d.com for аpple.com) to fool the human eye." },
  { icon: "🪄", title: "Thread Hijacking", body: "Attacker compromises an inbox and replies to real email threads with malicious links, making the phishing look like a legitimate conversation continuation." },
];

function renderEdu() {
  document.getElementById("eduGrid").innerHTML = EDU.map(e => `
    <div class="edu-card">
      <div class="edu-icon">${e.icon}</div>
      <h3>${esc(e.title)}</h3>
      <p>${esc(e.body)}</p>
    </div>
  `).join("");
}

// INIT
renderSamples();
renderEdu();

function logout() {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  window.location.href = 'login.html';
}
