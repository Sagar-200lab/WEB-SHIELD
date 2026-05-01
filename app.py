from flask import Flask, request, render_template_string, send_file, jsonify
from scanner import run_full_scan
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

import os
import threading
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.urandom(24)

limiter = Limiter(key_func=get_remote_address, app=app)

LAST_RESULTS = []
SCAN_STATUS = {"running": False, "progress": 0, "message": ""}


# ================= BACKGROUND SCAN =================
def background_scan(url):
    global LAST_RESULTS, SCAN_STATUS

    try:
        SCAN_STATUS.update({"running": True, "progress": 10, "message": "🌐 Crawling..."})
        results = run_full_scan(url, deep=True)

        SCAN_STATUS.update({"progress": 70, "message": "📊 Generating reports..."})

        LAST_RESULTS = results
        generate_chart(results)

        SCAN_STATUS.update({"progress": 100, "message": "✅ Scan Completed"})

    except Exception as e:
        SCAN_STATUS["message"] = str(e)

    SCAN_STATUS["running"] = False


# ================= UI =================
HTML = """
<!DOCTYPE html>
<html>
<head>
<title>WEB-SHIELD v2.0</title>

<link href="https://fonts.googleapis.com/css2?family=Orbitron&family=Share+Tech+Mono&display=swap" rel="stylesheet">

<style>
body {
    font-family: 'Share Tech Mono';
    background: black;
    color: #00ff88;
}

.container { max-width: 1200px; margin:auto; padding:20px; }

h1 {
    font-family: Orbitron;
    text-align:center;
    color:#00ff88;
}

input {
    width:100%;
    padding:15px;
    margin-top:10px;
    background:black;
    border:1px solid #00ff88;
    color:#00ff88;
}

button {
    width:100%;
    padding:15px;
    margin-top:10px;
    background:#00ff88;
    border:none;
    cursor:pointer;
}

/* 🔥 SPINNER UI */
.spinner-wrapper {
    display:flex;
    justify-content:center;
    margin-top:20px;
}

.spinner-circle {
    width:120px;
    height:120px;
    border-radius:50%;
    border:8px solid #222;
    border-top:8px solid #00ff88;
    display:flex;
    align-items:center;
    justify-content:center;
    animation: spin 1s linear infinite;
    position:relative;
}

.spinner-text {
    position:absolute;
    font-size:22px;
    font-weight:bold;
    color:#00ff88;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

/* 🔥 Progress text */
#progressStatus {
    text-align:center;
    margin-top:10px;
    font-size:16px;
}

/* Cards */
.vuln-card {
    background:#111;
    padding:20px;
    margin-top:20px;
    border-radius:10px;
}

/* Severity Colors */
.CRITICAL { color:red; font-weight:bold; }
.HIGH { color:orange; font-weight:bold; }
.MEDIUM { color:yellow; font-weight:bold; }
.LOW { color:lightgreen; font-weight:bold; }

.section-title {
    margin-top:10px;
    font-size:18px;
    color:#00d4ff;
}

.conf { color:#aaa; font-size:13px; }
</style>
</head>

<body>
<div class="container">

<h1>🛡 WEB-SHIELD</h1>

<form id="scanForm">
<input type="url" id="url" placeholder="https://example.com" required>
<button>Start Scan</button>
</form>

<!-- 🔥 PROGRESS UI -->
<div class="progress-container" id="progressContainer" style="display:none;">

    <div class="spinner-wrapper">
        <div class="spinner-circle">
            <div class="spinner-text" id="progressPercent">0%</div>
        </div>
    </div>

    <p id="progressStatus">Initializing...</p>

</div>

{% if results %}
<img src="/static/chart.png" width="100%">

{% for r in results %}
<div class="vuln-card">

<h3>🌐 {{ r.url }}</h3>

<div class="section-title">SQL Injection</div>
<p>{{ r.sql }} <span class="{{ r.sql_severity }}">[{{ r.sql_severity }}]</span>
<span class="conf">{{ r.sql_confidence }}%</span></p>

<div class="section-title">Cross-Site Scripting</div>
<p>{{ r.xss }} <span class="{{ r.xss_severity }}">[{{ r.xss_severity }}]</span>
<span class="conf">{{ r.xss_confidence }}%</span></p>

<div class="section-title">CSRF</div>
<p>{{ r.csrf }} <span class="{{ r.csrf_severity }}">[{{ r.csrf_severity }}]</span>
<span class="conf">{{ r.csrf_confidence }}%</span></p>

<div class="section-title">IDOR</div>
<p>{{ r.idor }} <span class="{{ r.idor_severity }}">[{{ r.idor_severity }}]</span>
<span class="conf">{{ r.idor_confidence }}%</span></p>

<div class="section-title">Misconfiguration</div>
<p>{{ r.misconfig }} <span class="{{ r.misconfig_severity }}">[{{ r.misconfig_severity }}]</span></p>

<div class="section-title">Outdated Components</div>
<p>{{ r.outdated }} <span class="{{ r.outdated_severity }}">[{{ r.outdated_severity }}]</span></p>

</div>
{% endfor %}

<a href="/report">📄 Download PDF Report</a>
{% endif %}

</div>

<script>
document.getElementById("scanForm").addEventListener("submit", async (e)=>{
e.preventDefault();

document.getElementById("progressContainer").style.display = "block";

await fetch("/scan", {
method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({url:document.getElementById("url").value})
});

let i=setInterval(async()=>{
let r=await fetch("/status");
let d=await r.json();

/* 🔥 UPDATE PERCENT TEXT */
document.getElementById("progressPercent").innerText = d.progress + "%";

/* 🔥 UPDATE STATUS MESSAGE */
document.getElementById("progressStatus").innerText = d.message;

if(d.progress>=100){
clearInterval(i);
location.reload();
}
},1000);
});
</script>

</body>
</html>
"""

# ================= ROUTES =================
@app.route("/")
def home():
    return render_template_string(HTML, results=LAST_RESULTS)


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data["url"]

    if SCAN_STATUS["running"]:
        return jsonify({"error": "Already running"})

    threading.Thread(target=background_scan, args=(url,), daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/status")
def status():
    return jsonify(SCAN_STATUS)


@app.route("/report")
def report():
    path = generate_pdf(LAST_RESULTS)
    return send_file(path, as_attachment=True)


# ================= CHART =================
def generate_chart(results):
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    count = {k: 0 for k in order}

    for r in results:
        for k in r:
            if "severity" in k and r[k] in count:
                count[r[k]] += 1

    colors = ["green", "yellow", "orange", "red"]

    plt.figure()
    plt.bar(order, [count[k] for k in order], color=colors)
    plt.savefig("static/chart.png")
    plt.close()


# ================= PDF =================
def generate_pdf(results):
    os.makedirs("reports", exist_ok=True)
    path = "reports/webshield_report.pdf"

    doc = SimpleDocTemplate(path)
    styles = getSampleStyleSheet()
    story = []

    # ===== TITLE =====
    story.append(Paragraph("🛡 WEB SHIELD VULNERABILITY REPORT", styles["Title"]))
    story.append(Spacer(1, 15))

    for r in results:
        story.append(Paragraph(f"<b>Target:</b> {r.get('url','N/A')}", styles["Heading2"]))
        story.append(Spacer(1, 10))

        # ================= SQLi =================
        story.append(Paragraph("<b>SQL Injection</b>", styles["Heading3"]))
        story.append(Paragraph(f"Finding: {r.get('sql')}", styles["Normal"]))
        story.append(Paragraph(f"Severity: {r.get('sql_severity')} | Confidence: {r.get('sql_confidence')}%", styles["Normal"]))
        story.append(Paragraph("Cause: Unsanitized user input is directly used in database queries.", styles["Normal"]))
        story.append(Paragraph("Fix: Use parameterized queries / prepared statements.", styles["Normal"]))
        story.append(Spacer(1, 8))

        # ================= XSS =================
        story.append(Paragraph("<b>Cross-Site Scripting (XSS)</b>", styles["Heading3"]))
        story.append(Paragraph(f"Finding: {r.get('xss')}", styles["Normal"]))
        story.append(Paragraph(f"Severity: {r.get('xss_severity')} | Confidence: {r.get('xss_confidence')}%", styles["Normal"]))
        story.append(Paragraph("Cause: User input is rendered without proper escaping.", styles["Normal"]))
        story.append(Paragraph("Fix: Encode output and apply Content Security Policy (CSP).", styles["Normal"]))
        story.append(Spacer(1, 8))

        # ================= CSRF =================
        story.append(Paragraph("<b>CSRF (Cross-Site Request Forgery)</b>", styles["Heading3"]))
        story.append(Paragraph(f"Finding: {r.get('csrf')}", styles["Normal"]))
        story.append(Paragraph(f"Severity: {r.get('csrf_severity')} | Confidence: {r.get('csrf_confidence')}%", styles["Normal"]))
        story.append(Paragraph("Cause: Missing CSRF tokens in sensitive requests.", styles["Normal"]))
        story.append(Paragraph("Fix: Implement CSRF tokens and SameSite cookies.", styles["Normal"]))
        story.append(Spacer(1, 8))

        # ================= IDOR =================
        story.append(Paragraph("<b>IDOR (Insecure Direct Object Reference)</b>", styles["Heading3"]))
        story.append(Paragraph(f"Finding: {r.get('idor')}", styles["Normal"]))
        story.append(Paragraph(f"Severity: {r.get('idor_severity')} | Confidence: {r.get('idor_confidence')}%", styles["Normal"]))
        story.append(Paragraph("Cause: Missing authorization checks when accessing objects.", styles["Normal"]))
        story.append(Paragraph("Fix: Enforce access control and validate user permissions.", styles["Normal"]))
        story.append(Spacer(1, 8))

        # ================= MISCONFIG =================
        story.append(Paragraph("<b>Security Misconfiguration</b>", styles["Heading3"]))
        story.append(Paragraph(f"Finding: {r.get('misconfig')}", styles["Normal"]))
        story.append(Paragraph(f"Severity: {r.get('misconfig_severity')} | Confidence: {r.get('misconfig_confidence')}%", styles["Normal"]))
        story.append(Paragraph("Cause: Missing security headers or exposed server info.", styles["Normal"]))
        story.append(Paragraph("Fix: Add headers like CSP, X-Frame-Options, and hide server details.", styles["Normal"]))
        story.append(Spacer(1, 8))

        # ================= OUTDATED =================
        story.append(Paragraph("<b>Outdated Components</b>", styles["Heading3"]))
        story.append(Paragraph(f"Finding: {r.get('outdated')}", styles["Normal"]))
        story.append(Paragraph(f"Severity: {r.get('outdated_severity')} | Confidence: {r.get('outdated_confidence')}%", styles["Normal"]))
        story.append(Paragraph("Cause: Use of outdated libraries with known vulnerabilities.", styles["Normal"]))
        story.append(Paragraph("Fix: Update dependencies regularly to latest secure versions.", styles["Normal"]))
        story.append(Spacer(1, 15))

    doc.build(story)
    return path

if __name__ == "__main__":
    os.makedirs("static", exist_ok=True)
    app.run(host="0.0.0.0", port=5000)