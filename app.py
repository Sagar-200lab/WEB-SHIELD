from flask import Flask, request, render_template_string, send_file
from scanner import run_full_scan
import matplotlib.pyplot as plt
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import os

app = Flask(__name__)

LAST_RESULTS = []

# ================= UI =================
HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Enterprise Vulnerability Scanner</title>
<style>
body { font-family: Arial; background:#0f172a; color:white; text-align:center; }
input { width:60%; padding:10px; }
button { padding:10px 20px; background:green; color:white; }
.box { background:#1e293b; margin:20px; padding:20px; }
</style>
</head>

<body>

{% macro color_severity(level) %}
    {% if level == "CRITICAL" %}
        <span style="color:#ef4444;font-weight:bold;">{{ level }}</span>
    {% elif level == "HIGH" %}
        <span style="color:#f97316;font-weight:bold;">{{ level }}</span>
    {% elif level == "MEDIUM" %}
        <span style="color:#eab308;font-weight:bold;">{{ level }}</span>
    {% else %}
        <span style="color:#22c55e;font-weight:bold;">{{ level }}</span>
    {% endif %}
{% endmacro %}

<h2>🔐 Vulnerability Scanner</h2>

<form method="post">
<input name="url" placeholder="Enter URL" required>
<button>Scan</button>
</form>
{% if error %}
<p style="color:red;">{{ error }}</p>
{% endif %}
{% if results %}
<div class="box">
<h3>Scan Results</h3>

{% for r in results %}
<p><b>{{ r.url }}</b></p>

<p><b>SQL Injection:</b> {{ r.sql }} | {{ color_severity(r.sql_severity) }} ({{ r.sql_confidence }}%)</p>
<p style="color:#94a3b8;font-size:13px;">
Cause: Unsanitized user input in SQL queries<br>
Fix: Use prepared statements / parameterized queries
</p>

<p><b>XSS:</b> {{ r.xss }} | {{ color_severity(r.xss_severity) }}</p>
<p style="color:#94a3b8;font-size:13px;">
Cause: Output not escaped<br>
Fix: Encode output before rendering
</p>

<p><b>CSRF:</b> {{ r.csrf }} | {{ color_severity(r.csrf_severity) }}</p>
<p style="color:#94a3b8;font-size:13px;">
Cause: Missing CSRF tokens<br>
Fix: Implement CSRF tokens and SameSite cookies
</p>

<p><b>IDOR:</b> {{ r.idor }} | {{ color_severity(r.idor_severity) }}</p>
<p style="color:#94a3b8;font-size:13px;">
Cause: Direct object access without authorization<br>
Fix: Enforce proper access control checks
</p>

<p><b>Misconfiguration:</b> {{ r.misconfig }} | {{ color_severity(r.misconfig_severity) }}</p>
<p style="color:#94a3b8;font-size:13px;">
Cause: Missing security headers<br>
Fix: Add CSP, X-Frame-Options, secure headers
</p>

<p><b>Outdated Components:</b> {{ r.outdated }} | {{ color_severity(r.outdated_severity) }}</p>
<p style="color:#94a3b8;font-size:13px;">
Cause: Old vulnerable libraries<br>
Fix: Update dependencies regularly
</p>

<hr>
{% endfor %}

<a href="/report">Download PDF Report</a>
<br><br>
<img src="/static/chart.png">

</div>
{% endif %}

</body>
</html>
"""


# ================= ROUTE =================
@app.route("/", methods=["GET", "POST"])
def home():
    global LAST_RESULTS

    results = None
    error = None

    if request.method == "POST":

        # safer input handling
        url = request.form.get("url", "").strip()

        if not url:
            error = "Please enter a valid URL"
            return render_template_string(HTML, results=None, error=error)

        # normalize URL
        if not url.startswith("http"):
            url = "http://" + url

        try:
            results = run_full_scan(url)
            LAST_RESULTS = results

            generate_chart(results)

        except Exception as e:
            error = f"Scan failed: {str(e)}"
            return render_template_string(HTML, results=None, error=error)

    return render_template_string(HTML, results=results, error=error)

# ================= CHART =================
def generate_chart(results):
    data = {"LOW":0,"MEDIUM":0,"HIGH":0,"CRITICAL":0}

    for r in results:
        for k in r:
            if "severity" in k:
                if r[k] in data:
                    data[r[k]] += 1
    plt.clf()
    plt.bar(data.keys(), data.values())
    os.makedirs("static", exist_ok=True)
    plt.savefig("static/chart.png")
    plt.close()


# ================= PDF =================
def generate_pdf(results):

    print("Generating professional PDF report...")

    file_path = os.path.abspath("report.pdf")
    doc = SimpleDocTemplate(file_path)

    styles = getSampleStyleSheet()
    content = []

    # ================= TITLE =================
    content.append(Paragraph("ENTERPRISE VULNERABILITY ASSESSMENT REPORT", styles["Title"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("This report contains automated security analysis results including confirmed and potential vulnerabilities.", styles["Normal"]))
    content.append(Spacer(1, 20))

    # ================= EACH TARGET =================
    for r in results:

        content.append(Paragraph(f"TARGET URL: {r['url']}", styles["Heading2"]))
        content.append(Spacer(1, 10))

        # ================= SQL =================
        content.append(Paragraph("1. SQL INJECTION", styles["Heading3"]))
        content.append(Paragraph(f"Status: {r['sql']} ({r['sql_severity']} - {r['sql_confidence']}%)", styles["Normal"]))

        sql_cause = "Unsanitized user input in database query execution."
        sql_fix = "Use parameterized queries / prepared statements."

        if "CONFIRMED" in r['sql']:
            sql_cause = "Confirmed SQL injection due to behavioral difference in query response or time delay."
        else:
            sql_cause = "Possible SQL injection due to inconsistent response patterns."

        content.append(Paragraph(f"Cause: {sql_cause}", styles["Normal"]))
        content.append(Paragraph(f"Recommendation: {sql_fix}", styles["Normal"]))
        content.append(Spacer(1, 10))

        # ================= XSS =================
        content.append(Paragraph("2. CROSS SITE SCRIPTING (XSS)", styles["Heading3"]))
        content.append(Paragraph(f"Status: {r['xss']} ({r['xss_severity']})", styles["Normal"]))

        content.append(Paragraph("Cause: Improper output encoding allows script execution in browser.", styles["Normal"]))
        content.append(Paragraph("Fix: Sanitize and encode output (HTML escaping, CSP headers).", styles["Normal"]))
        content.append(Spacer(1, 10))

        # ================= CSRF =================
        content.append(Paragraph("3. CSRF VULNERABILITY", styles["Heading3"]))
        content.append(Paragraph(f"Status: {r['csrf']} ({r['csrf_severity']})", styles["Normal"]))

        if "POSSIBLE" in r['csrf']:
            csrf_cause = "No CSRF token detected in form submission. This is a potential risk."
        else:
            csrf_cause = "CSRF protection mechanism detected (token-based or session-based)."

        content.append(Paragraph(f"Cause: {csrf_cause}", styles["Normal"]))
        content.append(Paragraph("Fix: Implement CSRF tokens and SameSite cookies.", styles["Normal"]))
        content.append(Spacer(1, 10))

        # ================= IDOR =================
        content.append(Paragraph("4. IDOR (INSECURE DIRECT OBJECT REFERENCE)", styles["Heading3"]))
        content.append(Paragraph(f"Status: {r['idor']} ({r['idor_severity']})", styles["Normal"]))

        content.append(Paragraph("Cause: Direct access to internal objects without authorization checks.", styles["Normal"]))
        content.append(Paragraph("Fix: Enforce access control validation on server-side objects.", styles["Normal"]))
        content.append(Spacer(1, 10))

        # ================= MISCONFIG =================
        content.append(Paragraph("5. SECURITY MISCONFIGURATION", styles["Heading3"]))
        content.append(Paragraph(f"Status: {r['misconfig']}", styles["Normal"]))

        if "Error" in r['misconfig']:
            mis_cause = "Unable to fetch headers or response incomplete. This may indicate server restriction or request failure."
        else:
            mis_cause = "Missing security headers such as CSP, X-Frame-Options, or exposed server version."

        content.append(Paragraph(f"Cause: {mis_cause}", styles["Normal"]))
        content.append(Paragraph("Fix: Configure security headers (CSP, HSTS, X-Frame-Options).", styles["Normal"]))
        content.append(Spacer(1, 10))

        # ================= OUTDATED =================
        content.append(Paragraph("6. OUTDATED COMPONENTS", styles["Heading3"]))
        content.append(Paragraph(f"Status: {r['outdated']}", styles["Normal"]))

        if "Error" in r['outdated']:
            out_cause = "Version detection failed due to limited visibility."
        else:
            out_cause = "Old or vulnerable libraries detected in response content."

        content.append(Paragraph(f"Cause: {out_cause}", styles["Normal"]))
        content.append(Paragraph("Fix: Regularly update frameworks, libraries, and dependencies.", styles["Normal"]))

        content.append(Spacer(1, 20))

    # ================= BUILD PDF =================
    doc.build(content)

    print("PROFESSIONAL PDF GENERATED SUCCESSFULLY")
@app.route("/report")
def report():
    global LAST_RESULTS

    if not LAST_RESULTS:
        return "No scan results available. Run a scan first."

    try:
        generate_pdf(LAST_RESULTS)

        file_path = os.path.abspath("report.pdf")

        if not os.path.exists(file_path):
            return "PDF generation failed (file not created). Check console."

        return send_file(file_path, as_attachment=True)

    except Exception as e:
        return f"PDF Error: {str(e)}"
if __name__ == "__main__":
    app.run(debug=True)