# 🔐 Enterprise Vulnerability Scanner

A web-based vulnerability scanner built using Python and Flask.  
This tool detects common web vulnerabilities such as SQL Injection, XSS, CSRF, IDOR, misconfiguration, and outdated components.

---

## 🚀 Features

- SQL Injection Detection (Boolean + Time-based)
- Cross-Site Scripting (XSS)
- CSRF Analysis
- IDOR Detection
- Security Misconfiguration Checks
- Outdated Component Detection
- Severity & Confidence Scoring
- Chart Dashboard
- PDF Report Generation

---
## 📄 PDF Report Feature

The scanner generates a detailed PDF vulnerability report after each scan.

### Steps:
1. Run the app
2. Perform a scan
3. Click "Download PDF Report"

### Sample Output
The report includes:
- Vulnerability details
- Severity levels
- Causes
- Suggested fixes

## 🛠️ Tech Stack

- Python
- Flask
- Requests
- BeautifulSoup
- Matplotlib
- ReportLab

---

## ▶️ How to Run

1. Clone the repository:
   git clone <your-repo-link>

2. Navigate into project:
   cd vulnerability-scanner

3. Install dependencies:
   pip install -r requirements…