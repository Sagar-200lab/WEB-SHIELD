import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urljoin
import difflib
import time
import re

TIMEOUT = 6
HEADERS = {"User-Agent": "Mozilla/5.0"}
session = requests.Session()

SQL_TRUE = "' OR 1=1 --"
SQL_FALSE = "' AND 1=2 --"
SQL_ERROR = "'"
SQL_TIME = "' OR SLEEP(2) --"

SQL_ERRORS = ["sql", "mysql", "syntax error", "warning", "database"]

XSS_PAYLOAD = "<script>alert(1)</script>"


def safe_get(url, params=None):
    try:
        response = session.get(
            url,
            params=params,
            headers=HEADERS,
            timeout=10,
            allow_redirects=True
        )

        # Only accept valid responses
        if response and response.status_code == 200:
            return response

        print(f"[WARN] Status {response.status_code} for {url}")
        return None

    except Exception as e:
        print(f"[ERROR] Request failed for {url}: {e}")
        return None


# ================= HELPERS =================
def normalize(url):
    return url.split("?")[0]


def get_params(url):
    return parse_qs(urlparse(url).query)


# ================= FORMS =================
def extract_forms(url):
    r = safe_get(url)
    if not r:
        return []

    soup = BeautifulSoup(r.text, "html.parser")
    forms = []

    for f in soup.find_all("form"):
        action = urljoin(url, f.get("action") or url)
        method = f.get("method", "get").lower()

        inputs = {}
        for i in f.find_all("input"):
            if i.get("name"):
                inputs[i["name"]] = "test"

        forms.append({
            "action": action,
            "method": method,
            "inputs": inputs
        })

    return forms


# ================= CRAWLER =================
def smart_crawl(start_url, max_pages=8):
    visited = set()
    queue = [start_url]
    results = []

    base = urlparse(start_url).netloc

    while queue and len(visited) < max_pages:
        url = queue.pop(0)

        if url in visited:
            continue

        visited.add(url)
        results.append(url)

        r = safe_get(url)
        if not r:
            continue

        soup = BeautifulSoup(r.text, "html.parser")

        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"])
            if urlparse(link).netloc == base:
                queue.append(link)

    return results


# ================= SQLi =================
def test_sqli(url):
    base = normalize(url)
    params = get_params(url)
    forms = extract_forms(url)

    for p in params:

        r1 = safe_get(base, {p: SQL_TRUE})
        r2 = safe_get(base, {p: SQL_FALSE})

        if r1 and r2:
            sim = difflib.SequenceMatcher(None, r1.text, r2.text).ratio()
            if sim < 0.7:
                return "CONFIRMED SQLi (Boolean)"

        r3 = safe_get(base, {p: SQL_ERROR})
        if r3 and any(e in r3.text.lower() for e in SQL_ERRORS):
            return "LIKELY SQLi (Error)"

        start = time.time()
        
        safe_get(base, {p: SQL_TIME})
        delay = time.time() - start
        if delay > 2.5 and delay < 10:
         return "CONFIRMED SQLi (Time)"

    for f in forms:
        for k in f["inputs"]:

            d1 = f["inputs"].copy()
            d2 = f["inputs"].copy()

            d1[k] = SQL_TRUE
            d2[k] = SQL_FALSE

            if f["method"] == "post":
                r1 = session.post(f["action"], data=d1)
                r2 = session.post(f["action"], data=d2)
            else:
                r1 = session.get(f["action"], params=d1)
                r2 = session.get(f["action"], params=d2)

            if r1 and r2:
                sim = difflib.SequenceMatcher(None, r1.text, r2.text).ratio()
                if sim < 0.7:
                    return "CONFIRMED SQLi (Form)"

    return "Clean"


# ================= XSS =================
def test_xss(url):
    forms = extract_forms(url)

    for f in forms:
        data = f["inputs"].copy()

        for k in data:
            data[k] = XSS_PAYLOAD

        if f["method"] == "post":
            r = session.post(f["action"], data=data)
        else:
            r = session.get(f["action"], params=data)

        if r and XSS_PAYLOAD in r.text:
            return "CONFIRMED XSS"

    return "Clean"


# ================= CSRF =================
def test_csrf(url):
    forms = extract_forms(url)

    for f in forms:
        r = safe_get(f["action"])
        if not r:
            continue

        soup = BeautifulSoup(r.text, "html.parser")
        tokens = soup.find_all("input", {"name": lambda x: x and "csrf" in x.lower()})

        if not tokens:
            return "POSSIBLE CSRF"

    return "Protected"


# ================= IDOR =================
def test_idor(url):
    ids = re.findall(r"/(\d+)", url)

    if not ids:
        return "Skipped"

    for i in ids:
        u1 = safe_get(url)
        u2 = safe_get(url.replace(f"/{i}", f"/{int(i)+1}"))

        if u1 and u2:
            sim = difflib.SequenceMatcher(None, u1.text, u2.text).ratio()
            if sim < 0.75:
                return "POSSIBLE IDOR"

    return "Clean"


# ================= MISCONFIG =================
def test_misconfig(url):
    try:
        r = safe_get(url)

        if not r:
            r = safe_get(normalize(url))

        if not r or not r.text or len(r.text) < 50:
         return "Error: No response"

        headers = r.headers
        issues = []

        if "X-Frame-Options" not in headers:
            issues.append("X-Frame-Options missing")

        if "Content-Security-Policy" not in headers:
            issues.append("CSP missing")

        if "Server" in headers:
            issues.append("Server exposed")

        return " | ".join(issues) if issues else "Secure"

    except Exception as e:
        return f"Error: {str(e)}"
# ================= OUTDATED =================
def test_outdated(url):
    try:
        r = safe_get(url)

        if not r:
            r = safe_get(normalize(url))

        if not r or not r.text or len(r.text) < 50:
         return "Error: No response"

        text = r.text.lower()

        if "jquery-1." in text:
            return "Outdated jQuery detected"

        return "Clean"

    except Exception as e:
        return f"Error: {str(e)}"
# ================= SCORING =================
def score(v):
    v = v.lower()

    if "confirmed" in v:
        return "CRITICAL", 90
    elif "likely" in v:
        return "HIGH", 70
    elif "possible" in v:
        return "MEDIUM", 50
    elif "missing" in v or "exposed" in v:
        return "MEDIUM", 60
    else:
        return "LOW", 30

# ================= MAIN =================
def run_full_scan(target_url, deep=False):

    urls = [target_url]

    if deep:
        urls = smart_crawl(target_url)

    results = []

    for u in urls:

        sql = test_sqli(u)
        xss = test_xss(u)
        csrf = test_csrf(u)
        idor = test_idor(u)
        mis = test_misconfig(u)
        out = test_outdated(u)

        results.append({
            "url": u,

            "sql": sql,
            "sql_severity": score(sql)[0],
            "sql_confidence": score(sql)[1],

            "xss": xss,
            "xss_severity": score(xss)[0],
            "xss_confidence": score(xss)[1],

            "csrf": csrf,
            "csrf_severity": score(csrf)[0],
            "csrf_confidence": score(csrf)[1],

            "idor": idor,
            "idor_severity": score(idor)[0],
            "idor_confidence": score(idor)[1],

            "misconfig": mis,
            "misconfig_severity": score(mis)[0],
            "misconfig_confidence": score(mis)[1],

            "outdated": out,
            "outdated_severity": score(out)[0],
            "outdated_confidence": score(out)[1],
        })

    return results