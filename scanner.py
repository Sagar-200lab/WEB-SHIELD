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

# 🔥 UNION-based payloads
SQL_UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT 1,2,3--",
]

# 🔥 Controlled fuzzing payloads
SQL_FUZZ_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 'a'='a",
    "' OR 1=1#",
]


def safe_get(url, params=None):
    for attempt in range(3):  # retry 3 times
        try:
            response = session.get(
                url,
                params=params,
                headers=HEADERS,
                timeout=20,
                allow_redirects=True
            )

            if response and response.status_code == 200:
                return response

        except Exception as e:
            print(f"[ERROR] Attempt {attempt+1} failed for {url}: {e}")
            time.sleep(1)

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
def smart_crawl(start_url, max_pages=15):
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

            # stay inside domain
            if urlparse(link).netloc == base:

                # 🔥 avoid useless links
                if any(x in link for x in ["logout", "#", "javascript"]):
                    continue

                if link not in visited:
                    queue.append(link)

    return list(set(results))


# ================= SQLi =================
def test_sqli(url):
    base = normalize(url)
    params = get_params(url)

    if not params:
        return ("Clean", 30)

    score_total = 0
    signals = []

    for p in params:

        # ---------- BOOLEAN ----------
        params_true = params.copy()
        params_false = params.copy()

        params_true[p] = [SQL_TRUE]
        params_false[p] = [SQL_FALSE]

        r1 = safe_get(base, params_true)
        r2 = safe_get(base, params_false)

        if r1 and r2:
            len_diff = abs(len(r1.text) - len(r2.text))
            sim = difflib.SequenceMatcher(None, r1.text, r2.text).ratio()

            if len_diff > 80:
                score_total += 2
                signals.append("LengthDiff")

            if sim < 0.85:
                score_total += 3
                signals.append("BooleanDiff")

        # ---------- ERROR ----------
        params_err = params.copy()
        params_err[p] = [SQL_ERROR]

        r3 = safe_get(base, params_err)
        if r3 and any(e in r3.text.lower() for e in SQL_ERRORS):
            score_total += 4
            signals.append("SQLError")

        # ---------- TIME ----------
        params_time = params.copy()
        params_time[p] = [SQL_TIME]

        start = time.time()
        safe_get(base, params_time)
        delay = time.time() - start

        if 2.5 < delay < 10:
            score_total += 5
            signals.append("TimeDelay")

        # ---------- UNION ----------
        for payload in SQL_UNION_PAYLOADS:
            params_union = params.copy()
            params_union[p] = [payload]

            r_union = safe_get(base, params_union)
            if not r_union:
                continue

            if r1 and any(e in r_union.text.lower() for e in SQL_ERRORS):
                score_total += 4
                signals.append("UnionError")

            elif r1 and abs(len(r_union.text) - len(r1.text)) > 100:
                score_total += 2
                signals.append("UnionDiff")

        # ---------- FUZZ ----------
        for payload in SQL_FUZZ_PAYLOADS:
            params_fuzz = params.copy()
            params_fuzz[p] = [payload]

            r_fuzz = safe_get(base, params_fuzz)
            if not r_fuzz:
                continue

            if any(e in r_fuzz.text.lower() for e in SQL_ERRORS):
                score_total += 3
                signals.append("FuzzError")

    # ---------- CONFIDENCE ----------
    confidence = min(100, score_total * 10)

    # ---------- FINAL LABEL ----------
    if score_total >= 8:
        label = "CONFIRMED SQLi"
    elif score_total >= 4:
        label = "LIKELY SQLi"
    elif score_total >= 2:
        label = "POSSIBLE SQLi"
    else:
        label = "Clean"

    return (f"{label} ({', '.join(signals)})", confidence)
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

    print("[*] Starting scan...")

    urls = [target_url]

    if deep:
        print("[*] Crawling target...")
        urls = smart_crawl(target_url, max_pages=15)

    urls = sorted(urls, key=lambda u: "?" in u, reverse=True)

    results = []

    for i, u in enumerate(urls):
        print(f"[+] Scanning ({i+1}/{len(urls)}): {u}")

        # ================= SQLi =================
        try:
            sql_result = test_sqli(u)
            sql, sql_conf = sql_result if isinstance(sql_result, tuple) else (sql_result, 30)
        except:
            sql, sql_conf = "Error", 0

        # ================= XSS =================
        try:
            xss_result = test_xss(u)
            xss = xss_result
            xss_conf = 70 if "CONFIRMED" in xss else 30 if "Clean" in xss else 50
        except:
            xss, xss_conf = "Error", 0

        # ================= CSRF =================
        try:
            csrf_result = test_csrf(u)
            csrf = csrf_result
            csrf_conf = 70 if "POSSIBLE" in csrf else 40
        except:
            csrf, csrf_conf = "Error", 0

        # ================= IDOR =================
        try:
            idor_result = test_idor(u)
            idor = idor_result
            idor_conf = 75 if "POSSIBLE" in idor else 30
        except:
            idor, idor_conf = "Error", 0

        # ================= MISCONFIG =================
        try:
            mis = test_misconfig(u)
            mis_conf = 70 if "missing" in mis.lower() else 30
        except:
            mis, mis_conf = "Error", 0

        # ================= OUTDATED =================
        try:
            out = test_outdated(u)
            out_conf = 80 if "outdated" in out.lower() else 30
        except:
            out, out_conf = "Error", 0

        # ================= STORE =================
        results.append({
            "url": u,

            "sql": sql,
            "sql_severity": score(sql)[0] if isinstance(sql, str) else "LOW",
            "sql_confidence": sql_conf,

            "xss": xss,
            "xss_severity": score(xss)[0] if isinstance(xss, str) else "LOW",
            "xss_confidence": xss_conf,

            "csrf": csrf,
            "csrf_severity": score(csrf)[0] if isinstance(csrf, str) else "LOW",
            "csrf_confidence": csrf_conf,

            "idor": idor,
            "idor_severity": score(idor)[0] if isinstance(idor, str) else "LOW",
            "idor_confidence": idor_conf,

            "misconfig": mis,
            "misconfig_severity": score(mis)[0] if isinstance(mis, str) else "LOW",
            "misconfig_confidence": mis_conf,

            "outdated": out,
            "outdated_severity": score(out)[0] if isinstance(out, str) else "LOW",
            "outdated_confidence": out_conf,
        })

    print("[*] Scan completed.")
    return results
