import re
import math
import idna
import requests
from urllib.parse import urlparse
from flask import Flask, request, jsonify

app = Flask(__name__)

# ------------------------------
# 0) Sender Risk
# ------------------------------

def sender_risk(sender: str):
    reasons = []
    verdict = "legitimate"

    if not re.match(r"^[a-zA-Z0-9@._-]+$", sender):
        reasons.append("invalid_chars")

    domain = sender.split("@")[-1].lower() if "@" in sender else sender.lower()

    if domain.startswith("xn--"):
        reasons.append("punycode_idn")

    tld = domain.split(".")[-1]
    if tld in RISKY_TLDS:
        reasons.append(f"risky_tld:{tld}")

    brands = brand_impersonation(domain)
    if brands:
        for b in brands:
            reasons.append(f"brand_impersonation:{b}")

    if reasons:
        verdict = "phishing"

    return {"sender": sender, "status": verdict, "reasons": reasons}



# -----------------------------
# 1) URL matching (liberal, fast)
# -----------------------------
URL_REGEX = re.compile(
    r'(?:(?:https?|ftp)://)?'              # optional scheme
    r'(?:\S+(?::\S*)?@)?'                  # optional user:pass@
    r'(?:'                                 # host: domain or IPv4
    r'(?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})' # domain.tld
    r'|'                                   # or IPv4
    r'(?:'                                 # strict-ish IPv4
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
    r'(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}'
    r')'
    r')'
    r'(?::\d{2,5})?'                       # optional port
    r'(?:/[^\s]*)?',                       # optional path
    re.IGNORECASE
)

# -----------------------------
# 2) Heuristic configuration
# -----------------------------
SUSPICIOUS_KEYWORDS = re.compile(
    r"(paypal|bank|secure|login|update|verify|account|signin|webscr|wallet|credentials|password|invoice|billing|unlock)",
    re.IGNORECASE
)

BRANDS = [
    "paypal", "microsoft", "amazon", "apple", "google", "outlook", "office", "netflix",
    "bankofamerica", "hsbc", "barclays", "chase", "facebook", "instagram", "tiktok"
]

# TLDs frequently abused (tune to your telemetry)
RISKY_TLDS = set(["xyz", "top", "click", "link", "work", "gq", "tk", "ml", "cf"])
# Paths often used in credential-harvesting kits
SUSPICIOUS_PATH_FRAGMENTS = re.compile(
    r"(login|signin|webscr|secure|verify|update|account|auth|customer|billing|confirm|reset)",
    re.IGNORECASE
)

# Homoglyph/punycode detection
def is_punycode(label: str) -> bool:
    return label.lower().startswith("xn--")

def contains_homoglyph(domain: str) -> bool:
    try:
        # If domain can be encoded/decoded with IDNA and includes punycode labels → suspicious
        labels = domain.split(".")
        return any(is_punycode(l) for l in labels)
    except Exception:
        return False

# Entropy (Shannon) to detect random-looking hostnames
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    length = len(s)
    return -sum((f/length) * math.log2(f/length) for f in freq.values())

# Basic brand impersonation check (substring and simple edits)
def brand_impersonation(domain: str) -> list:
    d = domain.lower()
    hits = []
    for b in BRANDS:
        if b in d:
            hits.append(b)
    return hits

# Extract domain safely
def extract_domain(url: str) -> str:
    # Ensure scheme for urlparse
    if not re.match(r'^[a-zA-Z]+://', url):
        url = "http://" + url
    parsed = urlparse(url)
    host = parsed.netloc.split("@")[-1]  # strip userinfo if present
    return host.lower()

def extract_tld(domain: str) -> str:
    parts = domain.split(".")
    return parts[-1] if len(parts) > 1 else ""

def is_ipv4(domain: str) -> bool:
    return re.match(
        r'^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$', domain
    ) is not None

# -----------------------------
# 3) Google Safe Browsing
# -----------------------------
API_KEY = "AIzaSyC1fjjIFA5qNRozgEAFCng3kUkOrfyiLI0"  # put your key here
SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

def check_safe_browsing(url: str):
    body = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        res = requests.post(SAFE_BROWSING_URL, json=body, timeout=6)
        js = res.json()
        if "matches" in js:
            return {"safe_browsing": "phishing", "detail": js["matches"]}
        return {"safe_browsing": "legitimate"}
    except Exception as e:
        return {"safe_browsing": "error", "message": str(e)}

# -----------------------------
# 4) Multi-layer decision engine
# -----------------------------
def analyze_url(url: str):
    reasons = []
    verdict = "legitimate"

    # Layer A: Regex presence (validation)
    if not URL_REGEX.match(url):
        return {"url": url, "status": "error", "reasons": ["invalid_url_pattern"]}

    # Normalize domain
    domain = extract_domain(url)
    tld = extract_tld(domain)

    # Layer B: Immediate red flags
    if SUSPICIOUS_KEYWORDS.search(url):
        reasons.append("keyword_match")
    if SUSPICIOUS_PATH_FRAGMENTS.search(url):
        reasons.append("path_fragment_match")
    if contains_homoglyph(domain):
        reasons.append("punycode_homoglyph")
    if tld in RISKY_TLDS:
        reasons.append(f"risky_tld:{tld}")
    if is_ipv4(domain):
        reasons.append("ip_host")
    # Entropy & length for domain label without dots
    core = domain.replace(".", "")
    if shannon_entropy(core) >= 3.5 and len(core) >= 18:
        reasons.append("high_entropy_long_domain")

    # Brand impersonation
    brands = brand_impersonation(domain)
    if brands:
        for b in brands:
            reasons.append(f"brand_impersonation:{b}")

    # If any heuristic fired, tentatively flag as phishing
    if reasons:
        verdict = "phishing"

    # Layer C: Safe Browsing check (authoritative)
    sb = check_safe_browsing(url)
    if sb["safe_browsing"] == "phishing":
        verdict = "phishing"
        reasons.append("safe_browsing_hit")
    elif sb["safe_browsing"] == "error":
        reasons.append("safe_browsing_error")

    result = {"url": url, "status": verdict, "reasons": reasons}
    if "detail" in sb:
        result["detail"] = sb["detail"]
    return result

# -----------------------------
# 5) Flask endpoints
# -----------------------------
@app.route("/check_link", methods=["POST"])
def check_link():
    data = request.json or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(analyze_url(url))

# Your existing ML prediction endpoint (body content)
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

MODEL_PATH = "final_model"  # adjust to your actual location relative to app.py
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)

@app.route("/predict_full", methods=["POST"])
def predict_full():
    data = request.json or {}
    sender = data.get("sender", "").strip()
    subject = data.get("subject", "").strip()
    body = data.get("body", "").strip()
    links = data.get("links", [])




    if not body and not sender and not subject:
        return jsonify({"error": "No email content provided"}), 400

    # --- ML tahmini (body + subject + sender birlikte) ---
    text = f"{sender} {subject} {body}"
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True)
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=1)
        label_id = int(torch.argmax(probs).item())
        confidence = float(probs[0][label_id].item())

    # Mapping (kontrol et: senin eğitiminde 0=phishing, 1=legitimate olabilir)
    label = "phishing" if label_id == 0 else "legitimate"

    # --- Sender analizi ---
    sender_result = sender_risk(sender)

    # --- URL analizi ---
    url_results = [analyze_url(url) for url in links]

    return jsonify({
        "label": label,
        "confidence": confidence,
        "sender_analysis": sender_result,
        "url_analysis": url_results
    })

if __name__ == "__main__":
    app.run(port=5000, debug=True)
