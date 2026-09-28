import re
import json
from urllib.parse import urlparse

PHISHING_KEYWORDS = [
    "verify", "update", "password", "urgent", "immediately",
    "suspended", "click", "login", "confirm", "security alert",
    "account locked", "reset"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".click", ".info", ".ru", ".cn"
]

def extract_urls(text):
    url_pattern = r'(https?://[^\s]+)'
    return re.findall(url_pattern, text)

def analyze_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    score = 0
    reasons = []

    if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
        score += 30
        reasons.append("URL uses raw IP address")

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 25
            reasons.append(f"Suspicious TLD detected: {tld}")

    if len(url) > 80:
        score += 10
        reasons.append("URL length unusually long")

    return score, reasons

def analyze_text(text):
    score = 0
    reasons = []

    for keyword in PHISHING_KEYWORDS:
        if keyword in text.lower():
            score += 5
            reasons.append(f"Keyword detected: {keyword}")

    return score, reasons

def analyze_sender(sender):
    score = 0
    reasons = []

    suspicious_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]

    if any(sender.endswith(d) for d in suspicious_domains):
        score += 10
        reasons.append("Sender uses free email provider")

    if "@" not in sender:
        score += 20
        reasons.append("Sender address malformed")

    return score, reasons

def analyze_email(email_text):
    urls = extract_urls(email_text)

    total_score = 0
    details = {
        "urls": [],
        "sender": "",
        "subject": "",
        "score_breakdown": []
    }

    sender_match = re.search(r"From:\s*(.*)", email_text)
    if sender_match:
        sender = sender_match.group(1).strip()
        details["sender"] = sender
        s_score, s_reasons = analyze_sender(sender)
        total_score += s_score
        details["score_breakdown"].extend(s_reasons)

    subject_match = re.search(r"Subject:\s*(.*)", email_text)
    if subject_match:
        subject = subject_match.group(1).strip()
        details["subject"] = subject
        t_score, t_reasons = analyze_text(subject)
        total_score += t_score
        details["score_breakdown"].extend(t_reasons)

    body_score, body_reasons = analyze_text(email_text)
    total_score += body_score
    details["score_breakdown"].extend(body_reasons)

    for url in urls:
        u_score, u_reasons = analyze_url(url)
        total_score += u_score
        details["urls"].append({
            "url": url,
            "score": u_score,
            "reasons": u_reasons
        })
        details["score_breakdown"].extend(u_reasons)

    classification = "Safe"
    if total_score >= 80:
        classification = "High Risk (Likely Phishing)"
    elif total_score >= 40:
        classification = "Medium Risk (Suspicious)"

    return {
        "total_score": total_score,
        "classification": classification,
        "details": details
    }

if __name__ == "__main__":
    with open("sample_email.txt", "r", encoding="utf-8") as f:
        email_text = f.read()

    result = analyze_email(email_text)

    with open("results.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4)

    print("Analysis complete. See results.json")
