import re
import socket
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "verify", "update", "login", "secure", "account",
    "bank", "password", "confirm", "paypal", "apple", "microsoft"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"
]


def is_ip_address(domain):
    try:
        socket.inet_aton(domain)
        return True
    except socket.error:
        return False


def contains_suspicious_keywords(text):
    text = text.lower()
    found = [word for word in SUSPICIOUS_KEYWORDS if word in text]
    return found


def is_shortened_url(domain):
    return domain in URL_SHORTENERS


def extract_urls(text):
    url_regex = r"(https?://[^\s]+)"
    return re.findall(url_regex, text)


def analyze_url(url):
    score = 0
    reasons = []

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if is_ip_address(domain):
        score += 3
        reasons.append("URL uses IP address instead of domain")

    if is_shortened_url(domain):
        score += 2
        reasons.append("URL shortener detected")

    suspicious_words = contains_suspicious_keywords(url)
    if suspicious_words:
        score += 2
        reasons.append(f"Suspicious keywords in URL: {', '.join(suspicious_words)}")

    return score, reasons


def analyze_email(email_text):
    total_score = 0
    report = []

    suspicious_words = contains_suspicious_keywords(email_text)
    if suspicious_words:
        total_score += 2
        report.append(f"Suspicious words in email: {', '.join(suspicious_words)}")

    urls = extract_urls(email_text)
    for url in urls:
        score, reasons = analyze_url(url)
        total_score += score
        report.extend(reasons)

    return total_score, report



def phishing_risk(score):
    if score >= 6:
        return "HIGH RISK ⚠️"
    elif score >= 3:
        return "MEDIUM RISK ⚠️"
    else:
        return "LOW RISK ✅"



if __name__ == "__main__":
    print("=== Phishing Detection Tool ===\n")

    email = input("Paste email content here:\n\n")

    score, details = analyze_email(email)
    risk = phishing_risk(score)

    print("\n--- Analysis Report ---")
    print(f"Risk level: {risk}")
    print(f"Score: {score}\n")

    if details:
        print("Reasons:")
        for d in details:
            print(f"- {d}")
    else:
        print("No suspicious indicators found.")
