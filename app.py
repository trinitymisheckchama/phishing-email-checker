import ipaddress
import re
from urllib.parse import urlsplit

from flask import Flask, render_template, request


app = Flask(__name__)

MAX_SUBJECT_LENGTH = 200
MAX_SENDER_LENGTH = 320
MAX_BODY_LENGTH = 20_000

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)
URL_TRIMMING = ".,;:!?)]}"
SHORTENER_DOMAINS = {
    "bit.ly",
    "buff.ly",
    "is.gd",
    "rebrand.ly",
    "tinyurl.com",
    "t.co",
}
WARNING_PHRASES = {
    "Urgent or threatening language": (
        "act immediately",
        "account will be suspended",
        "final warning",
        "immediate action required",
        "within 24 hours",
    ),
    "Request for sensitive information": (
        "bank details",
        "credit card",
        "login credentials",
        "password",
        "payment information",
        "social security number",
        "verify your account",
    ),
}


def _url_findings(text: str) -> list[dict[str, str | int]]:
    findings = []
    seen_urls = set()

    for match in URL_PATTERN.findall(text):
        url = match.rstrip(URL_TRIMMING)
        if url in seen_urls:
            continue
        seen_urls.add(url)

        try:
            parsed = urlsplit(url if "://" in url else f"http://{url}")
            hostname = (parsed.hostname or "").lower().rstrip(".")
        except ValueError:
            findings.append({
                "title": "Malformed link format",
                "detail": "A link in this message could not be safely parsed.",
                "points": 10,
            })
            continue

        if not hostname:
            continue

        if parsed.scheme.lower() == "http":
            findings.append({
                "title": "Link does not use HTTPS",
                "detail": f"{hostname} uses an unencrypted HTTP link.",
                "points": 10,
            })

        if hostname in SHORTENER_DOMAINS:
            findings.append({
                "title": "Link uses a URL shortener",
                "detail": f"The destination is hidden behind {hostname}.",
                "points": 20,
            })

        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            if hostname.startswith("xn--") or ".xn--" in hostname:
                findings.append({
                    "title": "Link contains an internationalized domain",
                    "detail": f"{hostname} may use lookalike characters.",
                    "points": 20,
                })
        else:
            findings.append({
                "title": "Link uses an IP address",
                "detail": f"{hostname} links directly to an IP address.",
                "points": 25,
            })

    return findings


def analyze_email(subject: str, sender: str, body: str) -> dict:
    """Return a heuristic risk score and the email patterns that contributed."""
    text = f"{subject}\n{sender}\n{body}".lower()
    findings: list[dict[str, str | int]] = []

    for title, phrases in WARNING_PHRASES.items():
        matched = next((phrase for phrase in phrases if phrase in text), None)
        if matched:
            points = 15 if title == "Urgent or threatening language" else 25
            findings.append({
                "title": title,
                "detail": f'The message includes the phrase "{matched}".',
                "points": points,
            })

    findings.extend(_url_findings(f"{subject}\n{body}"))
    score = min(sum(int(finding["points"]) for finding in findings), 100)

    if score >= 50:
        risk = "High"
    elif score >= 25:
        risk = "Medium"
    else:
        risk = "Low"

    return {"score": score, "risk": risk, "findings": findings}


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html")

    subject = request.form.get("subject", "").strip()
    sender = request.form.get("sender", "").strip()
    body = request.form.get("body", "").strip()

    if not body:
        return render_template(
            "index.html",
            error="Paste the email message so it can be checked.",
            subject=subject,
            sender=sender,
            body=body,
        ), 400

    if (
        len(subject) > MAX_SUBJECT_LENGTH
        or len(sender) > MAX_SENDER_LENGTH
        or len(body) > MAX_BODY_LENGTH
    ):
        return render_template(
            "index.html",
            error="The subject, sender, or message is longer than the allowed limit.",
            subject=subject[:MAX_SUBJECT_LENGTH],
            sender=sender[:MAX_SENDER_LENGTH],
            body=body[:MAX_BODY_LENGTH],
        ), 400

    result = analyze_email(subject, sender, body)
    return render_template(
        "index.html",
        subject=subject,
        sender=sender,
        body=body,
        result=result,
    )


if __name__ == "__main__":
    app.run(debug=False)
