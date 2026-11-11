# Phishing Email Checker

A small Flask app that checks pasted email text for a few common phishing warning signs, including urgent language, requests for sensitive information, unencrypted links, URL shorteners, IP-address links, and internationalized domains.

The checker is heuristic, not a security scanner: a high score does not prove an email is malicious, and a low score does not prove it is safe. It does not open links, send messages to an external service, or save submitted email content.

## Run locally

Requires Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000> in your browser.

## Run tests

```bash
python -m unittest discover -s tests
```
