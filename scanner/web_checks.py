import os
import ssl
import socket
from urllib.parse import urlparse
import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps restrict executable content and reduce XSS impact.",
    "Strict-Transport-Security": "Forces browsers to prefer HTTPS after a secure connection.",
    "X-Content-Type-Options": "Reduces MIME-type sniffing.",
    "X-Frame-Options": "Helps mitigate clickjacking.",
    "Referrer-Policy": "Controls referrer information sent by browsers.",
}


def _tls_check(hostname, port=443):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as tls:
                return {"ok": True, "version": tls.version(), "cipher": tls.cipher()[0] if tls.cipher() else None}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _exposed_file_checks(base_url):
    findings = []
    for path in ("/.env", "/.git/config", "/backup.zip", "/config.json"):
        try:
            response = requests.get(base_url.rstrip("/") + path, timeout=5, allow_redirects=False)
            if response.status_code == 200 and len(response.content) > 0:
                findings.append({"severity": "High", "title": f"Potentially exposed sensitive path: {path}", "description": "A commonly sensitive path returned HTTP 200. Manually validate whether sensitive content is accessible."})
        except requests.RequestException:
            pass
    return findings


def run_web_checks(target):
    raw = target if "://" in target else "https://" + target
    parsed = urlparse(raw)
    hostname = parsed.hostname
    if not hostname:
        return {"error": "Invalid URL", "findings": []}

    findings = []
    try:
        response = requests.get(raw, timeout=8, allow_redirects=False, headers={"User-Agent": "NetGuard/1.0 educational scanner"})
        headers = {k.lower(): v for k, v in response.headers.items()}
        if parsed.scheme == "http":
            location = headers.get("location", "")
            if not location.lower().startswith("https://"):
                findings.append({"severity": "Medium", "title": "HTTP does not redirect to HTTPS", "description": "The supplied HTTP endpoint did not return an HTTPS redirect in this passive check."})
        for header, description in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                findings.append({"severity": "Medium" if header in ("Content-Security-Policy", "Strict-Transport-Security") else "Low", "title": f"Missing security header: {header}", "description": description})
        server = response.headers.get("Server")
        if server:
            findings.append({"severity": "Low", "title": "Server header discloses software information", "description": "The response exposes a Server header; consider minimizing unnecessary technology disclosure.", "evidence": server})
        findings.extend(_exposed_file_checks(f"{parsed.scheme}://{parsed.netloc}"))
    except requests.RequestException as exc:
        return {"error": str(exc), "findings": findings}

    tls = _tls_check(hostname) if parsed.scheme == "https" else None
    return {"url": raw, "status_code": response.status_code, "tls": tls, "findings": findings}
