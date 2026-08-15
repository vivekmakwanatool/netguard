# NetGuard — Cybersecurity Scanning Dashboard

A self-hosted web app for authorized security testing: a threaded TCP port scanner with banner grabbing, a vulnerability heuristics engine, and passive web-app checks (HTTPS/TLS, security headers, exposed sensitive files) — all behind a login, with a live-progress scan screen and a printable report.

## ⚠️ Legal notice — read first

**Only scan hosts, networks, and web apps you own or have explicit written authorization to test.** Unauthorized scanning can violate laws such as the Computer Fraud and Abuse Act (US), the Information Technology Act 2000 (India), the Computer Misuse Act (UK), and similar legislation elsewhere — even a simple port scan. This app requires you to tick an authorization checkbox before every scan, but that's a reminder, not a legal shield. Good targets to practice on: your own machine (`127.0.0.1`), your own home router, or a deliberately-vulnerable lab like OWASP Juice Shop or a Hack The Box / TryHackMe target you've spun up.

## What it actually does

| Feature | How |
|---|---|
| Port scanner | Threaded TCP connect scan, configurable port range, banner grabbing, common-port service labeling |
| Vulnerability scan | Flags inherently-risky exposed services and matches banners against a small table of known-bad version strings |
| Web app checks | Passive, read-only checks: HTTPS enforcement, TLS errors, missing security headers (CSP, HSTS, X-Frame-Options...), commonly-exposed sensitive files (`.env`, `.git/config`, backups) |
| Auth | Login required for every route; passwords hashed with Werkzeug's `generate_password_hash` (PBKDF2) |
| Reporting | Severity-scored findings (Critical/High/Medium/Low), scan history, printable/PDF-able report via the browser's print dialog |

## Technologies Used

- Python 3
- Flask
- SQLite
- Werkzeug password hashing
- Threaded TCP socket scanning
- HTTP/HTTPS security checks
- HTML/CSS/JavaScript frontend

## Setup — Kali Linux

### Recommended: virtual environment

```bash
unzip netguard.zip
cd netguard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

If the project is already extracted, start from `cd netguard`.

Open:

`http://127.0.0.1:5050`

### If Kali blocks system-wide pip installation

Use the virtual-environment method above. If you intentionally choose the system Python, Kali may require:

```bash
pip install -r requirements.txt --break-system-packages
```

## Setup — Windows

```powershell
# Extract the project ZIP first
cd netguard
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open:

`http://127.0.0.1:5050`

## First Login

On first run the application prints a generated/default development login in the terminal. In the current project configuration it is:

```text
username: admin
password: changeme123
```

**Change this password immediately after logging in.** The application stores a password hash rather than the plaintext password.

## Project Structure

```text
netguard/
├── app.py
├── requirements.txt
├── scanner/
│   ├── port_scanner.py
│   ├── vuln_scanner.py
│   └── web_checks.py
├── templates/
├── static/
└── netguard.db          # created locally at runtime; do not commit
```

## Example Security Assessment

The project was tested in a controlled Kali Linux lab against an authorized website. The captured dashboard screenshots in `proof/` show the login interface, port-scan result, full-scan result, printable report view, and identified findings.

### Observed lab findings

The supplied test screenshots show:

- **Port scan:** 2 open ports out of 1024 scanned — HTTP/80 and HTTPS/443.
- **Full scan:** 2 Medium findings and 1 Low finding.
- **Medium:** HTTP does not redirect to HTTPS.
- **Medium:** Missing `Content-Security-Policy` header.
- **Low:** Server header discloses software information (`cloudflare`).

These are observations from the supplied lab screenshots, not a claim that the target is vulnerable in general. The scanner is heuristic and should be followed by manual validation.

## Reporting

The results page can be printed or saved as PDF using the browser print dialog. Reports include a severity summary, open ports, findings, and remediation-oriented descriptions.

## Limitations

This is a lightweight educational scanner, not a replacement for a full professional vulnerability-management platform. The vulnerability engine uses a small hand-curated set of heuristics and known-bad banner patterns; it does not maintain a live CVE feed.

Active exploitation, SQL injection payloads, XSS payload injection, and authentication brute-force testing are intentionally outside the scope of this project.

## Future Improvements

- Real CVE matching through the NVD API
- UDP scanning
- Role-based access control
- Background job queue for larger scans
- Expanded passive web security checks
- More comprehensive service/version fingerprinting

## Disclaimer

NetGuard is for educational and authorized security testing only. Always obtain explicit permission before scanning a host, network, or web application.
