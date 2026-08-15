# NetGuard — Project & Lab Assessment Summary

## Project Overview

NetGuard is a self-hosted Flask dashboard for authorized security testing. It combines threaded TCP port discovery, lightweight vulnerability heuristics, passive web security checks, authentication, scan history, live progress, and a printable results page.

## Security Features

- Login-protected dashboard
- Werkzeug password hashing
- Authorization confirmation before each scan
- Threaded TCP connect scanning
- Service labeling and limited banner grabbing
- Heuristic risky-service detection
- Passive HTTPS/security-header checks
- Sensitive-path exposure checks
- SQLite scan history
- Printable browser-based report

## Lab Evidence

The supplied Kali Linux screenshots show a controlled NetGuard lab run. The observed evidence includes the login page, a port-scan report, a full-scan report, findings/remediation, and a browser print preview.

Observed lab results shown in the supplied screenshots:

- 2 open ports from a 1024-port scan: HTTP/80 and HTTPS/443.
- Full scan summary: 2 Medium findings and 1 Low finding.
- Medium: HTTP endpoint did not redirect to HTTPS.
- Medium: Content-Security-Policy header was missing.
- Low: Server header disclosed software information.

These are observations from the supplied lab evidence only. They are not a general vulnerability claim about the target.

## Methodology

1. Confirm authorization and define the target.
2. Run a bounded TCP port scan.
3. Identify open services and optional banners.
4. Apply lightweight vulnerability heuristics.
5. For web targets, perform passive HTTP/TLS/header checks.
6. Review findings manually.
7. Export or print the report for documentation.

## Limitations

NetGuard is an educational/lightweight scanner. It does not maintain a live CVE database and does not perform active SQL injection, XSS exploitation, credential brute forcing, or other intrusive exploitation.

## Ethical Use

Only scan systems you own or have explicit permission to test. Use intentionally vulnerable labs such as OWASP Juice Shop, local services, or other authorized training environments.
