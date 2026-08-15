import re

RISKY_SERVICES = {
    23: ("High", "Telnet is exposed; it sends credentials and traffic without modern transport protection."),
    6379: ("High", "Redis is commonly deployed without authentication and should not be internet-facing."),
    27017: ("High", "MongoDB should be protected with authentication and network access controls."),
    445: ("Medium", "SMB exposure increases attack surface and should normally be restricted."),
    3389: ("Medium", "RDP exposure should be restricted to trusted networks or VPN access."),
}

KNOWN_BAD_BANNERS = [
    (re.compile(r"apache/2\.4\.49", re.I), "High", "Apache HTTP Server 2.4.49 is associated with a known vulnerable release."),
    (re.compile(r"openssh[_ -]7\.[0-5]", re.I), "Medium", "The detected OpenSSH banner appears old and should be manually validated."),
]


def evaluate_open_ports(open_ports):
    findings = []
    for item in open_ports:
        port = item.get("port")
        banner = item.get("banner", "") or ""
        if port in RISKY_SERVICES:
            severity, description = RISKY_SERVICES[port]
            findings.append({"severity": severity, "title": f"Risky service exposed on port {port}", "description": description, "port": port})
        for pattern, severity, description in KNOWN_BAD_BANNERS:
            if pattern.search(banner):
                findings.append({"severity": severity, "title": "Potential outdated service banner", "description": description, "port": port, "evidence": banner})
    return findings
