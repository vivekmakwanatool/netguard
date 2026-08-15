import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
}


def parse_port_range(spec):
    ports = set()
    for part in (spec or "1-1024").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            start, end = int(start), int(end)
            if start < 1 or end > 65535 or start > end:
                raise ValueError("Invalid port range")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if not 1 <= port <= 65535:
                raise ValueError("Invalid port")
            ports.add(port)
    return sorted(ports)


def _scan_port(host, port, timeout=0.7):
    result = {"port": port, "state": "closed", "service": COMMON_SERVICES.get(port, "unknown"), "banner": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((host, port)) == 0:
            result["state"] = "open"
            try:
                sock.settimeout(0.5)
                sock.sendall(b"\r\n")
                banner = sock.recv(256).decode("utf-8", errors="replace").strip()
                result["banner"] = banner[:256]
            except OSError:
                pass
    except OSError:
        pass
    finally:
        sock.close()
    return result


def scan_host(host, ports, progress_callback=None, workers=64):
    try:
        socket.gethostbyname(host)
    except socket.gaierror as exc:
        return {"error": f"Unable to resolve target: {exc}", "results": []}

    results = []
    total = len(ports)
    done = 0
    with ThreadPoolExecutor(max_workers=min(workers, max(1, total))) as pool:
        futures = {pool.submit(_scan_port, host, p): p for p in ports}
        for future in as_completed(futures):
            results.append(future.result())
            done += 1
            if progress_callback:
                progress_callback(done, total)
    results.sort(key=lambda item: item["port"])
    return {"host": host, "scanned": total, "results": results}
