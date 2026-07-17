import socket
import threading
from datetime import datetime

# Common ports with service names
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB", 6379: "Redis", 5432: "PostgreSQL"
}

def resolve_host(target):
    try:
        ip = socket.gethostbyname(target)
        hostname = socket.getfqdn(target)
        return ip, hostname
    except socket.gaierror as e:
        return None, str(e)

def grab_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        # Send HTTP request for web ports
        if port in [80, 8080, 8443]:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        else:
            s.send(b"\r\n")
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner[:100] if banner else None
    except:
        return None

def scan_port(ip, port, results, lock):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        s.close()

        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            banner = grab_banner(ip, port)
            with lock:
                results.append({
                    "port": port,
                    "status": "OPEN",
                    "service": service,
                    "banner": banner or "N/A"
                })
    except:
        pass

def run_scan(target, port_range="common"):
    ip, hostname = resolve_host(target)
    if not ip:
        return {"error": f"Could not resolve host: {target}"}

    if port_range == "common":
        ports = list(COMMON_PORTS.keys())
    elif port_range == "top100":
        ports = list(range(1, 101))
    elif port_range == "full":
        ports = list(range(1, 1025))
    else:
        ports = list(COMMON_PORTS.keys())

    results = []
    lock = threading.Lock()
    threads = []

    start_time = datetime.now()

    for port in ports:
        t = threading.Thread(target=scan_port, args=(ip, port, results, lock))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    results.sort(key=lambda x: x["port"])

    return {
        "target": target,
        "ip": ip,
        "hostname": hostname,
        "port_range": port_range,
        "total_ports_scanned": len(ports),
        "open_ports": len(results),
        "scan_duration": round(duration, 2),
        "scan_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "ports": results
    }
