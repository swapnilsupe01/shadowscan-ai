import socket

def scan_ports(hosts, ports=[21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 8080, 8443]):
    """
    Performs port scanning on specified hosts.
    """
    open_ports = {}
    print(f"[*] Port scanning {len(hosts)} hosts for standard ports...")
    
    for host in hosts:
        open_ports[host] = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.0)
                    result = s.connect_ex((host, port))
                    if result == 0:
                        open_ports[host].append(port)
                        print(f"    [✔] {host}:{port} - OPEN")
            except Exception:
                pass
    return open_ports
