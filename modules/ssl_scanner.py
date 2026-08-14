import os
import ssl
import socket
import json
import subprocess
import shutil
from datetime import datetime

def parse_ssl_cert_python(host, port=443, timeout=5.0):
    """
    Natively inspects SSL/TLS certificate for a target host on port 443 without external binaries.
    Returns a dictionary of certificate details or None if connection fails.
    """
    clean_host = host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    ssl_info = {}
    try:
        with socket.create_connection((clean_host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=clean_host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cipher = ssock.cipher()
                version = ssock.version()
                
                ssl_info['host'] = clean_host
                ssl_info['tls_version'] = version
                ssl_info['cipher'] = cipher[0] if cipher else None
                
                if cert:
                    # Subject & Issuer
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    ssl_info['subject_cn'] = subject.get('commonName')
                    ssl_info['issuer_cn'] = issuer.get('commonName') or issuer.get('organizationName')
                    
                    # Validity Dates
                    not_after = cert.get('notAfter')
                    not_before = cert.get('notBefore')
                    ssl_info['valid_from'] = not_before
                    ssl_info['valid_until'] = not_after
                    
                    if not_after:
                        try:
                            # Format: 'May 10 23:59:59 2024 GMT'
                            expire_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days_left = (expire_dt - datetime.utcnow()).days
                            ssl_info['days_until_expiration'] = days_left
                            ssl_info['is_expired'] = days_left < 0
                        except Exception:
                            pass
                            
                    # SANs
                    sans = [item[1] for item in cert.get('subjectAltName', []) if item[0] == 'DNS']
                    ssl_info['san_domains'] = sans
                else:
                    ssl_info['note'] = "Certificate retrieved without detailed fields (CERT_NONE mode)."
                    
    except Exception as e:
        ssl_info['error'] = str(e)
        
    return ssl_info

def scan_ssl(hosts, output_dir):
    """
    Scans SSL/TLS configurations for target hosts using testssl.sh (if present)
    combined with a native Python SSL socket inspector fallback.
    Returns a dict mapping {host: ssl_data}.
    """
    os.makedirs(output_dir, exist_ok=True)
    ssl_results = {}
    
    if not hosts:
        return ssl_results
        
    print(f"[*] Analyzing SSL/TLS configurations for {len(hosts)} hosts...")
    
    # 1. Native Python SSL Inspection (guaranteed cross-platform)
    for host in hosts:
        print(f"  [+] Inspecting SSL certificate on {host}...")
        cert_data = parse_ssl_cert_python(host)
        if cert_data:
            ssl_results[host] = cert_data
            out_file = os.path.join(output_dir, f"ssl_{host.replace('.', '_')}.json")
            try:
                with open(out_file, "w", encoding="utf-8") as f:
                    json.dump(cert_data, f, indent=2)
            except Exception as e:
                print(f"    [!] Failed to save {out_file}: {e}")
                
    # 2. External testssl.sh check (if available)
    testssl_path = shutil.which("testssl.sh") or "/opt/testssl.sh/testssl.sh"
    if os.path.exists(testssl_path) or shutil.which("testssl.sh"):
        print("[*] Running testssl.sh deep scan...")
        for host in hosts[:2]:
            clean_h = host.replace("https://", "").replace("http://", "").split("/")[0]
            out_file = os.path.join(output_dir, f"testssl_{clean_h}.txt")
            try:
                cmd = [testssl_path, "--quiet", "--logfile", out_file, clean_h]
                subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"  [✔] testssl.sh output saved for {clean_h}.")
            except Exception as e:
                print(f"  [X] testssl.sh failed on {clean_h}: {e}")
                
    # Save overall summary file
    summary_file = os.path.join(output_dir, "ssl_summary.json")
    try:
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(ssl_results, f, indent=2)
        print(f"[✔] SSL scan completed. Saved summary to {summary_file}")
    except Exception as e:
        print(f"[!] Failed to save SSL summary file: {e}")
        
    return ssl_results
