import os
import json
import urllib.request
import urllib.error
import subprocess
import shutil

def audit_http_security_headers(url, timeout=5.0):
    """
    Audits HTTP security headers and server technology information disclosures.
    """
    target_url = url if url.startswith(('http://', 'https://')) else f"https://{url}"
    findings = {
        "url": target_url,
        "missing_headers": [],
        "information_disclosure": [],
        "misconfigurations": []
    }
    
    recommended_headers = {
        "Strict-Transport-Security": "HSTS header missing (forces HTTPS connections).",
        "Content-Security-Policy": "CSP header missing (mitigates XSS & data injection).",
        "X-Frame-Options": "X-Frame-Options missing (susceptible to Clickjacking).",
        "X-Content-Type-Options": "X-Content-Type-Options missing (susceptible to MIME sniffing).",
        "Referrer-Policy": "Referrer-Policy header missing.",
        "Permissions-Policy": "Permissions-Policy header missing."
    }
    
    try:
        req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0 (ShadowScan AI Security Auditor)'})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            headers = {k.title(): v for k, v in response.headers.items()}
            
            # Check missing headers
            for header, desc in recommended_headers.items():
                if header not in headers:
                    findings["missing_headers"].append({"header": header, "description": desc})
                    
            # Check tech disclosures
            for disc_header in ["Server", "X-Powered-By", "X-Aspnet-Version", "X-Generator"]:
                if disc_header in headers:
                    findings["information_disclosure"].append({
                        "header": disc_header,
                        "value": headers[disc_header]
                    })
                    
            # Check CORS
            cors_origin = headers.get("Access-Control-Allow-Origin")
            if cors_origin == "*":
                findings["misconfigurations"].append({
                    "type": "Wildcard CORS",
                    "description": "Access-Control-Allow-Origin is set to '*' (wildcard)."
                })
                
    except Exception as e:
        findings["error"] = str(e)
        
    return findings

def run_nuclei_vuln_scan(hosts, output_dir):
    """
    Performs vulnerability scanning on hosts using Nuclei (if installed)
    combined with a native Python HTTP security header & disclosure auditor fallback.
    Returns a dictionary of vulnerability findings.
    """
    os.makedirs(output_dir, exist_ok=True)
    all_vulnerabilities = {
        "native_audit": {},
        "nuclei_output": ""
    }
    
    if not hosts:
        return all_vulnerabilities

    print(f"[*] Running HTTP security & vulnerability audit on {len(hosts)} hosts...")
    
    # 1. Native Security Header Audit
    for host in hosts:
        audit_res = audit_http_security_headers(host)
        all_vulnerabilities["native_audit"][host] = audit_res
        
    # Save native findings
    native_out = os.path.join(output_dir, "vulnerabilities.json")
    try:
        with open(native_out, "w", encoding="utf-8") as f:
            json.dump(all_vulnerabilities["native_audit"], f, indent=2)
        print(f"  [✔] Native security header audit saved to {native_out}")
    except Exception as e:
        print(f"  [!] Failed to save {native_out}: {e}")
        
    # 2. Nuclei Scan (if binary exists)
    nuclei_path = shutil.which("nuclei")
    out_file = os.path.join(output_dir, "nuclei_vulns.txt")
    
    if nuclei_path:
        temp_hosts = os.path.join(output_dir, "temp_vuln_hosts.txt")
        try:
            with open(temp_hosts, "w") as f:
                f.write("\n".join(hosts))
            
            print("[*] Running Nuclei CVE & vulnerability templates...")
            cmd = [nuclei_path, "-l", temp_hosts, "-severity", "critical,high,medium", "-o", out_file]
            subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL)
            
            if os.path.exists(out_file):
                with open(out_file, "r") as f:
                    content = f.read()
                    all_vulnerabilities["nuclei_output"] = content
                print(f"  [✔] Nuclei vulnerability scan completed. Saved to {out_file}")
        except Exception as e:
            print(f"  [X] Nuclei scan failed: {e}")
        finally:
            if os.path.exists(temp_hosts):
                try:
                    os.remove(temp_hosts)
                except Exception:
                    pass
    else:
        print("[!] Nuclei binary not found. Native security header audit completed successfully.")

    # Save summary text report
    summary_txt = os.path.join(output_dir, "vulnerabilities_summary.txt")
    try:
        with open(summary_txt, "w", encoding="utf-8") as f:
            f.write("=== SHADOWSCAN AI VULNERABILITY AUDIT REPORT ===\n\n")
            for host, res in all_vulnerabilities["native_audit"].items():
                f.write(f"Host: {host}\n")
                f.write(f"  Missing Security Headers: {len(res.get('missing_headers', []))}\n")
                for mh in res.get('missing_headers', []):
                    f.write(f"    - {mh['header']}: {mh['description']}\n")
                if res.get('information_disclosure'):
                    f.write("  Information Disclosure:\n")
                    for idis in res['information_disclosure']:
                        f.write(f"    - {idis['header']}: {idis['value']}\n")
                f.write("\n")
            if all_vulnerabilities["nuclei_output"]:
                f.write("=== NUCLEI DETECTED CVEs ===\n")
                f.write(all_vulnerabilities["nuclei_output"])
        print(f"[✔] Vulnerability summary saved to {summary_txt}")
    except Exception as e:
        print(f"[!] Failed to save {summary_txt}: {e}")

    return all_vulnerabilities
