import os
import json
import ssl
import socket
import urllib.request
import urllib.error
import subprocess
import shutil

# Signatures for dangling CNAME takeover detection
TAKEOVER_SIGNATURES = {
    "GitHub Pages": {
        "cname": ["github.io"],
        "fingerprint": ["There's no site here", "404 Not Found"]
    },
    "AWS S3 Bucket": {
        "cname": ["s3.amazonaws.com", "s3-website"],
        "fingerprint": ["NoSuchBucket", "The specified bucket does not exist"]
    },
    "Heroku App": {
        "cname": ["herokuapp.com"],
        "fingerprint": ["no such app", "Heroku | No such app"]
    },
    "Azure App Service": {
        "cname": ["azurewebsites.net", "cloudapp.net"],
        "fingerprint": ["404 Web Site not found", "The resource you are looking for has been removed"]
    },
    "Shopify Store": {
        "cname": ["myshopify.com"],
        "fingerprint": ["Sorry, this shop is currently unavailable"]
    },
    "Fastly CDN": {
        "cname": ["fastly.net"],
        "fingerprint": ["Fastly error: unknown domain"]
    },
    "Zendesk": {
        "cname": ["zendesk.com"],
        "fingerprint": ["Help Center Closed"]
    },
    "Ghost Blog": {
        "cname": ["ghost.io"],
        "fingerprint": ["The thing you were looking for is no longer here"]
    },
    "Surge.sh": {
        "cname": ["surge.sh"],
        "fingerprint": ["project not found"]
    },
    "Tumblr": {
        "cname": ["domains.tumblr.com"],
        "fingerprint": ["Whatever you were looking for doesn't get better"]
    }
}

def check_cname_takeover_python(domain, timeout=4.0):
    """
    Natively checks if a subdomain's CNAME points to an unclaimed cloud service.
    """
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    
    cname_target = None
    try:
        import dns.resolver
        answers = dns.resolver.resolve(clean_domain, 'CNAME')
        for rdata in answers:
            cname_target = str(rdata.target).rstrip('.')
            break
    except Exception:
        try:
            cname_target = socket.gethostbyname_ex(clean_domain)[0]
        except Exception:
            pass

    if not cname_target:
        return None

    # Check if CNAME matches any known cloud service pattern
    matched_service = None
    matched_sig = None
    for service, sig in TAKEOVER_SIGNATURES.items():
        for pat in sig["cname"]:
            if pat in cname_target.lower():
                matched_service = service
                matched_sig = sig
                break
        if matched_service:
            break

    if not matched_service:
        return None

    # Verify HTTP error fingerprint signature
    is_vulnerable = False
    http_response = ""
    ssl_context = ssl._create_unverified_context()
    for proto in ["https://", "http://"]:
        url = f"{proto}{clean_domain}"
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (ShadowScan AI Takeover Scanner)'})
            with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as resp:
                body = resp.read().decode('utf-8', errors='ignore')
                for fp in matched_sig["fingerprint"]:
                    if fp.lower() in body.lower():
                        is_vulnerable = True
                        http_response = body[:200]
                        break
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='ignore')
            for fp in matched_sig["fingerprint"]:
                if fp.lower() in body.lower():
                    is_vulnerable = True
                    http_response = body[:200]
                    break
        except Exception:
            pass
            
        if is_vulnerable:
            break

    return {
        "domain": clean_domain,
        "cname": cname_target,
        "service": matched_service,
        "vulnerable": is_vulnerable,
        "evidence": http_response if is_vulnerable else "CNAME points to service, but HTTP fingerprint did not trigger."
    }

def detect_subdomain_takeover(hosts, output_dir):
    """
    Performs subdomain takeover detection using subzy or nuclei,
    combined with a native Python CNAME & HTTP fingerprint checker fallback.
    Returns a list of takeover results.
    """
    os.makedirs(output_dir, exist_ok=True)
    takeover_results = []
    
    if not hosts:
        print("[!] No hosts provided for subdomain takeover analysis.")
        return takeover_results

    print(f"[*] Running subdomain takeover analysis for {len(hosts)} hosts...")
    
    # 1. Native Python CNAME & Fingerprint Inspection
    native_findings = []
    for host in hosts:
        res = check_cname_takeover_python(host)
        if res:
            native_findings.append(res)
            if res.get("vulnerable"):
                print(f"  [!] CRITICAL: Subdomain Takeover Vulnerability on {res['domain']} ({res['service']})!")
                takeover_results.append(f"Subdomain Takeover Identified on {res['domain']} pointing to {res['cname']} ({res['service']})")
                
    out_json = os.path.join(output_dir, "takeover_results.json")
    try:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(native_findings, f, indent=2)
        print(f"  [✔] Native takeover scan saved to {out_json}")
    except Exception as e:
        print(f"  [!] Failed to save {out_json}: {e}")

    # 2. External Tools (subzy / nuclei)
    subzy_path = shutil.which("subzy")
    nuclei_path = shutil.which("nuclei")
    
    temp_hosts = os.path.join(output_dir, "temp_hosts_takeover.txt")
    with open(temp_hosts, "w") as f:
        f.write("\n".join(hosts))
        
    if subzy_path:
        print("[*] Running subzy for subdomain takeover check...")
        out_file = os.path.join(output_dir, "subzy_results.json")
        try:
            subprocess.run([subzy_path, "run", "--targets", temp_hosts, "--output", out_file], check=False, stdout=subprocess.DEVNULL)
            if os.path.exists(out_file):
                with open(out_file, "r") as f:
                    takeover_results.append(f.read())
                print("  [✔] Subzy scan completed.")
        except Exception as e:
            print(f"  [X] Subzy failed: {e}")
            
    elif nuclei_path:
        print("[*] Running Nuclei subdomain takeover templates...")
        out_file = os.path.join(output_dir, "nuclei_takeovers.txt")
        try:
            subprocess.run([nuclei_path, "-l", temp_hosts, "-tags", "takeover", "-o", out_file], check=False, stdout=subprocess.DEVNULL)
            if os.path.exists(out_file):
                with open(out_file, "r") as f:
                    content = f.read()
                    if content.strip():
                        takeover_results.append(content)
                        print("  [!] Nuclei detected potential takeover!")
                print("  [✔] Nuclei takeover check completed.")
        except Exception as e:
            print(f"  [X] Nuclei failed: {e}")

    if os.path.exists(temp_hosts):
        try:
            os.remove(temp_hosts)
        except Exception:
            pass

    out_summary = os.path.join(output_dir, "takeover_summary.txt")
    try:
        with open(out_summary, "w", encoding="utf-8") as f:
            f.write("=== SHADOWSCAN AI SUBDOMAIN TAKEOVER REPORT ===\n\n")
            if takeover_results:
                for item in takeover_results:
                    f.write(f"{item}\n")
            else:
                f.write("No subdomain takeover vulnerabilities detected across analyzed hosts.\n")
        print(f"[✔] Takeover summary report saved to {out_summary}")
    except Exception as e:
        print(f"[!] Failed to save {out_summary}: {e}")
        
    return takeover_results
