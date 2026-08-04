import subprocess
import shutil
import os
import urllib.request
import json
import re

def _clean_domain(domain):
    """Strip http/https, www., trailing slashes to get root domain."""
    domain = domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0]
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain

def run_subfinder(domain, output_dir):
    """
    Runs subfinder to discover subdomains.
    """
    subfinder_path = shutil.which("subfinder")
    if not subfinder_path:
        print("[!] subfinder is not installed. Skipping passive subdomain discovery.")
        return []
    
    clean_dom = _clean_domain(domain)
    out_file = os.path.join(output_dir, "subfinder_output.txt")
    print(f"[*] Running subfinder on {clean_dom}...")
    try:
        subprocess.run([subfinder_path, "-d", clean_dom, "-o", out_file], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.path.exists(out_file):
            with open(out_file, "r") as f:
                subs = [line.strip() for line in f if line.strip()]
            print(f"[✔] subfinder discovered {len(subs)} subdomains.")
            return subs
    except Exception as e:
        print(f"[X] Subfinder error: {e}")
    return []

def run_crtsh(domain):
    """
    Queries crt.sh database for subdomains with retries and domain cleaning.
    """
    clean_dom = _clean_domain(domain)
    print(f"[*] Querying crt.sh for {clean_dom}...")
    
    urls = [
        f"https://crt.sh/?q=%25.{clean_dom}&output=json",
        f"https://crt.sh/?q={clean_dom}&output=json"
    ]
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'application/json'
    }
    
    for url in urls:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as response:
                raw_body = response.read().decode('utf-8', errors='ignore')
                
                # Check if response is valid JSON
                if not raw_body.strip().startswith('['):
                    continue
                    
                data = json.loads(raw_body)
                subdomains = set()
                for entry in data:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        # Clean wildcards and invalid characters
                        sub = re.sub(r'^\*\.', '', sub)
                        if sub and not sub.startswith('*') and clean_dom in sub:
                            subdomains.add(sub)
                
                if subdomains:
                    print(f"[✔] crt.sh discovered {len(subdomains)} subdomains.")
                    return list(subdomains)
        except json.JSONDecodeError:
            # crt.sh often returns HTML error page (504 Gateway Timeout) when overloaded
            print(f"[!] crt.sh returned non-JSON response (server overloaded).")
        except Exception as e:
            print(f"[!] crt.sh request attempt error: {e}")
            
    print(f"[X] crt.sh query failed or returned no results.")
    return []
