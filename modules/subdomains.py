import subprocess
import shutil
import os

def run_subfinder(domain, output_dir):
    """
    Runs subfinder to discover subdomains.
    """
    subfinder_path = shutil.which("subfinder")
    if not subfinder_path:
        print("[!] subfinder is not installed. Skipping passive subdomain discovery.")
        return []
    
    out_file = os.path.join(output_dir, "subfinder_output.txt")
    print(f"[*] Running subfinder on {domain}...")
    try:
        subprocess.run([subfinder_path, "-d", domain, "-o", out_file], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
    Queries crt.sh database for subdomains.
    """
    import urllib.request
    import json
    print(f"[*] Querying crt.sh for {domain}...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode('utf-8'))
            subdomains = set()
            for entry in data:
                name = entry.get('name_value', '')
                for sub in name.split('\n'):
                    sub = sub.strip().lower()
                    if sub and not sub.startswith('*'):
                        subdomains.add(sub)
            print(f"[✔] crt.sh discovered {len(subdomains)} subdomains.")
            return list(subdomains)
    except Exception as e:
        print(f"[X] crt.sh query failed: {e}")
    return []
