import urllib.request
import json
import re

def gather_osint(domain):
    """
    Performs passive intelligence gathering on the domain.
    """
    osint_data = {
        "emails": [],
        "dns_dump": {}
    }
    print(f"[*] Gathering OSINT data for {domain}...")
    
    # Try querying the hacker-target DNS lookup API (free service)
    try:
        url = f"https://api.hackertarget.com/dnslookup/?q={domain}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            res = response.read().decode('utf-8')
            osint_data["dns_dump"] = {"hackertarget": res.split("\n")}
            print("[✔] DNS lookup dump retrieved.")
    except Exception as e:
        print(f"[!] Hackertarget OSINT failed: {e}")
        
    return osint_data
