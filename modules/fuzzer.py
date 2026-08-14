import os
import json
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

# Built-in curated wordlist of high-risk endpoints and sensitive files
DEFAULT_WORDLIST = [
    ".env",
    ".git/config",
    ".git/HEAD",
    ".ds_store",
    "robots.txt",
    "sitemap.xml",
    "admin",
    "admin/",
    "login",
    "api/",
    "api/v1/",
    "swagger.json",
    "api-docs",
    "config.php",
    "backup.zip",
    "db.sql",
    "server-status"
]

def check_endpoint(base_url, path, timeout=4.0):
    """
    Checks a single URL endpoint and returns response status details.
    """
    if not base_url.startswith(('http://', 'https://')):
        base_url = f"https://{base_url}"
        
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    result = None
    
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (ShadowScan AI Fuzzer)'})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status = response.status
            size = len(response.read(2048)) # sample size
            result = {
                "url": url,
                "path": path,
                "status": status,
                "size": size
            }
    except urllib.error.HTTPError as e:
        if e.code in [301, 302, 403, 401]:
            result = {
                "url": url,
                "path": path,
                "status": e.code,
                "size": 0
            }
    except Exception:
        pass
        
    return result

def run_directory_fuzzing(hosts, output_dir, wordlist=None, max_threads=5):
    """
    Performs multi-threaded HTTP endpoint and directory fuzzing against target hosts.
    Saves findings into 07_fuzzing/ directory.
    Returns a dictionary of discovered endpoints.
    """
    os.makedirs(output_dir, exist_ok=True)
    fuzz_results = {}
    
    if not hosts:
        print("[!] No live hosts provided for endpoint fuzzing.")
        return fuzz_results

    targets = hosts[:5] # limit targets to prevent rate limits
    paths = wordlist if wordlist else DEFAULT_WORDLIST
    
    print(f"[*] Starting endpoint & directory fuzzing on {len(targets)} hosts ({len(paths)} paths)...")
    
    discovered_count = 0
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_info = {}
        for host in targets:
            for path in paths:
                future = executor.submit(check_endpoint, host, path)
                future_to_info[future] = (host, path)
                
        for future in as_completed(future_to_info):
            res = future.result()
            if res:
                host, path = future_to_info[future]
                if host not in fuzz_results:
                    fuzz_results[host] = []
                fuzz_results[host].append(res)
                discovered_count += 1
                status_color = "[200 OK]" if res['status'] == 200 else f"[{res['status']}]"
                print(f"  [+] Discovered: {res['url']} {status_color}")

    # Save findings
    out_json = os.path.join(output_dir, "fuzz_results.json")
    try:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(fuzz_results, f, indent=2)
        print(f"[✔] Fuzzing results saved to {out_json} ({discovered_count} endpoints found).")
    except Exception as e:
        print(f"[!] Failed to save {out_json}: {e}")

    out_txt = os.path.join(output_dir, "fuzz_summary.txt")
    try:
        with open(out_txt, "w", encoding="utf-8") as f:
            f.write("=== SHADOWSCAN AI ENDPOINT FUZZING REPORT ===\n\n")
            for host, entries in fuzz_results.items():
                f.write(f"Host: {host}\n")
                for item in entries:
                    f.write(f"  [{item['status']}] {item['url']}\n")
                f.write("\n")
        print(f"[✔] Fuzzing summary report saved to {out_txt}")
    except Exception as e:
        print(f"[!] Failed to save {out_txt}: {e}")

    return fuzz_results
