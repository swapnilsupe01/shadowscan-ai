import urllib.request
import ssl
import json
import shutil
import subprocess
import os

def fingerprint_technology(urls):
    """
    Fingerprints web technologies using headers, body matching, or whatweb.
    """
    tech_results = {}
    whatweb_path = shutil.which("whatweb")
    ssl_context = ssl._create_unverified_context()
    
    for url in urls:
        tech_results[url] = []
        if whatweb_path:
            print(f"[*] Running whatweb on {url}...")
            try:
                result = subprocess.run([whatweb_path, "--color=never", url], capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    output = result.stdout.strip()
                    tech_results[url].append(output)
                    print(f"    [✔] Fingerprinted: {output[:120]}...")
                    continue
            except Exception as e:
                print(f"[!] whatweb error: {e}")
                
        # Basic fallback matching via HTTP headers
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5, context=ssl_context) as response:
                headers = response.info()
                server = headers.get('Server', '')
                powered_by = headers.get('X-Powered-By', '')
                if server:
                    tech_results[url].append(f"Server: {server}")
                if powered_by:
                    tech_results[url].append(f"X-Powered-By: {powered_by}")
        except Exception:
            pass
            
    return tech_results

