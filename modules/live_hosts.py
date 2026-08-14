import ssl
import urllib.request

def check_live(hosts, timeout=5.0):
    """
    Checks which hosts are alive by requesting them over http/https.
    """
    live_urls = []
    ssl_context = ssl._create_unverified_context()
    print(f"[*] Checking HTTP/HTTPS connectivity for {len(hosts)} hosts...")
    for host in hosts:
        for proto in ['https://', 'http://']:
            url = f"{proto}{host}"
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as response:
                    if response.status:
                        live_urls.append(url)
                        break
            except Exception:
                continue
    return live_urls

