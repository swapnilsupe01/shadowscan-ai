import subprocess
import shutil
import os

def scan_ssl(hosts, output_dir):
    """
    Scans SSL/TLS configuration using testssl.sh.
    """
    testssl_path = shutil.which("testssl.sh") or "/opt/testssl.sh/testssl.sh"
    if not os.path.exists(testssl_path) and not shutil.which("testssl.sh"):
        print("[!] testssl.sh is not installed or not in PATH. Skipping SSL/TLS analysis.")
        return
        
    print(f"[*] Running SSL/TLS analysis for {len(hosts)} hosts...")
    os.makedirs(output_dir, exist_ok=True)
    for host in hosts:
        out_file = os.path.join(output_dir, f"ssl_{host}.txt")
        print(f"[*] Analyzing SSL configuration on {host}...")
        try:
            cmd = [testssl_path, "--quiet", "--logfile", out_file, host]
            subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"[✔] SSL analysis saved for {host}.")
        except Exception as e:
            print(f"[X] SSL analysis failed on {host}: {e}")
