import subprocess
import shutil
import os

def run_nuclei_vuln_scan(hosts, output_dir):
    """
    Performs vulnerability scanning on hosts using Nuclei.
    """
    nuclei_path = shutil.which("nuclei")
    out_file = os.path.join(output_dir, "nuclei_vulns.txt")
    
    if not nuclei_path:
        print("[!] Nuclei is not installed. Skipping vulnerability scanner.")
        return ""
        
    os.makedirs(output_dir, exist_ok=True)
    temp_hosts = os.path.join(output_dir, "temp_vuln_hosts.txt")
    with open(temp_hosts, "w") as f:
        f.write("\n".join(hosts))
        
    print("[*] Running Nuclei vulnerability scan...")
    try:
        cmd = [nuclei_path, "-l", temp_hosts, "-severity", "critical,high,medium", "-o", out_file]
        subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL)
        if os.path.exists(out_file):
            with open(out_file, "r") as f:
                content = f.read()
            print(f"[✔] Vulnerability scan completed. Results saved to {out_file}")
            if os.path.exists(temp_hosts):
                os.remove(temp_hosts)
            return content
    except Exception as e:
        print(f"[X] Nuclei scanning failed: {e}")
        
    if os.path.exists(temp_hosts):
        os.remove(temp_hosts)
    return ""
