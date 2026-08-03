import subprocess
import shutil
import os

def detect_subdomain_takeover(hosts, output_dir):
    """
    Performs subdomain takeover detection using subzy or nuclei.
    """
    subzy_path = shutil.which("subzy")
    nuclei_path = shutil.which("nuclei")
    
    takeover_results = []
    os.makedirs(output_dir, exist_ok=True)
    
    # Write hosts to a temp file
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
                print("[✔] Takeover check completed (subzy).")
        except Exception as e:
            print(f"[X] Subzy failed: {e}")
            
    elif nuclei_path:
        print("[*] Running Nuclei subdomain takeover templates...")
        out_file = os.path.join(output_dir, "nuclei_takeovers.txt")
        try:
            subprocess.run([nuclei_path, "-l", temp_hosts, "-tags", "takeover", "-o", out_file], check=False, stdout=subprocess.DEVNULL)
            if os.path.exists(out_file):
                with open(out_file, "r") as f:
                    content = f.read()
                    takeover_results.append(content)
                    if content.strip():
                        print("[!] Potential Subdomain Takeover identified!")
                print("[✔] Takeover check completed (Nuclei).")
        except Exception as e:
            print(f"[X] Nuclei failed: {e}")
    else:
        print("[!] Neither subzy nor nuclei found. Skipping subdomain takeover detection.")
        
    if os.path.exists(temp_hosts):
        os.remove(temp_hosts)
        
    return takeover_results
