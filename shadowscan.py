#!/usr/bin/env python3
"""
ShadowScan AI - Main Orchestrator CLI
"""

import sys
import os
import json
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import modules
from guardrails.auth_check import check_authorization
from modules.subdomains import run_subfinder, run_crtsh
from modules.dns_validator import resolve_dns_records
from modules.live_hosts import check_live
from modules.screenshotter import capture_screenshots
from modules.ssl_scanner import scan_ssl
from modules.fingerprint import fingerprint_technology
from modules.takeover import detect_subdomain_takeover
from modules.port_scanner import scan_ports
from modules.osint import gather_osint
from modules.cve_scanner import run_nuclei_vuln_scan
from modules.ai_analyzer import analyze_vulnerabilities
from modules.report_gen import generate_html_report


def get_timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

class ReconSession:
    def __init__(self, target):
        self.target = target
        self.timestamp = get_timestamp()
        self.session_folder = os.path.join("sessions", f"recon_{target.replace('.', '_')}_{self.timestamp}")
        
        # Paths
        self.subdomains_dir = os.path.join(self.session_folder, "01_subdomains")
        self.dns_dir = os.path.join(self.session_folder, "02_dns")
        self.live_hosts_dir = os.path.join(self.session_folder, "03_live_hosts")
        self.screenshots_dir = os.path.join(self.session_folder, "04_screenshots")
        self.ssl_dir = os.path.join(self.session_folder, "05_ssl")
        self.vuln_dir = os.path.join(self.session_folder, "06_vulnerabilities")
        self.fuzz_dir = os.path.join(self.session_folder, "07_fuzzing")
        self.takeover_dir = os.path.join(self.session_folder, "08_takeover")
        self.ai_dir = os.path.join(self.session_folder, "09_ai_analysis")
        self.osint_dir = os.path.join(self.session_folder, "10_osint")
        self.ports_dir = os.path.join(self.session_folder, "11_ports")
        self.fingerprint_dir = os.path.join(self.session_folder, "12_fingerprint")
        
        # Create dirs
        for d in [self.subdomains_dir, self.dns_dir, self.live_hosts_dir,
                  self.screenshots_dir, self.ssl_dir, self.vuln_dir,
                  self.fuzz_dir, self.takeover_dir, self.ai_dir,
                  self.osint_dir, self.ports_dir, self.fingerprint_dir, "reports"]:
            os.makedirs(d, exist_ok=True)
            
        self.state_file = os.path.join(self.session_folder, "session_state.json")
        self.state = {
            "target": self.target,
            "subdomains": [],
            "live_hosts": [],
            "open_ports": {},
            "technologies": {},
            "osint": {},
            "dns_records": {},
            "completed_phases": [],
            "last_updated": self.timestamp
        }
        
    def save_state(self):
        self.state["last_updated"] = get_timestamp()
        os.makedirs(self.session_folder, exist_ok=True)
        with open(self.state_file, "w") as f:
            json.dump(self.state, f, indent=2)
    
    def save_results(self, directory, filename, data):
        """Save results to a file in the given session directory."""
        filepath = os.path.join(directory, filename)
        try:
            os.makedirs(directory, exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                if isinstance(data, (dict, list)):
                    json.dump(data, f, indent=2)
                else:
                    f.write(str(data))
            print(f"    [💾] Saved: {filepath}")
        except Exception as e:
            print(f"    [!] Failed to save {filepath}: {e}")

def print_banner():
    banner = """
\033[1;36m╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                                     ║
║  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗███████╗ ██████╗                ║
║  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔════╝                ║
║  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║███████╗██║                     ║
║  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║╚════██║██║                     ║
║  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝███████║╚██████╗                ║
║  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚══════╝ ╚═════╝                ║
║                                                                                     ║
║                             █████╗ ██╗                                              ║
║                            ██╔══██╗██║                                              ║
║                            ███████║██║                                              ║
║                            ██╔══██║██║                                              ║
║                            ██║  ██║██║                                              ║
║                            ╚═╝  ╚═╝╚═╝                                              ║
║                                                                                     ║
║\033[1;33m       Intelligent Recon & Local LLM AI Security Analyzer              \033[1;36m║
║\033[1;32m                    Powered by Ollama + Llama 3.1                      \033[1;36m║
║                                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝\033[0m
"""
    print(banner)

def run_parallel(tasks, max_workers=4):
    """
    Run multiple tasks in parallel using ThreadPoolExecutor.
    tasks: list of (name, function, args) tuples.
    Returns dict of {name: result}.
    """
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {}
        for name, func, args in tasks:
            future = executor.submit(func, *args)
            future_map[future] = name
        
        for future in as_completed(future_map):
            name = future_map[future]
            try:
                results[name] = future.result()
                print(f"\033[1;32m[✔] Phase completed: {name}\033[0m")
            except Exception as e:
                print(f"\033[1;31m[X] Phase failed: {name} — {e}\033[0m")
                results[name] = None
    
    return results

def main():
    print_banner()
    start_time = time.time()
    
    if len(sys.argv) < 2:
        print("[!] Usage: python shadowscan.py <target_domain>")
        sys.exit(1)
        
    target = sys.argv[1].strip()
    
    # 1. Guardrail
    check_authorization(target)
    
    # 2. Session Init
    session = ReconSession(target)
    print(f"[*] Session started in: {session.session_folder}")
    
    # ── PHASE 1: OSINT + Subdomain Discovery (parallel) ──────────────
    print(f"\n\033[1;36m{'═'*60}")
    print("  PHASE 1: OSINT & Subdomain Discovery (parallel)")
    print(f"{'═'*60}\033[0m\n")
    
    phase1_tasks = [
        ("OSINT Gathering", gather_osint, (target,)),
        ("Subfinder Scan", run_subfinder, (target, session.subdomains_dir)),
        ("crt.sh Lookup", run_crtsh, (target,)),
    ]
    phase1_results = run_parallel(phase1_tasks, max_workers=3)
    
    subs1 = phase1_results.get("Subfinder Scan") or []
    subs2 = phase1_results.get("crt.sh Lookup") or []
    all_subs = sorted(list(set([target] + subs1 + subs2)))
    session.state["subdomains"] = all_subs
    
    # Save OSINT results
    osint_data = phase1_results.get("OSINT Gathering") or {}
    session.state["osint"] = osint_data
    session.save_results(session.osint_dir, "osint_results.json", osint_data)
    
    # Save all subdomains to file
    session.save_results(session.subdomains_dir, "all_subdomains.txt", "\n".join(all_subs))
    session.save_results(session.subdomains_dir, "crtsh_subdomains.txt", "\n".join(subs2))
    session.save_results(session.subdomains_dir, "subfinder_subdomains.txt", "\n".join(subs1))
    session.save_state()
    print(f"\n[✔] Total unique subdomains discovered: {len(all_subs)}")
    
    # ── PHASE 2: DNS + Live Hosts (parallel) ─────────────────────────
    print(f"\n\033[1;36m{'═'*60}")
    print("  PHASE 2: DNS Validation & Live Host Detection (parallel)")
    print(f"{'═'*60}\033[0m\n")
    
    dns_tasks = [("DNS: " + sub, resolve_dns_records, (sub,)) for sub in all_subs[:5]]
    dns_results = run_parallel(dns_tasks, max_workers=5)
    
    # Save DNS results
    all_dns = {}
    for name, result in dns_results.items():
        domain = name.replace("DNS: ", "")
        if result:
            all_dns[domain] = result
    session.state["dns_records"] = all_dns
    session.save_results(session.dns_dir, "dns_records.json", all_dns)
    
    live_urls = check_live(all_subs[:10])
    session.state["live_hosts"] = live_urls
    
    # Save live hosts to file
    session.save_results(session.live_hosts_dir, "live_hosts.txt", "\n".join(live_urls))
    session.save_state()
    print(f"[✔] Live hosts found: {len(live_urls)}")
    
    # ── PHASE 3: Screenshots + SSL + Fingerprint + Takeover (parallel)
    print(f"\n\033[1;36m{'═'*60}")
    print("  PHASE 3: Screenshots, SSL, Fingerprint, Takeover (parallel)")
    print(f"{'═'*60}\033[0m\n")
    
    phase3_tasks = [
        ("Screenshots", capture_screenshots, (live_urls, session.screenshots_dir)),
        ("SSL Scanning", scan_ssl, (all_subs[:2], session.ssl_dir)),
        ("Tech Fingerprint", fingerprint_technology, (live_urls,)),
        ("Takeover Detection", detect_subdomain_takeover, (all_subs[:10], session.takeover_dir)),
    ]
    phase3_results = run_parallel(phase3_tasks, max_workers=4)
    
    # Save fingerprint/technology results
    tech_data = phase3_results.get("Tech Fingerprint") or {}
    session.state["technologies"] = tech_data
    session.save_results(session.fingerprint_dir, "technologies.json", tech_data)
    session.save_state()
    
    # ── PHASE 4: Port Scan + Nuclei Vuln Scan (parallel) ─────────────
    print(f"\n\033[1;36m{'═'*60}")
    print("  PHASE 4: Port Scanning & Vulnerability Detection (parallel)")
    print(f"{'═'*60}\033[0m\n")
    
    phase4_tasks = [
        ("Port Scanner", scan_ports, (all_subs[:3],)),
        ("Nuclei CVE Scan", run_nuclei_vuln_scan, (all_subs[:3], session.vuln_dir)),
    ]
    phase4_results = run_parallel(phase4_tasks, max_workers=2)
    
    open_ports = phase4_results.get("Port Scanner") or {}
    session.state["open_ports"] = open_ports
    
    # Save port scan results
    session.save_results(session.ports_dir, "open_ports.json", open_ports)
    session.save_state()
    
    # ── PHASE 5: AI Analysis & Report (sequential) ───────────────────
    print(f"\n\033[1;36m{'═'*60}")
    print("  PHASE 5: AI Analysis & Report Generation")
    print(f"{'═'*60}\033[0m\n")
    
    ai_insights = analyze_vulnerabilities(session.state)
    
    # Save AI analysis to file
    session.save_results(session.ai_dir, "ai_analysis.md", ai_insights)
    
    report_path = os.path.join("reports", f"report_{target}_{get_timestamp()}.html")
    generate_html_report(session.state, ai_insights, report_path)
    
    # ── DONE ─────────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)
    
    print(f"\n\033[1;32m{'═'*60}")
    print(f"  [✔] SCAN COMPLETE — Total time: {minutes}m {seconds}s")
    print(f"  [✔] Report saved: {report_path}")
    print(f"  [✔] Session data: {session.session_folder}")
    print(f"{'═'*60}\033[0m\n")

if __name__ == "__main__":
    main()

