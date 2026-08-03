#!/usr/bin/env python3
"""
ShadowScan AI - Main Orchestrator CLI
"""

import sys
import os
import json
from datetime import datetime

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
        
        # Create dirs
        for d in [self.subdomains_dir, self.dns_dir, self.live_hosts_dir, self.screenshots_dir, self.ssl_dir, self.vuln_dir, self.fuzz_dir, self.takeover_dir, "reports"]:
            os.makedirs(d, exist_ok=True)
            
        self.state_file = os.path.join(self.session_folder, "session_state.json")
        self.state = {
            "target": self.target,
            "subdomains": [],
            "live_hosts": [],
            "open_ports": {},
            "technologies": {},
            "completed_phases": [],
            "last_updated": self.timestamp
        }
        
    def save_state(self):
        self.state["last_updated"] = get_timestamp()
        with open(self.state_file, "w") as f:
            json.dump(self.state, f, indent=2)

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

def main():
    print_banner()
    
    if len(sys.argv) < 2:
        print("[!] Usage: python shadowscan.py <target_domain>")
        sys.exit(1)
        
    target = sys.argv[1].strip()
    
    # 1. Guardrail
    check_authorization(target)
    
    # 2. Session Init
    session = ReconSession(target)
    print(f"[*] Session started in: {session.session_folder}")
    
    # 3. OSINT & Passive DNS
    osint_data = gather_osint(target)
    
    # 4. Subdomain Discovery
    subs1 = run_subfinder(target, session.subdomains_dir)
    subs2 = run_crtsh(target)
    all_subs = sorted(list(set([target] + subs1 + subs2)))
    session.state["subdomains"] = all_subs
    session.save_state()
    
    # 5. DNS validations
    for sub in all_subs[:10]: # Limit for demo speed
        resolve_dns_records(sub)
        
    # 6. Live Host Filtering & Screen Capture
    live_urls = check_live(all_subs[:20]) # Validate subset
    session.state["live_hosts"] = live_urls
    session.save_state()
    
    capture_screenshots(live_urls, session.screenshots_dir)
    
    # 7. SSL Scanning
    scan_ssl(all_subs[:3], session.ssl_dir)
    
    # 8. Tech Fingerprinting & Subdomain Takeovers
    fingerprint_technology(live_urls)
    detect_subdomain_takeover(all_subs, session.takeover_dir)
    
    # 9. Port Scanner
    open_ports = scan_ports(all_subs[:5])
    session.state["open_ports"] = open_ports
    session.save_state()
    
    # 10. Vulnerability/CVE Scanner
    run_nuclei_vuln_scan(all_subs[:5], session.vuln_dir)
    
    # 11. AI Analysis & Report Generation
    ai_insights = analyze_vulnerabilities(session.state)
    
    report_path = os.path.join("reports", f"report_{target}_{get_timestamp()}.html")
    generate_html_report(session.state, ai_insights, report_path)
    
    print("====================================================")
    print(f"[✔] Scan complete. Final report: {report_path}")
    print("====================================================")

if __name__ == "__main__":
    main()
