# ShadowScan AI

ShadowScan AI is an intelligent, AI-powered web reconnaissance and vulnerability scanning suite optimized for Kali Linux.

## Project Structure
```
shadowscan-ai/
├── shadowscan.py          # Main CLI runner & orchestrator
├── requirements.txt       # Python dependencies
├── setup.sh               # Install script for Kali Linux dependencies
├── README.md              # Documentation
├── guardrails/
│   └── auth_check.py      # Authorization and scope checks
└── modules/
    ├── __init__.py
    ├── subdomains.py      # 1. Subdomain enumeration (passive & active)
    ├── dns_validator.py   # 2. DNS validations & lookups
    ├── live_hosts.py      # 3. Live host connectivity validation
    ├── ssl_scanner.py     # 4. SSL/TLS configuration checks
    ├── fingerprint.py     # 5. Technology fingerprinting (WhatWeb/headers)
    ├── takeover.py        # 6. Subdomain takeover detection (Subzy/Nuclei)
    ├── screenshotter.py   # 7. Screenshotting live hosts (Selenium)
    ├── port_scanner.py    # 8. Local/remote port scanner
    ├── osint.py           # 9. Passive OSINT & intelligence gathering
    ├── cve_scanner.py     # 10. Vulnerability/CVE scanning (Nuclei)
    ├── ai_analyzer.py     # 11. Ollama-based local LLM security analyzer
    └── report_gen.py      # 12. HTML/Markdown reporting engine
```

## Features
- **Passive & Active Subdomain Enumeration**: Integrates passive search (via crt.sh) and active search (via Subfinder) to map the attack surface.
- **DNS Lookup & Validations**: Performs detailed DNS record queries (A, AAAA, MX, NS, TXT, CNAME, SOA) and IPPTR reverse resolutions.
- **Live Host Discovery**: Probes discovered subdomains to check for live web server responses.
- **SSL/TLS Configuration Checks**: Leverages `testssl.sh` to identify SSL configurations, vulnerabilities, and deprecated ciphers.
- **Web Fingerprinting**: Analyzes headers and uses `WhatWeb` to catalog backend technologies.
- **Subdomain Takeover Detection**: Checks pointing configurations for abandoned SaaS and third-party aliases (using Subzy).
- **Automated Headless Screenshots**: Uses Selenium to take browser screenshots of live targets.
- **Port Scanner**: Performs quick port scanning to discover exposed services.
- **Passive OSINT**: Gathers target info passively.
- **Vulnerability/CVE Scanner**: Orchestrates `Nuclei` templates to check for thousands of CVEs and web application vulnerabilities.
- **AI Security Analysis**: Connects with a local **Ollama** LLM (e.g., Llama 3.1) to analyze scanner findings and deliver human-readable insights and remediation advice.
- **HTML Reporting**: Generates interactive HTML reports compiling scan outputs and AI-generated insights.

## Requirements
- **Operating System**: Kali Linux (recommended) or any Debian-based Linux distribution.
- **Python**: Version 3.8 or higher.
- **Local LLM Engine**: Ollama (configured with the `llama3.1` model).
- **Core Utilities**: `git`, `python3-pip`, `python3-venv`, `chromium` (or `google-chrome`).

## Installation
First, clone the repository:
```bash
git clone https://github.com/swapnilsupe01/shadowscan-ai.git
cd shadowscan-ai
```

Run the dependency setup script:
```bash
chmod +x setup.sh
sudo ./setup.sh
```

Ensure Ollama is installed and run the local `llama3.1` model:
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull Llama 3.1 model
ollama pull llama3.1
```

## Usage
To execute the complete reconnaissance and vulnerability scanning workflow:
```bash
python3 shadowscan.py <target_domain>
```
*Note: Make sure your Ollama service is active and running in the background before initiating the scan.*

## Main Menu / Workflow
When executing `shadowscan.py`, the orchestrator moves through the following pipeline:
1. **Authorization Check**: Validates if the target domain matches user authorization boundaries.
2. **OSINT Gathering**: Grabs passive domain information.
3. **Subdomain Enumeration**: Executes CRT.sh and Subfinder lookups.
4. **DNS Validations**: Verifies record states for the discovered scope.
5. **Host Filtering**: Identifies live HTTP/HTTPS services.
6. **Screen Capturing**: Fires up a headless Selenium Chromium browser to capture homepages.
7. **SSL Scanning**: Profiles TLS parameters for key hosts.
8. **Technology & Takeover Profiling**: Checks web fingerprints and looks for orphaned CNAME records.
9. **Port Scanning**: Probes for open TCP services.
10. **Nuclei Vulnerability Scan**: Checks live targets against Nuclei templates.
11. **AI Analysis**: Sends the JSON results payload to the local `llama3.1` LLM for insights.
12. **Report Generation**: Emits a single HTML report file inside the `reports/` folder.

## Notes & Limitations
- **Scanning Thresholds**: By default, ShadowScan AI implements query limiting (e.g., scanning only the top discovered subdomains) to ensure swift execution times during demos. You can scale these counts directly in `shadowscan.py`.
- **System Permissions**: Some system installation fallbacks (like writing to `/usr/local/bin` or running `apt`) require root or `sudo` privileges.
- **Resource Usage**: Running a local LLM via Ollama can be resource-intensive. A minimum of 8GB system RAM (16GB recommended) is advised for running the `llama3.1:8b` model smoothly.
