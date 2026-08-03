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
