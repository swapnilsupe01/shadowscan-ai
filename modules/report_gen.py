import os
import json
import html

def generate_html_report(recon_data, ai_findings, output_path):
    """
    Generates a rich, interactive dark-mode HTML dashboard combining scan findings,
    screenshot galleries, technical fingerprints, open ports, and AI recommendations.
    """
    print(f"[*] Generating final HTML report at {output_path}...")
    
    target = html.escape(str(recon_data.get('target', 'Target')))
    timestamp = html.escape(str(recon_data.get('last_updated', 'N/A')))
    
    subdomains = recon_data.get('subdomains', [])
    live_hosts = recon_data.get('live_hosts', [])
    open_ports = recon_data.get('open_ports', {})
    technologies = recon_data.get('technologies', {})
    screenshots = recon_data.get('screenshots', {})
    dns_records = recon_data.get('dns_records', {})
    ssl_certs = recon_data.get('ssl_certificates', {})
    takeovers = recon_data.get('takeover', [])
    cve_vulns = recon_data.get('cve_vulnerabilities', {})
    fuzzing = recon_data.get('fuzzing', {})
    
    # Calculate stats
    total_subdomains = len(subdomains)
    total_live = len(live_hosts)
    total_open_ports = sum(len(ports) for ports in open_ports.values() if isinstance(ports, list))
    total_screenshots = len(screenshots)
    total_takeovers = len(takeovers)
    total_fuzz_endpoints = sum(len(items) for items in fuzzing.values() if isinstance(items, list))
    
    # Build Screenshot Gallery HTML
    screenshot_cards = []
    report_dir = os.path.dirname(os.path.abspath(output_path))
    
    if screenshots:
        for url, img_path in screenshots.items():
            if img_path and os.path.exists(img_path):
                # Calculate relative path from report location to screenshot file
                try:
                    rel_path = os.path.relpath(img_path, start=report_dir)
                except Exception:
                    rel_path = img_path
            else:
                rel_path = ""
            
            clean_url = html.escape(url)
            if rel_path:
                screenshot_cards.append(f"""
                <div class="shot-card">
                    <div class="shot-img-container">
                        <a href="{html.escape(rel_path)}" target="_blank">
                            <img src="{html.escape(rel_path)}" alt="Screenshot of {clean_url}" class="shot-img" loading="lazy">
                        </a>
                    </div>
                    <div class="shot-info">
                        <a href="{clean_url}" target="_blank" class="shot-url">{clean_url}</a>
                    </div>
                </div>
                """)
            else:
                screenshot_cards.append(f"""
                <div class="shot-card">
                    <div class="shot-img-container placeholder">
                        <span>No Image</span>
                    </div>
                    <div class="shot-info">
                        <a href="{clean_url}" target="_blank" class="shot-url">{clean_url}</a>
                    </div>
                </div>
                """)
    
    screenshot_gallery_html = "".join(screenshot_cards) if screenshot_cards else "<p class='empty-msg'>No screenshots captured during this scan session.</p>"

    # Format Fuzzing HTML
    fuzz_rows = []
    if fuzzing:
        for host, items in fuzzing.items():
            if items:
                for item in items:
                    st = item.get('status')
                    status_class = "success" if st == 200 else "warning"
                    fuzz_rows.append(f"<tr><td><a href='{html.escape(item['url'])}' target='_blank'>{html.escape(item['url'])}</a></td><td><span class='badge port-badge'>{st}</span></td></tr>")
    fuzz_table_html = "".join(fuzz_rows) if fuzz_rows else "<tr><td colspan='2' class='empty-msg'>No sensitive endpoints discovered during fuzzing.</td></tr>"

    # Format SSL HTML
    ssl_rows = []
    if ssl_certs:
        for host, data in ssl_certs.items():
            if isinstance(data, dict):
                issuer = html.escape(str(data.get('issuer_cn', 'Unknown')))
                tls = html.escape(str(data.get('tls_version', 'Unknown')))
                days = data.get('days_until_expiration', 'N/A')
                ssl_rows.append(f"<tr><td><strong>{html.escape(host)}</strong></td><td>{issuer}</td><td>{tls}</td><td>{days} days</td></tr>")
    ssl_table_html = "".join(ssl_rows) if ssl_rows else "<tr><td colspan='4' class='empty-msg'>No SSL certificate details parsed.</td></tr>"

    # Format Ports HTML
    ports_rows = []
    if open_ports:
        for host, ports in open_ports.items():
            if ports:
                port_badges = " ".join([f"<span class='badge port-badge'>{p}</span>" for p in ports])
                ports_rows.append(f"<tr><td><strong>{html.escape(host)}</strong></td><td>{port_badges}</td></tr>")
    ports_table_html = "".join(ports_rows) if ports_rows else "<tr><td colspan='2' class='empty-msg'>No open ports detected.</td></tr>"

    # Format Tech Stack HTML
    tech_rows = []
    if technologies:
        for url, tech in technologies.items():
            if tech:
                tech_str = html.escape(str(tech))
                tech_rows.append(f"<tr><td><a href='{html.escape(url)}' target='_blank'>{html.escape(url)}</a></td><td><code>{tech_str}</code></td></tr>")
    tech_table_html = "".join(tech_rows) if tech_rows else "<tr><td colspan='2' class='empty-msg'>No technology fingerprints detected.</td></tr>"

    # Format Takeover HTML
    takeover_items = []
    if takeovers:
        for item in takeovers:
            if item:
                takeover_items.append(f"<div class='vuln-alert critical'><strong>Subdomain Takeover Alert:</strong><pre>{html.escape(str(item))}</pre></div>")
    takeover_html = "".join(takeover_items) if takeover_items else "<p class='empty-msg'>No subdomain takeover vulnerabilities detected.</p>"

    # AI Insights formatting
    ai_html = html.escape(ai_findings).replace("\n", "<br>")

    # Assemble complete HTML
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShadowScan AI Report - {target}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-main: #0b0f19;
            --bg-card: #151c2c;
            --bg-card-hover: #1e293b;
            --border-color: #1e293d;
            --primary: #38bdf8;
            --primary-glow: rgba(56, 189, 248, 0.2);
            --accent: #818cf8;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --danger: #f43f5e;
            --warning: #fbbf24;
            --success: #10b981;
        }}
        
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Inter', system-ui, sans-serif; background-color: var(--bg-main); color: var(--text-main); line-height: 1.6; padding: 24px; }}
        .container {{ max-width: 1300px; margin: 0 auto; }}
        
        /* Header */
        .header {{ text-align: center; padding: 30px 20px; background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 100%); border: 1px solid #312e81; border-radius: 16px; margin-bottom: 24px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5); }}
        .header h1 {{ font-size: 2.2rem; font-weight: 700; color: var(--primary); margin-bottom: 8px; letter-spacing: -0.5px; }}
        .header p {{ color: var(--text-muted); font-size: 0.95rem; }}
        .header p strong {{ color: var(--text-main); }}
        
        /* Stats Grid */
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }}
        .stat-card {{ background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 12px; padding: 20px; text-align: center; transition: transform 0.2s, border-color 0.2s; }}
        .stat-card:hover {{ transform: translateY(-2px); border-color: var(--primary); }}
        .stat-value {{ font-size: 2rem; font-weight: 700; color: var(--primary); line-height: 1.2; }}
        .stat-label {{ font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }}
        
        /* Section Cards */
        .card {{ background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 16px; padding: 24px; margin-bottom: 24px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }}
        .card h2 {{ font-size: 1.3rem; font-weight: 600; color: var(--primary); margin-bottom: 16px; border-bottom: 1px solid var(--border-color); padding-bottom: 10px; display: flex; align-items: center; justify-content: space-between; }}
        
        /* Screenshots Gallery */
        .gallery-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 20px; }}
        .shot-card {{ background: #0f172a; border: 1px solid var(--border-color); border-radius: 10px; overflow: hidden; transition: transform 0.2s, box-shadow 0.2s; }}
        .shot-card:hover {{ transform: translateY(-3px); box-shadow: 0 8px 20px var(--primary-glow); border-color: var(--primary); }}
        .shot-img-container {{ height: 170px; overflow: hidden; background: #020617; display: flex; align-items: center; justify-content: center; }}
        .shot-img {{ width: 100%; height: 100%; object-fit: cover; object-position: top; transition: transform 0.3s; }}
        .shot-card:hover .shot-img {{ transform: scale(1.03); }}
        .shot-info {{ padding: 12px 14px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; background: #1e293b; }}
        .shot-url {{ color: var(--primary); text-decoration: none; font-size: 0.85rem; font-weight: 500; }}
        .shot-url:hover {{ text-decoration: underline; }}
        .placeholder {{ color: var(--text-muted); font-size: 0.85rem; }}

        /* Tables & Lists */
        table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border-color); font-size: 0.9rem; }}
        th {{ background: #0f172a; color: var(--text-muted); font-weight: 600; }}
        tr:hover td {{ background: rgba(255,255,255,0.02); }}
        
        pre {{ background: #020617; color: #34d399; padding: 16px; border-radius: 8px; font-family: monospace; font-size: 0.85rem; overflow-x: auto; max-height: 350px; line-height: 1.5; border: 1px solid #1e293b; }}
        code {{ background: #020617; color: #38bdf8; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 0.85rem; }}
        
        /* Badges */
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 600; font-family: monospace; }}
        .port-badge {{ background: rgba(56, 189, 248, 0.15); color: var(--primary); border: 1px solid rgba(56, 189, 248, 0.3); margin-right: 4px; }}
        
        /* Vulnerability Alerts */
        .vuln-alert {{ background: rgba(244, 63, 94, 0.1); border: 1px solid var(--danger); border-radius: 8px; padding: 14px; margin-bottom: 12px; color: #fca5a5; }}
        .vuln-alert strong {{ color: var(--danger); }}
        .empty-msg {{ color: var(--text-muted); font-style: italic; font-size: 0.9rem; }}
        
        .footer {{ text-align: center; padding: 20px; color: var(--text-muted); font-size: 0.85rem; border-top: 1px solid var(--border-color); margin-top: 40px; }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>ShadowScan AI Reconnaissance Report</h1>
            <p>Target Domain: <strong>{target}</strong> | Generated on: <strong>{timestamp}</strong></p>
        </div>
        
        <!-- Metrics -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{total_subdomains}</div>
                <div class="stat-label">Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_live}</div>
                <div class="stat-label">Live Hosts</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_open_ports}</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_fuzz_endpoints}</div>
                <div class="stat-label">Fuzzed Endpoints</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_screenshots}</div>
                <div class="stat-label">Screenshots</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: {'var(--danger)' if total_takeovers > 0 else 'var(--success)'};">{total_takeovers}</div>
                <div class="stat-label">Takeover Risks</div>
            </div>
        </div>

        <!-- AI Insights -->
        <div class="card">
            <h2>🤖 AI Security Insights & Risk Assessment</h2>
            <div style="background: #0f172a; padding: 18px; border-radius: 8px; border: 1px solid var(--border-color); line-height: 1.7; font-size: 0.95rem;">
                {ai_html}
            </div>
        </div>

        <!-- Screenshot Gallery -->
        <div class="card">
            <h2>📸 Screenshot Gallery ({total_screenshots})</h2>
            <div class="gallery-grid">
                {screenshot_gallery_html}
            </div>
        </div>

        <!-- Fuzzing Endpoints -->
        <div class="card">
            <h2>🔍 Discovered Endpoints & Sensitive Files ({total_fuzz_endpoints})</h2>
            <table>
                <thead>
                    <tr><th>URL</th><th>Status</th></tr>
                </thead>
                <tbody>
                    {fuzz_table_html}
                </tbody>
            </table>
        </div>

        <!-- SSL Certificates -->
        <div class="card">
            <h2>🔒 SSL/TLS Certificate Audits</h2>
            <table>
                <thead>
                    <tr><th>Host</th><th>Issuer</th><th>TLS Version</th><th>Days to Expiration</th></tr>
                </thead>
                <tbody>
                    {ssl_table_html}
                </tbody>
            </table>
        </div>

        <!-- Open Ports -->
        <div class="card">
            <h2>🔌 Discovered Open Ports</h2>
            <table>
                <thead>
                    <tr><th>Host / Subdomain</th><th>Open Ports</th></tr>
                </thead>
                <tbody>
                    {ports_table_html}
                </tbody>
            </table>
        </div>

        <!-- Tech Stack -->
        <div class="card">
            <h2>💻 Technology Stack Fingerprints</h2>
            <table>
                <thead>
                    <tr><th>URL</th><th>Detected Stack</th></tr>
                </thead>
                <tbody>
                    {tech_table_html}
                </tbody>
            </table>
        </div>

        <!-- Subdomain Takeovers -->
        <div class="card">
            <h2>⚠️ Subdomain Takeover Vulnerability Audits</h2>
            {takeover_html}
        </div>

        <!-- Discovered Subdomains -->
        <div class="card">
            <h2>🌐 Discovered Subdomains ({total_subdomains})</h2>
            <pre>{"<br>".join(map(html.escape, subdomains)) if subdomains else "No subdomains found."}</pre>
        </div>

        <!-- Live HTTP Hosts -->
        <div class="card">
            <h2>🟢 Live HTTP/HTTPS Hosts ({total_live})</h2>
            <pre>{"<br>".join(map(html.escape, live_hosts)) if live_hosts else "No live hosts found."}</pre>
        </div>

        <div class="footer">
            Generated by <strong>ShadowScan AI</strong> — Automated Attack Surface Recon & Vulnerability Engine
        </div>
    </div>
</body>
</html>
"""
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[✔] HTML Report successfully generated at: {output_path}")
    except Exception as e:
        print(f"[X] Failed to generate HTML report: {e}")
