import os

def generate_html_report(recon_data, ai_findings, output_path):
    """
    Generates a structured HTML report combining scan findings and AI recommendations.
    """
    print(f"[*] Generating final HTML report at {output_path}...")
    
    # Simple CSS design
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>ShadowScan AI Recon Report - {recon_data.get('target', 'Target')}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #f1f5f9; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: auto; }}
        h1, h2, h3 {{ color: #38bdf8; }}
        .card {{ background-color: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }}
        pre {{ background-color: #020617; padding: 15px; border-radius: 4px; overflow-x: auto; color: #34d399; }}
        .header {{ text-align: center; border-bottom: 2px solid #38bdf8; padding-bottom: 20px; margin-bottom: 30px; }}
        .badge {{ background-color: #ef4444; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ShadowScan AI Reconnaissance Report</h1>
            <p>Target: <strong>{recon_data.get('target')}</strong> | Scanned on: {recon_data.get('last_updated')}</p>
        </div>
        
        <div class="card">
            <h2>AI Security Insights & Recommendations</h2>
            <div>{ai_findings.replace("\n", "<br>")}</div>
        </div>

        <div class="card">
            <h2>Discovered Subdomains ({len(recon_data.get('subdomains', []))})</h2>
            <pre>{chr(10).join(recon_data.get('subdomains', []))}</pre>
        </div>

        <div class="card">
            <h2>Live HTTP/HTTPS Hosts ({len(recon_data.get('live_hosts', []))})</h2>
            <pre>{chr(10).join(recon_data.get('live_hosts', []))}</pre>
        </div>
    </div>
</body>
</html>
"""
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[✔] Report generated successfully.")
    except Exception as e:
        print(f"[X] Failed to generate HTML report: {e}")
