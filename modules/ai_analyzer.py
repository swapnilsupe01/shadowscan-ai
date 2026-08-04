import urllib.request
import json

def _check_ollama_running():
    """Quick health check — fail fast if Ollama isn't running."""
    try:
        req = urllib.request.Request("http://localhost:11434/api/tags")
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status == 200
    except Exception:
        return False

def _summarize_recon_data(recon_data):
    """
    Create a compact summary of recon data for the LLM.
    Sending the full JSON causes timeouts — the LLM processes less data faster.
    """
    summary_parts = []
    
    target = recon_data.get("target", "Unknown")
    summary_parts.append(f"Target: {target}")
    
    # Subdomains — just count and list first 20
    subs = recon_data.get("subdomains", [])
    summary_parts.append(f"\nSubdomains found: {len(subs)}")
    if subs:
        summary_parts.append("Top subdomains: " + ", ".join(subs[:20]))
    
    # Live hosts
    live = recon_data.get("live_hosts", [])
    summary_parts.append(f"\nLive hosts: {len(live)}")
    if live:
        summary_parts.append("Live URLs: " + ", ".join(live[:15]))
    
    # Open ports — include all, this is critical for security
    ports = recon_data.get("open_ports", {})
    if ports:
        summary_parts.append("\nOpen Ports:")
        for host, port_list in ports.items():
            if port_list:
                summary_parts.append(f"  {host}: {', '.join(map(str, port_list))}")
    
    # Technologies
    techs = recon_data.get("technologies", {})
    if techs:
        summary_parts.append("\nTechnologies Detected:")
        for url, tech_list in techs.items():
            if tech_list:
                # Truncate long whatweb output
                tech_str = str(tech_list)[:200]
                summary_parts.append(f"  {url}: {tech_str}")
    
    # DNS records — just key ones
    dns = recon_data.get("dns_records", {})
    if dns:
        summary_parts.append("\nDNS Records:")
        for domain, records in list(dns.items())[:5]:
            important = {}
            for rtype in ["A", "MX", "CNAME", "NS"]:
                if records.get(rtype):
                    important[rtype] = records[rtype]
            if important:
                summary_parts.append(f"  {domain}: {json.dumps(important)}")
    
    return "\n".join(summary_parts)

def analyze_vulnerabilities(recon_data, model_name="llama3.1:8b"):
    """
    Sends findings to local Ollama LLM for intelligent security analysis.
    """
    # Step 1: Check if Ollama is even running
    print(f"[*] Checking Ollama connection...")
    if not _check_ollama_running():
        print("[X] Ollama is not running or not reachable at localhost:11434")
        print("[!] Start Ollama with: ollama serve")
        print("[!] Or skip AI analysis with: --no-ai flag")
        return "AI analysis unavailable — Ollama is not running."
    
    print(f"[✔] Ollama is running. Using model: {model_name}")
    print(f"[*] Preparing summarized findings for LLM analysis...")
    
    # Step 2: Create a compact summary instead of dumping full JSON
    summary = _summarize_recon_data(recon_data)
    
    prompt = (
        f"You are a cybersecurity expert. Analyze the following reconnaissance results "
        f"and provide a security assessment.\n\n"
        f"Reconnaissance Summary:\n{summary}\n\n"
        f"Provide:\n"
        f"1. Risk Assessment (Critical/High/Medium/Low findings)\n"
        f"2. Key vulnerabilities identified\n"
        f"3. Prioritized remediation steps\n"
        f"4. Security recommendations\n\n"
        f"Keep your response concise and actionable. Use Markdown formatting."
    )
    
    payload = {
        "model": model_name,
        "prompt": prompt,
        "stream": False
    }
    
    url = "http://localhost:11434/api/generate"
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
        print(f"[*] Waiting for LLM response (this may take 1-3 minutes)...")
        with urllib.request.urlopen(req, timeout=300) as response:
            res = json.loads(response.read().decode('utf-8'))
            analysis = res.get('response', '')
            print("[✔] AI Analysis completed successfully.")
            return analysis
    except urllib.error.URLError as e:
        print(f"[X] AI Analysis failed: {e}")
        print("[!] Ensure Ollama is running and has the model installed.")
        print(f"[!] Install model with: ollama pull {model_name}")
        return "AI analysis unavailable (Ollama connection error)."
    except Exception as e:
        error_msg = str(e)
        if "timed out" in error_msg:
            print(f"[X] AI Analysis timed out after 300 seconds.")
            print("[!] Your system may not have enough RAM/CPU for this model.")
            print("[!] Try a smaller model: python3 shadowscan.py target --ai-model phi3")
        else:
            print(f"[X] AI Analysis failed: {e}")
        return f"AI analysis unavailable ({error_msg})."
