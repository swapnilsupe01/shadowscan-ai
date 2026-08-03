import urllib.request
import json

def analyze_vulnerabilities(recon_data, model_name="llama3"):
    """
    Sends findings to local Ollama LLM for intelligent security analysis.
    """
    print(f"[*] Sending reconnaissance findings to Ollama LLM ({model_name}) for security analysis...")
    
    prompt = (
        f"Analyze the following reconnaissance results for security vulnerabilities. "
        f"Suggest potential risks, remediation steps, and prioritized fix list:\n\n"
        f"JSON Findings:\n{json.dumps(recon_data, indent=2)}\n\n"
        f"Provide your analysis in clean Markdown structure."
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
        with urllib.request.urlopen(req, timeout=60) as response:
            res = json.loads(response.read().decode('utf-8'))
            analysis = res.get('response', '')
            print("[✔] AI Analysis completed.")
            return analysis
    except Exception as e:
        print(f"[X] AI Analysis failed: {e}")
        print("[!] Ensure Ollama is running and has the model installed (e.g. `ollama run llama3`).")
        return "AI analysis unavailable (Ollama connection error)."
