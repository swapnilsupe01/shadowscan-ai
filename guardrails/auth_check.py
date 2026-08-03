import os
import sys

def check_authorization(target):
    """
    Guardrail to ensure scanning is authorized.
    Checks if a target falls within allowed bounds or gets explicit user confirmation.
    """
    print(f"\n[!] SECURITY GUARDRAIL: Authorization Check for target: {target}")
    
    # Check if target is a loopback or private address, which might be allowed or need caution
    if "127.0.0.1" in target or "localhost" in target:
        print("[!] Warning: You are targeting localhost/loopback.")
    
    confirm = input(f"[?] Are you explicitly authorized to perform security reconnaissance on '{target}'? (y/N): ").strip().lower()
    if confirm != 'y':
        print("[X] Execution aborted: Unauthorized scanning is strictly prohibited.")
        sys.exit(1)
    
    print("[✔] Authorization confirmed. Proceeding...\n")
    return True
