import os
import sys
import shutil
import subprocess

def find_chrome_binary():
    """
    Locates the Chrome/Chromium/Edge binary across Windows, Linux (Kali/Ubuntu), VMs, and macOS.
    """
    # 1. System PATH lookups
    for binary_name in ['google-chrome', 'chromium', 'chromium-browser', 'chrome', 'google-chrome-stable']:
        path = shutil.which(binary_name)
        if path and os.path.isfile(path):
            return path
            
    # 2. Platform-specific common paths
    possible_paths = []
    
    if sys.platform == "win32":
        local_appdata = os.environ.get("LOCALAPPDATA", "")
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        
        possible_paths = [
            os.path.join(program_files, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(program_files_x86, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(local_appdata, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(program_files, "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(program_files_x86, "Microsoft", "Edge", "Application", "msedge.exe"),
        ]
    elif sys.platform.startswith("linux"):
        possible_paths = [
            "/usr/bin/google-chrome",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/google-chrome-stable",
            "/snap/bin/chromium",
        ]
    elif sys.platform == "darwin":
        possible_paths = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ]
        
    for path in possible_paths:
        if os.path.isfile(path):
            return path
            
    return None

def capture_screenshots(urls, output_dir):
    """
    Captures screenshots of live URLs using Chromium/Chrome via Selenium headless.
    Compatible with Windows, Kali Linux, Ubuntu, VMs, and macOS.
    """
    if not urls:
        print("[!] No live URLs provided for screenshotting.")
        return

    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
    except ImportError:
        print("[!] selenium not installed. Skipping screenshot phase. Install via 'pip install selenium'")
        return
    
    chrome_path = find_chrome_binary()
    if not chrome_path:
        print("[!] Chrome/Chromium browser not found on this system (Checked Windows, Linux/Kali/Ubuntu, macOS). Skipping screenshot capture.")
        return

    print(f"[*] Found browser binary at: {chrome_path}")
    os.makedirs(output_dir, exist_ok=True)
    
    chrome_options = Options()
    chrome_options.add_argument('--headless=new')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--ignore-certificate-errors')
    chrome_options.add_argument('--allow-insecure-localhost')
    chrome_options.add_argument('--window-size=1920,1080')
    chrome_options.binary_location = chrome_path
    
    print(f"[*] Capturing screenshots of {len(urls)} URLs...")
    driver = None
    try:
        driver = webdriver.Chrome(options=chrome_options)
    except Exception as e:
        # Fallback if setting explicit binary_location caused an issue with webdriver manager
        print(f"[!] Primary Webdriver init failed ({e}). Trying fallback without explicit binary location...")
        try:
            fallback_options = Options()
            fallback_options.add_argument('--headless=new')
            fallback_options.add_argument('--no-sandbox')
            fallback_options.add_argument('--disable-dev-shm-usage')
            fallback_options.add_argument('--ignore-certificate-errors')
            driver = webdriver.Chrome(options=fallback_options)
        except Exception as fallback_err:
            print(f"[X] Webdriver initialization failed completely: {fallback_err}")
            return

    try:
        for url in urls:
            try:
                # Ensure scheme
                target_url = url if url.startswith(('http://', 'https://')) else f"http://{url}"
                driver.set_page_load_timeout(15)
                driver.get(target_url)
                
                clean_name = target_url.replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')[:100]
                filename = f"{clean_name}.png"
                filepath = os.path.join(output_dir, filename)
                
                driver.save_screenshot(filepath)
                print(f"[✔] Screenshot saved: {filepath}")
            except Exception as e:
                print(f"[X] Failed screenshotting {url}: {e}")
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
