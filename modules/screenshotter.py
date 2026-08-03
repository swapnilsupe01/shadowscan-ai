import os
import shutil
import subprocess

def capture_screenshots(urls, output_dir):
    """
    Captures screenshots of live URLs using Chromium/Chrome via Selenium headless.
    """
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
    except ImportError:
        print("[!] selenium not installed. Skipping screenshot phase.")
        return
    
    chrome_path = shutil.which('google-chrome') or shutil.which('chromium') or shutil.which('chromium-browser')
    if not chrome_path:
        print("[!] Chromium browser not found. Skipping screenshot capture.")
        return

    os.makedirs(output_dir, exist_ok=True)
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.binary_location = chrome_path
    
    print(f"[*] Capturing screenshots of {len(urls)} URLs...")
    try:
        driver = webdriver.Chrome(options=chrome_options)
        for url in urls:
            try:
                driver.set_page_load_timeout(10)
                driver.get(url)
                filename = url.replace('https://', '').replace('http://', '').replace('/', '_')[:100] + ".png"
                filepath = os.path.join(output_dir, filename)
                driver.save_screenshot(filepath)
                print(f"[✔] Screenshot saved for {url}")
            except Exception as e:
                print(f"[X] Failed screenshotting {url}: {e}")
        driver.quit()
    except Exception as e:
        print(f"[X] Webdriver error: {e}")
