#!/bin/bash
# Installation script for ShadowScan AI dependencies on Kali Linux

echo "=========================================="
echo " Setting up ShadowScan AI Dependencies     "
echo "=========================================="

# Update system
sudo apt update -y

# Install system dependencies
sudo apt install -y python3-pip python3-venv subfinder testssl.sh chromium chromium-driver whatweb nuclei

# Install Python packages
pip3 install -r requirements.txt --break-system-packages

# Add subzy installation fallback instructions
echo "[*] Optionally download subzy from: https://github.com/LukaSikic/subzy"
echo "[✔] Dependencies setup complete. Run with: python3 shadowscan.py <domain>"
