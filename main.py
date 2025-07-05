import os
import subprocess

# Đảm bảo thư mục output tồn tại
if not os.path.exists("output"):
    os.makedirs("output")

  # Chạy các bước
print("Step 1: Collecting IOCs from AlienVault OTX...")
subprocess.run(["python", "collect_ioc.py"], check=True)

print("Step 2: Enriching IOCs with VirusTotal and AbuseIPDB...")
subprocess.run(["python", "enrich_ioc.py"], check=True)

print("Step 3: Starting Streamlit dashboard...")
subprocess.run(["streamlit", "run", "dashboard.py"])