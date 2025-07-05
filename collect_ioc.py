import requests
import re
import json
from config import OTX_API_KEY

# Lấy dữ liệu từ AlienVault OTX
def fetch_otx_pulses():
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get("results", [])
    else:
        print(f"Error fetching OTX pulses: {response.status_code}")
        return []

# Hàm trích xuất IOC
def extract_ioc(text):
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    hash_pattern = r'\b[a-fA-F0-9]{32}\b'  # MD5 hash
    
    ips = re.findall(ip_pattern, text)
    urls = re.findall(url_pattern, text)
    hashes = re.findall(hash_pattern, text)
    return {"ips": ips, "urls": urls, "hashes": hashes}

# Thu thập và trích xuất IOC
pulses = fetch_otx_pulses()
iocs = {"ips": [], "urls": [], "hashes": []}

for pulse in pulses:
    # Lấy nội dung từ pulse (tên, mô tả, IOC)
    text = pulse.get("name", "") + " " + pulse.get("description", "")
    pulse_iocs = pulse.get("indicators", [])
    for ioc in pulse_iocs:
        text += " " + ioc.get("indicator", "")
    
    # Trích xuất IOC từ text
    extracted_iocs = extract_ioc(text)
    iocs["ips"].extend(extracted_iocs["ips"])
    iocs["urls"].extend(extracted_iocs["urls"])
    iocs["hashes"].extend(extracted_iocs["hashes"])

# Loại bỏ trùng lặp
iocs["ips"] = list(set(iocs["ips"]))
iocs["urls"] = list(set(iocs["urls"]))
iocs["hashes"] = list(set(iocs["hashes"]))

# Lưu IOC vào file JSON
with open("output/iocs.json", "w", encoding="utf-8") as f:
    json.dump(iocs, f, indent=4)
print("IOCs saved to output/iocs.json")
print(iocs)