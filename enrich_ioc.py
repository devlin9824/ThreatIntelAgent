import requests
import json
import pandas as pd
from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY


# Hàm làm giàu IP qua VirusTotal
def enrich_ip_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return {
                "ip": ip,
                "vt_reputation": data["data"]["attributes"].get("reputation", 0),
                "vt_country": data["data"]["attributes"].get("country", "Unknown"),
                "vt_last_analysis": data["data"]["attributes"].get("last_analysis_stats", {})
            }
        else:
            return {"ip": ip, "error": f"VirusTotal error: {response.status_code}"}
    except Exception as e:
        return {"ip": ip, "error": f"VirusTotal exception: {str(e)}"}


# Hàm làm giàu IP qua AbuseIPDB
def enrich_ip_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    try:
        response = requests.get(url, params=params, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return {
                "ip": ip,
                "ab_confidence": data["data"].get("abuseConfidenceScore", 0),
                "ab_country": data["data"].get("countryCode", "Unknown"),
                "ab_reports": data["data"].get("totalReports", 0)
            }
        else:
            return {"ip": ip, "error": f"AbuseIPDB error: {response.status_code}"}
    except Exception as e:
        return {"ip": ip, "error": f"AbuseIPDB exception: {str(e)}"}


# Hàm làm giàu IOC (chỉ xử lý IP trong ví dụ này)
def enrich_ioc(ip):
    vt_result = enrich_ip_virustotal(ip)
    ab_result = enrich_ip_abuseipdb(ip)
    return {
        "ip": ip,
        "vt_reputation": vt_result.get("vt_reputation", "N/A"),
        "vt_country": vt_result.get("vt_country", "N/A"),
        "vt_last_analysis": vt_result.get("vt_last_analysis", "N/A"),
        "ab_confidence": ab_result.get("ab_confidence", "N/A"),
        "ab_country": ab_result.get("ab_country", "N/A"),
        "ab_reports": ab_result.get("ab_reports", "N/A")
    }


# Đọc IOC từ file
with open("output/iocs.json", "r", encoding="utf-8") as f:
    iocs = json.load(f)

# Làm giàu tất cả IP
enriched_iocs = [enrich_ioc(ip) for ip in iocs.get("ips", [])]

# Lưu kết quả vào CSV
df = pd.DataFrame(enriched_iocs)
df.to_csv("output/enriched_iocs.csv", index=False)
print("Enriched IOCs saved to output/enriched_iocs.csv")
print(df)
