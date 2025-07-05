import requests
from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY

     # Kiểm tra VirusTotal API
vt_url = "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
vt_response = requests.get(vt_url, headers=vt_headers)
print("VirusTotal Response:", vt_response.json() if vt_response.status_code == 200 else vt_response.status_code)

     # Kiểm tra AbuseIPDB API
ab_url = "https://api.abuseipdb.com/api/v2/check"
ab_params = {"ipAddress": "8.8.8.8", "maxAgeInDays": 90}
ab_headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
ab_response = requests.get(ab_url, params=ab_params, headers=ab_headers)
print("AbuseIPDB Response:", ab_response.json() if ab_response.status_code == 200 else ab_response.status_code)