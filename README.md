# Threat Intelligence IOC Collector

This project builds an AI Agent to collect and enrich Indicators of Compromise (IOCs) from open sources (Twitter/X, VirusTotal, AbuseIPDB) for Cyber Threat Intelligence.

## Prerequisites
- Python 3.8 or higher
- API Keys: VirusTotal, AbuseIPDB, Twitter/X
- Install dependencies: `pip install -r requirements.txt`
- Install spaCy model: `python -m spacy download en_core_web_sm`

## Setup
1. Clone the repository:
   git clone https://github.com/<your-username>/ThreatIntelAgent.git
   cd ThreatIntelAgent

2. Create a virtual environment:
python -m venv venv
.\venv\Scripts\activate  # Windows

3. Install dependencies:
pip install -r requirements.txt
python -m spacy download en_core_web_sm

4. Create a config.py file from config_template.py and add your API Keys:
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key"
TWITTER_API_KEY = "your_twitter_api_key"
TWITTER_API_SECRET = "your_twitter_api_secret"
TWITTER_ACCESS_TOKEN = "your_twitter_access_token"
TWITTER_ACCESS_TOKEN_SECRET = "your_twitter_access_token_secret"

5. Run the main script:
python main.py

## Notes
Free API Keys have limits (VirusTotal: 500/day, AbuseIPDB: 1000/day).
Contact: <your-email> for issues.</your-email>