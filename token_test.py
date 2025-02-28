import requests
import pandas as pd
import time
import os
from collections import deque

# Load credentials from GitHub Actions secrets
CLIENT_ID = os.getenv("OPENVULN_CLIENT_ID")
CLIENT_SECRET = os.getenv("OPENVULN_CLIENT_SECRET")
TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"

# API rate limits
MAX_REQUESTS_PER_SECOND = 5
MAX_REQUESTS_PER_MINUTE = 30
request_timestamps = deque()

# List of possible OS types
os_types = ["asa", "fxos", "ftd", "ios", "iosxe", "nxos", "aci", "fmc"]

def enforce_rate_limit():
    """Ensure API requests comply with rate limits."""
    current_time = time.time()
    
    while request_timestamps and request_timestamps[0] < current_time - 60:
        request_timestamps.popleft()
    
    if len(request_timestamps) >= MAX_REQUESTS_PER_MINUTE:
        time.sleep(60 - (current_time - request_timestamps[0]))
    
    if len([t for t in request_timestamps if t > current_time - 1]) >= MAX_REQUESTS_PER_SECOND:
        time.sleep(1)
    
    request_timestamps.append(time.time())

def get_token():
    """Retrieve access token from Cisco API."""
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }
    
    enforce_rate_limit()
    response = requests.post(TOKEN_URL, headers=headers, data=data, timeout=30)
    response.raise_for_status()
    return response.json().get("access_token")

def fetch_advisories(version):
    """Check PSIRT advisories for a given software version."""
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    for os_type in os_types:
        url = f"https://apix.cisco.com/security/advisories/v2/OSType/{os_type}?version={version}"
        
        enforce_rate_limit()
        response = requests.get(url, headers=headers, timeout=30)
        print(f"Checking {os_type} for version {version} - Status: {response.status_code}")
        
        if response.status_code == 200:
            advisories = response.json().get("advisories", [])
            high_severity = sum(1 for adv in advisories if "High" in adv.get("sir", ""))
            critical_severity = sum(1 for adv in advisories if "Critical" in adv.get("sir", ""))
            
            if high_severity > 0 or critical_severity > 0:
                return high_severity, critical_severity  # Return first successful match
    
    return "Error", "Error"

def process_excel():
    """Read Excel file, check vulnerabilities, and update it."""
    file_path = "Baseline_albr_extract.xlsx"
    df = pd.read_excel(file_path)
    
    version_cache = {}
    psirt_high = []
    psirt_critical = []
    
    for index, row in df.iterrows():
        version = str(row["software_version"]).strip()
        
        if version:
            if version in version_cache:
                high, critical = version_cache[version]
            else:
                high, critical = fetch_advisories(version)
                version_cache[version] = (high, critical)
        else:
            high, critical = "Error", "Error"
        
        psirt_high.append(high)
        psirt_critical.append(critical)
    
    df["psirt_high"] = psirt_high
    df["psirt_critical"] = psirt_critical
    
    df.to_excel(file_path, index=False)
    print("✅ Excel file updated successfully!")

if __name__ == "__main__":
    process_excel()
