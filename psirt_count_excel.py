import requests
import pandas as pd
import time
from collections import deque

# List of possible OS types to try
os_types = ["asa", "fxos", "ftd", "ios", "iosxe", "nxos", "aci", "fmc"]

# API rate limits
MAX_REQUESTS_PER_SECOND = 5
MAX_REQUESTS_PER_MINUTE = 30

# Request tracking
request_timestamps = deque()

def enforce_rate_limit():
    current_time = time.time()
    
    # Remove timestamps older than a minute
    while request_timestamps and request_timestamps[0] < current_time - 60:
        request_timestamps.popleft()
    
    # Enforce per-minute limit
    if len(request_timestamps) >= MAX_REQUESTS_PER_MINUTE:
        time.sleep(60 - (current_time - request_timestamps[0]))
    
    # Enforce per-second limit
    second_requests = [t for t in request_timestamps if t > current_time - 1]
    if len(second_requests) >= MAX_REQUESTS_PER_SECOND:
        time.sleep(1)
    
    request_timestamps.append(time.time())

def get_token():
    CLIENT_ID = "ve76j4vtz6p3sa94s2pv6fyd"
    CLIENT_SECRET = "MAGsTGkub77u5jt7WRJBxfTq"
    TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
    
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }
    
    enforce_rate_limit()
    response = requests.post(TOKEN_URL, headers=headers, data=data, timeout=30)  # Increased timeout
    response.raise_for_status()
    return response.json().get("access_token")

def fetch_advisories(version):
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    for os_type in os_types:
        base_url = f"https://apix.cisco.com/security/advisories/v2/OSType/{os_type}?version={version}"
        
        enforce_rate_limit()
        response = requests.get(base_url, headers=headers, timeout=30)  # Increased timeout
        print(f"Checking {os_type} for version {version} - Status Code: {response.status_code}")
        
        if response.status_code == 200:
            advisories = response.json().get("advisories", [])
            high_severity = sum(1 for adv in advisories if "High" in adv.get("sir", ""))
            critical_severity = sum(1 for adv in advisories if "Critical" in adv.get("sir", ""))
            
            if high_severity > 0 or critical_severity > 0:
                return high_severity, critical_severity  # Return first successful match
    
    return "Error", "Error"

def process_excel():
    file_path = "C:\\Users\\vezhilnilavan\\Desktop\\git project\\Baseline_albr_extract.xlsx"
    df = pd.read_excel(file_path)
    
    version_cache = {}  # Cache to avoid redundant API calls
    psirt_high = []
    psirt_critical = []
    
    for index, row in df.iterrows():
        cleaned_version = str(row["software_version"]).strip()
        
        if cleaned_version:
            if cleaned_version in version_cache:
                high, critical = version_cache[cleaned_version]
            else:
                high, critical = fetch_advisories(cleaned_version)
                version_cache[cleaned_version] = (high, critical)
        else:
            high, critical = "Error", "Error"
        
        psirt_high.append(high)
        psirt_critical.append(critical)
    
    df["psirt_high"] = psirt_high
    df["psirt_critical"] = psirt_critical
    
    df.to_excel(file_path, index=False)
    print("Updated Excel file saved successfully!")

if __name__ == "__main__":
    process_excel()
 