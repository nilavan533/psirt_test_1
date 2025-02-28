import os
import requests

def get_token():
    """Generate an OAuth2 access token from Cisco's API using GitHub Secrets."""
    CLIENT_ID = os.getenv("OPENVULN_CLIENT_ID")
    CLIENT_SECRET = os.getenv("OPENVULN_CLIENT_SECRET")
    TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"

    if not CLIENT_ID or not CLIENT_SECRET:
        print("❌ ERROR: Missing API credentials. Check GitHub Secrets.")
        return None

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }

    response = requests.post(TOKEN_URL, headers=headers, data=data, timeout=30)

    if response.status_code == 200:
        print("✅ Token generated successfully!")
        return response.json().get("access_token")
    else:
        print(f"❌ TOKEN GENERATION FAILED! (Status Code: {response.status_code})")
        print(f"🔹 RESPONSE TEXT: {response.text}")
        return None

if __name__ == "__main__":
    token = get_token()
    if token:
        print("🔹 ACCESS TOKEN:", token[:20] + "...")  # Print only part of the token for security
