import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

TARGET_IP = "51.254.35.55" # Known to have 7,000+ domains

def test_otx():
    print("\n--- Testing AlienVault OTX (Passive DNS) ---")
    key = os.getenv("ALIENVAULT_OTX_API_KEY")
    if not key:
        print("Skipping: No API Key")
        return

    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{TARGET_IP}/passive_dns"
    headers = {"X-OTX-API-KEY": key}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            count = data.get('count', 0)
            print(f"Success! Found {count} passive DNS records.")
            if count > 0:
                print(f"Sample: {data['passive_dns'][0].get('hostname')}")
        else:
            print(f"Failed: HTTP {r.status_code} - {r.text[:100]}")
    except Exception as e:
        print(f"Error: {e}")

def test_whoisxml_reverse():
    print("\n--- Testing WhoisXML (Reverse IP) ---")
    key = os.getenv("WHOISXML_API_KEY")
    if not key:
        print("Skipping: No API Key")
        return
        
    # Endpoint for Reverse IP
    url = "https://reverse-ip.whoisxmlapi.com/api/v1"
    params = {
        "apiKey": key,
        "ip": TARGET_IP,
        "outputFormat": "json"
    }
    
    try:
        r = requests.get(url, params=params, timeout=10)
        if r.status_code == 200:
            data = r.json()
            # The structure usually has 'unique' count or 'result' list
            count = data.get('size', 0)
            if 'result' in data:
                count = len(data['result'])
            print(f"Success! Found {count} domains.")
            if count > 0:
                 # Check first item structure
                 sample = data['result'][0] if 'result' in data and data['result'] else "N/A"
                 print(f"Sample: {sample.get('name') if isinstance(sample, dict) else sample}")
        else:
             print(f"Failed: HTTP {r.status_code} - {r.text[:100]}")
    except Exception as e:
        print(f"Error: {e}")

def test_hackertarget():
    print("\n--- Testing HackerTarget (Free API) ---")
    url = f"https://api.hackertarget.com/reverseiplookup/?q={TARGET_IP}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            lines = r.text.split('\n')
            print(f"Success! Found {len(lines)} records.")
            if len(lines) > 0:
                print(f"Sample: {lines[0]}")
        else:
            print(f"Failed: HTTP {r.status_code}")
    except Exception as e:
        print(f"Error: {e}")

def main():
    print(f"Testing PADNS capabilities for IP: {TARGET_IP}")
    test_otx()
    test_whoisxml_reverse()
    test_hackertarget()

if __name__ == "__main__":
    main()
