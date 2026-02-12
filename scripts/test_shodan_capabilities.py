import os
import shodan
from dotenv import load_dotenv

load_dotenv()
api = shodan.Shodan(os.getenv('SHODAN_API_KEY'))

def test_feature(name, func):
    print(f"\nTesting {name}...")
    try:
        func()
        print(f"  [SUCCESS] Access Granted.")
    except shodan.APIError as e:
        print(f"  [FAILED] Access Denied or Error: {e}")
    except Exception as e:
        print(f"  [ERROR] Unexpected: {e}")

def main():
    print("--- Shodan Capability Test ---")

    # 1. Base Plan Info
    try:
        info = api.info()
        print(f"Plan Type: {info.get('plan', 'Unknown')}")
        print(f"HTTPS/Telnet Access: {info.get('https')}/{info.get('telnet')}")
    except:
        print("Could not fetch plan info.")

    # 2. Standard Search
    test_feature("Standard Search (port:80)", lambda: api.search("port:80", limit=1))

    # 3. Vuln Filter (Often blocked on Basic)
    test_feature("Vulnerability Filter (vuln:CVE-2019-0708)", lambda: api.search("vuln:CVE-2019-0708", limit=1))

    # 4. Tag Filter
    test_feature("Tag Filter (tag:ics)", lambda: api.search("tag:ics", limit=1))

    # 5. Facets (Stats)
    test_feature("Facets (Summing countries)", lambda: api.count("port:80", facets=[('country', 5)]))

    # 6. Host Lookup
    test_feature("Host Lookup (8.8.8.8)", lambda: api.host("8.8.8.8"))

    # 7. SSL Filters
    test_feature("SSL Filters (ssl.cert.subject.cn)", lambda: api.search("ssl.cert.subject.cn:google.com", limit=1))

if __name__ == "__main__":
    main()
