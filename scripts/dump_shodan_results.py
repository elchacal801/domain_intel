import os
import csv
import shodan
from dotenv import load_dotenv

# Load env
load_dotenv()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

if not SHODAN_API_KEY:
    print("Error: SHODAN_API_KEY not found.")
    exit(1)

api = shodan.Shodan(SHODAN_API_KEY)

def check_api_plan():
    print("\n--- Shodan API Capabilities ---")
    try:
        info = api.info()
        print(f"Plan: {info.get('plan', 'n/a')}")
        print(f"Query Credits: {info.get('query_credits', 0)}")
        print(f"Scan Credits: {info.get('scan_credits', 0)}")
        print(f"HTTPS: {info.get('https', False)}")
        print(f"Telnet: {info.get('telnet', False)}")
        return info
    except shodan.APIError as e:
        print(f"Error checking API info: {e}")
        return None

def dump_search_results(queries, output_file):
    print(f"\n--- Dumping Results to {output_file} ---")
    
    unique_matches = {} # IP as key to dedup
    
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['query', 'ip_str', 'port', 'org', 'country', 'hostnames', 'os', 'isp', 'asn', 'domains', 'last_update'])
            
            for query in queries:
                print(f"Running query: {query}")
                try:
                    # Using search_cursor to get all results if needed, but standard search is safer for credits if results are huge. 
                    # Previous output showed ~100 total, so standard search is fine (returns 100 by default).
                    results = api.search(query, limit=1000) 
                    print(f"  Found {results['total']} matches.")
                    
                    for m in results['matches']:
                        ip = m['ip_str']
                        row = [
                            query,
                            ip,
                            m.get('port'),
                            m.get('org', ''),
                            m.get('location', {}).get('country_name', ''),
                            ';'.join(m.get('hostnames', [])),
                            m.get('os', ''),
                            m.get('isp', ''),
                            m.get('asn', ''),
                            ';'.join(m.get('domains', [])),
                            m.get('timestamp', '')
                        ]
                        writer.writerow(row)
                        
                except shodan.APIError as e:
                    print(f"  Error with query '{query}': {e}")

        print(f"Done. Saved to {output_file}")

    except Exception as e:
        print(f"File Error: {e}")

def main():
    check_api_plan()
    
    queries = [
        'http.title:"Disposable Email"',
        'http.title:"Disposable Temporary Email"',
        'http.title:"Disposable Emails"', 
        'http.title:"Temporary Email"',
        'http.title:"Temporary Emails"',
        'http.title:"disposable and free domain"'
    ]
    
    output_csv = "data/shodan_disposable_email_hunt.csv"
    dump_search_results(queries, output_csv)

if __name__ == "__main__":
    main()
