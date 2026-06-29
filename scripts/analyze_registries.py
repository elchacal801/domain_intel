import csv
import collections
import sys

input_file = "data/dea_domains_probed.csv"
counts = collections.Counter()

try:
    with open(input_file, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            reg = row.get("registry", "").strip()
            if reg:
                counts[reg] += 1
            
    print(f"Total entries with registry data: {sum(counts.values())}")
    print("\nTop 20 Registries:")
    for reg, count in counts.most_common(20):
        print(f"{reg}: {count}")

except Exception as e:
    print(f"Error: {e}")
