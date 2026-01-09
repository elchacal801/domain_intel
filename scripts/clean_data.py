import csv
import os
import glob
import re

DATA_DIR = "data"

def clean_asn_value(value):
    """
    Standardizes ASN value to integer string for consistent mapping.
    Removes 'AS' prefix and handles doubled values.
    """
    value = str(value).strip().upper()
    if not value:
        return ""
    
    # Handle "12345 67890" or "12345,67890" -> take first
    parts = re.split(r'[\s,]+', value)
    first_part = parts[0] if parts else ""
    
    # Strip "AS" prefix if present for normalization
    if first_part.startswith("AS"):
        return first_part[2:]
    return first_part

def get_column_name(headers, candidates):
    """
    Finds the actual column name from a list of candidates.
    Returns the first match or None.
    """
    for h in headers:
        if h.lower() in candidates:
            return h
    return None

def build_asn_map(files):
    """
    Scans all files to build a mapping of Normalized ASN -> ASN Name.
    Prioritizes non-empty names.
    """
    asn_map = {}
    print("Building ASN Name map...")
    count = 0
    for file_path in files:
        with open(file_path, 'r', encoding='utf-8-sig', errors='replace') as f:
            try:
                reader = csv.DictReader(f)
                if not reader.fieldnames:
                    continue
                
                asn_col = get_column_name(reader.fieldnames, ['asn', 'asn_number'])
                name_col = get_column_name(reader.fieldnames, ['asn_name', 'name'])
                
                if not asn_col or not name_col:
                    continue
                
                for row in reader:
                    normalized_asn = clean_asn_value(row.get(asn_col, ''))
                    name = row.get(name_col, '').strip()
                    
                    if normalized_asn and name:
                        asn_map[normalized_asn] = name
                        count += 1
            except Exception as e:
                print(f"Error reading {os.path.basename(file_path)} for map: {e}")
    
    print(f"Found {len(asn_map)} unique ASN names from {count} records.")
    return asn_map

def extract_service_from_name(name):
    """
    Heuristic to extract a Service name from the ASN Name description.
    """
    if not name:
        return ""
    # Remove quotes if present
    name = name.strip('"').strip()
    
    # Split by comma or space
    parts = re.split(r'[, ]+', name)
    if parts:
        candidate = parts[0]
        # Cleanup "AS-" prefix from service name if present e.g. "AS-VULTR" -> "VULTR"
        if candidate.upper().startswith("AS-") and len(candidate) > 3:
            return candidate[3:]
        # "HETZNER-AS" -> "HETZNER"
        if candidate.upper().endswith("-AS") and len(candidate) > 3:
            return candidate[:-3]
        return candidate
    return ""

def process_files(files, asn_map):
    for file_path in files:
        filename = os.path.basename(file_path)
        print(f"Processing {filename}...")
        
        fixed_rows = []
        headers = []
        modified_count = 0
        added_columns = []
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig', errors='replace') as f:
                reader = csv.DictReader(f)
                original_headers = reader.fieldnames
                
                if not original_headers:
                    continue
                
                headers = list(original_headers)
                
                asn_col = get_column_name(headers, ['asn', 'asn_number'])
                name_col = get_column_name(headers, ['asn_name', 'name'])
                
                if not asn_col:
                    print(f"  Skipping {filename}: no 'asn' column found. Headers: {headers}")
                    continue
                
                # Check for missing Name column and add if needed
                if not name_col:
                    print(f"  Adding missing 'Name' column to {filename}")
                    name_col = 'Name'
                    # Insert after ASN column if possible
                    try:
                        idx = headers.index(asn_col)
                        headers.insert(idx + 1, name_col)
                    except:
                        headers.append(name_col)
                        
                    added_columns.append(name_col)
                    modified_count += 1 
                
                # Special handling for vpn_asns.csv: Add 'Service' column if missing
                service_col = None
                if filename == 'vpn_asns.csv':
                    service_col = get_column_name(headers, ['service', 'service_name'])
                    if not service_col:
                        print(f"  Adding missing 'Service' column to {filename}")
                        service_col = 'Service'
                        headers.append(service_col)
                        added_columns.append(service_col)
                        modified_count += 1

                for row in reader:
                    original_asn_val = row.get(asn_col, '')
                    
                    # 1. Fix Doubled ASN
                    match = re.search(r'^([a-zA-Z0-9]+)[\s,]+', original_asn_val)
                    if match:
                        new_asn_val = match.group(1)
                        if new_asn_val != original_asn_val:
                            row[asn_col] = new_asn_val
                            modified_count += 1
                            original_asn_val = new_asn_val 
                    
                    # 2. Fix Missing Name (or populate new Name column)
                    current_name = row.get(name_col, '').strip() if name_col in row else ''
                    normalized_asn = clean_asn_value(original_asn_val)
                    
                    if not current_name:
                        if normalized_asn in asn_map:
                            row[name_col] = asn_map[normalized_asn]
                            current_name = asn_map[normalized_asn]
                            modified_count += 1
                    
                    # 3. Populate Service Column (vpn_asns.csv)
                    if service_col:
                        current_service = row.get(service_col, '').strip() if service_col in row else ''
                        if not current_service and current_name:
                            extracted_service = extract_service_from_name(current_name)
                            if extracted_service:
                                row[service_col] = extracted_service
                                modified_count += 1
                    
                    # Ensure all headers are keys in row (for new columns)
                    for col in added_columns:
                        if col not in row:
                            row[col] = ''
                            
                    fixed_rows.append(row)
                    
        except Exception as e:
            print(f"Error processing {filename}: {e}")
            continue
            
        if modified_count > 0:
            print(f"  {modified_count} modifications in {filename}. Saving...")
            try:
                with open(file_path, 'w', encoding='utf-8', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=headers)
                    writer.writeheader()
                    writer.writerows(fixed_rows)
            except Exception as e:
                print(f"Error writing {filename}: {e}")
        else:
            print(f"  No changes needed for {filename}.")

def main():
    files = glob.glob(os.path.join(DATA_DIR, "*.csv"))
    if not files:
        print("No CSV files found.")
        return

    asn_map = build_asn_map(files)
    process_files(files, asn_map)
    print("\nDone.")

if __name__ == "__main__":
    main()
