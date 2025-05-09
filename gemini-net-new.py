# The following script will take two Clair scans as input (.csv format) and compare them to determine 
# remediated CVEs versus new CVEs between the two scans.

import csv
import sys
import os
from datetime import datetime

def parse_clair_report(report_path):
    """
    Parses a Clair CSV report and extracts unique vulnerability instances
    mapped to their severity.
    Expects headers: 'image', 'vulnerability', 'packageName', 'severity'. <--- Corrected case
    Returns a dictionary: {(image, cve, pkg): severity, ...}
    """
    # 1. Entry Point Debug
    print(f"Debug: ==> Entered parse_clair_report for: '{os.path.basename(report_path)}'")
    # Initialize as dictionary instead of set
    vulnerability_details = {}

    # 2. Pre-Check Debug
    if not report_path:
         print(f"Debug: Path is empty, returning empty dict.", file=sys.stderr)
         return vulnerability_details
    print(f"Debug: Path is not empty.")
    if not os.path.exists(report_path):
        print(f"Error: File not found via os.path.exists: '{report_path}'. Returning empty dict.", file=sys.stderr)
        print(f"Debug: <== Exiting parse_clair_report (file not found) for: '{os.path.basename(report_path)}'")
        return vulnerability_details
    print(f"Debug: File exists via os.path.exists.")

    reader = None

    try:
        # 3. Before File Open Debug
        print(f"Debug: Attempting to open file '{os.path.basename(report_path)}'...")
        with open(report_path, 'r', newline='', encoding='utf-8', errors='ignore') as csvfile:
            # 4. After File Open / Before Reader Debug
            print(f"Debug: File '{os.path.basename(report_path)}' opened successfully. Attempting csv.DictReader...")
            reader = csv.DictReader(csvfile)
            # 5. After Reader / Headers Debug
            print(f"Debug: csv.DictReader created. Headers found: {reader.fieldnames}")

            if reader.fieldnames is None:
                print(f"Error: Could not read headers from CSV file '{report_path}'. Is the file empty or corrupted?", file=sys.stderr)
                print(f"Debug: <== Exiting parse_clair_report (no headers) for: '{os.path.basename(report_path)}'")
                return vulnerability_details

            # --- CHANGE 1: Corrected required header list ---
            required_headers = ['image', 'vulnerability', 'packageName', 'severity'] # Lowercase 's'
            # ---------------------------------------------------
            if not all(header in reader.fieldnames for header in required_headers):
                 # This error should now only trigger if 'image', 'vulnerability', or 'packageName' are missing
                 print(f"Error: CSV file '{os.path.basename(report_path)}' missing one or more required headers: {required_headers}. Found headers: {reader.fieldnames}", file=sys.stderr)
                 print(f"Debug: <== Exiting parse_clair_report (missing headers) for: '{os.path.basename(report_path)}'")
                 return vulnerability_details

            # 7. Before Loop Debug
            print(f"Debug: Headers look OK. Starting row processing for '{os.path.basename(report_path)}'...")
            processed_rows = 0
            added_vulns = 0
            for row_num, row in enumerate(reader, start=2):
                processed_rows += 1
                image_identifier = row.get('image')
                cve_id = row.get('vulnerability')
                package_name = row.get('packageName')
                # --- CHANGE 2: Use lowercase 'severity' to get value ---
                severity = row.get('severity') # Lowercase 's'
                # -------------------------------------------------------

                if image_identifier and cve_id and package_name:
                    # If severity is missing or blank, default to 'Unknown'
                    severity_val = severity.strip() if severity and severity.strip() else 'Unknown'
                    # Create the key tuple
                    key = (image_identifier.strip(), cve_id.strip(), package_name.strip())
                    # Add to dictionary {key: severity}
                    vulnerability_details[key] = severity_val
                    added_vulns += 1
                # else: # Optional warning for rows missing core data
                    # print(f"Warning: Skipping row {row_num} in '{os.path.basename(report_path)}' due to missing image/cve/package.", file=sys.stderr)


            # 8. After Loop Debug (Counts entries added to dict)
            print(f"Debug: Finished row processing for '{os.path.basename(report_path)}'. Processed={processed_rows}, Added={added_vulns} unique vulnerabilities.")

    except FileNotFoundError:
        print(f"Debug: Caught FileNotFoundError inside try block (unexpected).", file=sys.stderr)
        print(f"Error: File not found at {report_path} (unexpected).", file=sys.stderr)
    except csv.Error as e:
         line_num_str = f" around line {reader.line_num}" if reader and hasattr(reader, 'line_num') else ""
         print(f"Debug: Caught csv.Error inside try block.", file=sys.stderr)
         print(f"Error reading CSV file {report_path}{line_num_str}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"Debug: Caught generic Exception inside try block: {type(e).__name__}", file=sys.stderr)
        print(f"An unexpected error occurred while parsing {report_path}: {e}", file=sys.stderr)

    # 9. Final Exit Debug (Returns length of dict)
    print(f"Debug: <== Exiting parse_clair_report (normal exit) for: '{os.path.basename(report_path)}'. Returning details for {len(vulnerability_details)} items.")
    # Return the dictionary
    return vulnerability_details


# --- compare_scans function handling Severity ---
def compare_scans(report_a_path, report_b_path):
    """
    Compares two Clair scan reports (dictionaries mapping vuln tuple to severity),
    prints summary (incl. severity) to terminal, and writes detailed results to CSV.
    """
    file_a_name = os.path.basename(report_a_path) if report_a_path else "[Invalid Path A]"
    file_b_name = os.path.basename(report_b_path) if report_b_path else "[Invalid Path B]"

    print(f"\nAttempting to compare '{file_a_name}' and '{file_b_name}'...")

    # Receive dictionaries instead of sets
    details_a = parse_clair_report(report_a_path)
    details_b = parse_clair_report(report_b_path)

    # Get keys (the unique tuples) for comparison
    keys_a = details_a.keys()
    keys_b = details_b.keys()

    # Calculate differences based on keys
    remediated_keys = keys_a - keys_b
    new_keys = keys_b - keys_a

    # --- Write detailed results to CSV file ---
    csv_filename = None
    # Check existence again before trying to write (parsing might have failed above but reported empty)
    if report_a_path and report_b_path and os.path.exists(report_a_path) and os.path.exists(report_b_path):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_a_name = file_a_name.replace('.csv','').replace('.','_').replace(' ','_').replace('(','').replace(')','')
        safe_b_name = file_b_name.replace('.csv','').replace('.','_').replace(' ','_').replace('(','').replace(')','')
        csv_filename = f"comparison_{safe_a_name}_vs_{safe_b_name}_{timestamp}.csv"
        if len(csv_filename) > 150:
             csv_filename = f"vulnerability_comparison_{timestamp}.csv"

        print(f"\nAttempting to write detailed results to '{csv_filename}'...")
        try:
            with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                # Add Severity to CSV Header
                writer.writerow(['Status', 'Image', 'CVE', 'Package', 'Severity'])

                # Write Remediated
                print(f"Debug: Writing {len(remediated_keys)} remediated items to CSV...")
                # Iterate through remediated keys, lookup severity in details_a
                for key in sorted(list(remediated_keys)):
                    img, cve, pkg = key
                    severity = details_a.get(key, 'Unknown') # Get severity from dict A
                    writer.writerow(['Remediated', img, cve, pkg, severity])

                # Write New
                print(f"Debug: Writing {len(new_keys)} new items to CSV...")
                # Iterate through new keys, lookup severity in details_b
                for key in sorted(list(new_keys)):
                    img, cve, pkg = key
                    severity = details_b.get(key, 'Unknown') # Get severity from dict B
                    writer.writerow(['New', img, cve, pkg, severity])

            print(f"Successfully wrote results to '{csv_filename}'.")
        except IOError as e:
            print(f"\nError: Could not write results to CSV file '{csv_filename}': {e}", file=sys.stderr)
            csv_filename = None
        except Exception as e:
             print(f"\nAn unexpected error occurred while writing CSV '{csv_filename}': {e}", file=sys.stderr)
             csv_filename = None
    else:
         print("\nSkipping CSV output because one or both input files were not found or paths were invalid during parsing attempt.")


    # --- Print summary results to Terminal (existing logic) ---
    print("\n--- Comparison Results (Terminal Summary) ---")

    print(f"\nA) Remediated Vulnerabilities (Present in '{file_a_name}' but NOT in '{file_b_name}'):")
    # Iterate through remediated keys, lookup severity in details_a
    if remediated_keys:
        for key in sorted(list(remediated_keys)):
            img, cve, pkg = key
            severity = details_a.get(key, 'Unknown') # Get severity from dict A
            # Add Severity to printout
            print(f"  - Image: {img}, CVE: {cve}, Package: {pkg}, Severity: {severity}")
    else:
        print(f"  (No unique vulnerabilities found only in '{file_a_name}')")

    print(f"\nB) New Vulnerabilities (Present in '{file_b_name}' but NOT in '{file_a_name}'):")
    # Iterate through new keys, lookup severity in details_b
    if new_keys:
        for key in sorted(list(new_keys)):
            img, cve, pkg = key
            severity = details_b.get(key, 'Unknown') # Get severity from dict B
            # Add Severity to printout
            print(f"  - Image: {img}, CVE: {cve}, Package: {pkg}, Severity: {severity}")
    else:
        print(f"  (No unique vulnerabilities found only in '{file_b_name}')")

    # --- Final Confirmation ---
    print("\n--- End of Comparison ---")
    if csv_filename:
        print(f"\nNOTE: Detailed results were also saved to '{csv_filename}' in the current directory.")
    else:
        print(f"\nNOTE: Detailed results were NOT saved to a CSV file due to errors or missing input files.")


# --- Main execution block (handles user input - no changes needed here) ---
if __name__ == "__main__":
    print("Clair Scan Comparison Tool (CSV Version)")
    print("----------------------------------------")
    print("Compares two CSV reports and outputs results (incl. severity) to terminal and a CSV file.")
    # Update date using system time
    current_date_str = datetime.now().strftime("%B %d, %Y")
    print(f"(Current Date: {current_date_str})")


    # Prompt user for the first file path
    scan_a_file = input("Enter the full path to the first Clair CSV report: ").strip()

    # Prompt user for the second file path
    scan_b_file = input("Enter the full path to the second Clair CSV report: ").strip()

    # Basic check if paths were actually entered
    if not scan_a_file or not scan_b_file:
        print("\nError: Both file paths are required to perform the comparison.", file=sys.stderr)
        sys.exit(1) # Exit the script indicating an error

    # Call the comparison function with the user-provided paths
    compare_scans(scan_a_file, scan_b_file)
