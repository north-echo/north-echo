import requests

def read_cve_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

def check_cve_in_cisa(cve_list):
    url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
    response = requests.get(url)
    if response.status_code != 200:
        print("Failed to retrieve CISA's known exploited vulnerabilities")
        return

    cisa_cves = response.text
    for cve in cve_list:
        if cve in cisa_cves:
            print(f"{cve} is in CISA's Known Exploited Vulnerability database.")
        else:
            print(f"{cve} is NOT in the database.")

def main():
    file_path = '/Users/clusk/Downloads/slo-report-cves.txt'  # Update this to your CVE file path
    cve_list = read_cve_file(file_path)
    check_cve_in_cisa(cve_list)

if __name__ == "__main__":
    main()
