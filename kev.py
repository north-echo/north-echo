import requests

def check_cve_in_cisa_database(cve_id):
    # URL to CISA's known exploited vulnerabilities catalog
    # This URL may need to be updated based on CISA's current data endpoint
    cisa_api_url = 'https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv'

    try:
        response = requests.get(cisa_api_url)
        response.raise_for_status()

        # Check if the CVE is in the data
        if cve_id in response.text:
            return True
        else:
            return False

    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        return False

def main():
    cve_id = input("Enter the CVE ID (e.g., CVE-2021-34527): ")
    if check_cve_in_cisa_database(cve_id):
        print(f"The CVE {cve_id} is in CISA's Known Exploited Vulnerabilities database.")
    else:
        print(f"The CVE {cve_id} is not in CISA's Known Exploited Vulnerabilities database.")

if __name__ == "__main__":
    main()