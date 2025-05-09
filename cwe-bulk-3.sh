#!/bin/bash

# Enable debug mode (set to "true" to enable debugging output)
DEBUG=true

# Function to retrieve CWE for a given CVE
fetch_cwe() {
    local CVE_ID="$1"

    # Get the OSIDB access token if not already set
    if [[ -z "$OSIDB_ACCESS_TOKEN" || "$OSIDB_ACCESS_TOKEN" == "null" ]]; then
        OSIDB_RESPONSE=$(curl -s -H 'Content-Type: application/json' --negotiate -u : "https://osidb.prodsec.redhat.com/auth/token")
        OSIDB_ACCESS_TOKEN=$(echo "$OSIDB_RESPONSE" | jq -r ".access")

        # Validate token
        if [[ -z "$OSIDB_ACCESS_TOKEN" || "$OSIDB_ACCESS_TOKEN" == "null" ]]; then
            echo "Error: Failed to retrieve OSIDB access token. Please check authentication."
            return
        fi
    fi

    # Retrieve CWE for the given CVE
    RESPONSE=$(curl -s -H "Authorization: Bearer $OSIDB_ACCESS_TOKEN" -X GET \
    "https://osidb.prodsec.redhat.com/osidb/api/v1/flaws?cve_id=$CVE_ID&include_fields=cve_id,cwe_id")

    # Debugging: Print the full API response
    if [[ "$DEBUG" == "true" ]]; then
        echo "Debug: Full API Response for $CVE_ID:"
        echo "$RESPONSE" | jq .
    fi

    # Check if the API returned an error or empty data
    ERROR_MESSAGE=$(echo "$RESPONSE" | jq -r '.error // empty')
    if [[ -n "$ERROR_MESSAGE" ]]; then
        echo "Error: API returned an error for $CVE_ID: $ERROR_MESSAGE"
        echo "$CVE_ID,API_ERROR" >> results.csv
        return
    fi

    DATA_COUNT=$(echo "$RESPONSE" | jq -r '.results | length')
    if [[ "$DATA_COUNT" -eq 0 ]]; then
        echo "$CVE_ID,N/A" >> results.csv
        if [[ "$DEBUG" == "true" ]]; then
            echo "Debug: No data found for $CVE_ID"
        fi
        return
    fi

    # Extract CVE and CWE values
    CVE_VALUE=$(echo "$RESPONSE" | jq -r '.results[].cve_id' | head -n 1)
    CWE_VALUE=$(echo "$RESPONSE" | jq -r '.results[].cwe_id' | head -n 1)

    # If extraction fails, default to N/A
    CVE_VALUE=${CVE_VALUE:-"N/A"}
    CWE_VALUE=${CWE_VALUE:-"N/A"}

    # Debug: Print extracted values before writing to CSV
    if [[ "$DEBUG" == "true" ]]; then
        echo "Debug: Extracted values: CVE=$CVE_VALUE, CWE=$CWE_VALUE"
    fi

    # Append the result to the CSV file
    echo "$CVE_VALUE,$CWE_VALUE" >> results.csv
}

# Initialize CSV file with lowercase headers only if it does not exist
if [[ ! -f results.csv ]]; then
    echo "cve_id,cwe_id" > results.csv
fi

# Main loop with option for bulk processing
while true; do
    read -p "Enter CVE ID (or type 'exit' to quit, or provide a filename for bulk processing): " INPUT

    # Exit condition
    if [[ "$INPUT" == "exit" ]]; then
        echo "Exiting..."
        break
    fi

    # If input is a file, process bulk list
    if [[ -f "$INPUT" ]]; then
        echo "Processing bulk list from $INPUT..."
        while IFS= read -r CVE_ID; do
            fetch_cwe "$CVE_ID"
        done < "$INPUT"
    else
        # Fetch and display CWE ID for the given single CVE
        fetch_cwe "$INPUT"
    fi
done