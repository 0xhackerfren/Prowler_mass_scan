#!/usr/bin/env python3

"""
Prowler AWS Multi-Account Scanner (In Development)

This script reads AWS account credentials (Access Key, Secret Key, and an Account Name)
from a CSV file, updates the default AWS credentials locally, and runs Prowler against each
account. The console output is streamed directly so you can watch progress in real time.

Future Plans:
    1. Add support for Azure
    2. Add support for GCP
    3. Add support for Kubernetes

Usage:
    python prowler_mass_scan.py <path_to_csv> <aws_region>

Example:
    python prowler_mass_scan.py accounts.csv us-east-1

Author: 0xHackerfren
"""

import os
import csv
import subprocess
import sys
from pathlib import Path

def update_aws_credentials(access_key, secret_key):
    """
    Writes the provided AWS credentials (Access Key, Secret Key) to the default profile
    in the ~/.aws/credentials file. This function is intended to update credentials
    just before a scan so that the current profile matches the account being scanned.

    Steps:
        1. Construct the path to ~/.aws/credentials.
        2. Ensure the ~/.aws directory exists (creates it if not).
        3. Create the lines that represent the default AWS profile in the credentials file.
        4. Write the lines to the file, overwriting any previous data.
        5. Print the contents of the updated file to confirm the change succeeded.
        6. If reading the file fails, log an error message.
    """
    # Path to ~/.aws/credentials
    credentials_path = Path.home() / ".aws" / "credentials"

    # Make sure the ~/.aws directory exists
    os.makedirs(credentials_path.parent, exist_ok=True)

    print("[DEBUG] Overwriting credentials for the default profile")

    # Define the new credentials content
    new_lines = [
        "[default]\n",
        f"aws_access_key_id = {access_key}\n",
        f"aws_secret_access_key = {secret_key}\n",
    ]

    # Write the credentials to the file
    with open(credentials_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)

    print("[DEBUG] Default profile credentials updated")
    print("[DEBUG] Printing current AWS credentials file content:")

    # Read the credentials file to verify the contents
    try:
        with open(credentials_path, "r", encoding="utf-8") as f:
            print(f.read().strip())
    except Exception as e:
        print(f"[ERROR] Unable to read the credentials file: {e}")


def run_prowler_scan(region, account_name):
    """
    Executes a Prowler scan using the updated default AWS credentials and specified region.

    This function:
        1. Constructs the Prowler command with appropriate flags:
           - "prowler aws" to run AWS-specific checks.
           - "-f <region>" to set the AWS region.
           - "-F <account_name>" so that Prowler tags its output files with this account name.
        2. Uses subprocess.run() without `check=True` so non-zero exit codes don't raise exceptions.
        3. Streams the output of Prowler directly to the console in real time.
        4. Interprets the Prowler exit code:
            - 0 indicates all checks passed.
            - 3 indicates some checks failed (not necessarily a broken scan).
            - Other non-zero codes are considered unexpected errors.

    Args:
        region (str): The AWS region for the Prowler scan (e.g., "us-east-1").
        account_name (str): The name of the account being scanned, used to label outputs.
    """
    # Construct the command list for subprocess
    command = ["prowler", "aws", "-f", region, "-F", account_name]
    print(f"[DEBUG] Running Prowler scan with command: {' '.join(command)}")

    # Run the Prowler command, letting output stream to the console
    result = subprocess.run(command)

    # Check the return code and log accordingly
    if result.returncode == 0:
        print(f"[INFO] Prowler scan completed successfully for account: {account_name}")
    elif result.returncode == 3:
        print(f"[WARNING] Prowler reported some failed checks for account: {account_name} (exit code: 3)")
    else:
        print(f"[ERROR] Prowler returned exit code {result.returncode} for account: {account_name}")


def main():
    """
    Main entry point for the script. Steps include:
        1. Validating command line arguments (CSV path and AWS region).
        2. Reading the CSV file that contains AWS accounts' credentials.
        3. For each valid row in the CSV, update the default AWS credentials locally,
           then run a Prowler scan using the newly updated credentials.
        4. Handle errors and logs appropriately.

    CSV Format (example):
        Account Name,Access Key ID,Secret Access Key
        dev_account,AKIA....,secret_key_here
        prod_account,AKIA....,secret_key_here
        ...
    """
    # Expecting exactly 2 arguments: CSV file and region
    if len(sys.argv) != 3:
        print("Usage: python prowler_mass_scan.py <path_to_csv> <aws_region>")
        sys.exit(1)

    # Extract the CSV path and AWS region from command line arguments
    csv_path, region = sys.argv[1], sys.argv[2]

    print(f"[DEBUG] CSV file: {csv_path}")
    print(f"[DEBUG] AWS region: {region}")

    # Verify the CSV file is a valid file
    if not os.path.isfile(csv_path):
        print(f"[ERROR] CSV file not found: {csv_path}")
        sys.exit(1)

    # Read the CSV file to retrieve account credentials
    try:
        with open(csv_path, "r", encoding="utf-8") as csv_file:
            reader = csv.DictReader(csv_file)
            # Iterate over each row, extracting the credentials and account name
            for row in reader:
                account_name = row.get("Account Name")
                access_key = row.get("Access Key ID")
                secret_key = row.get("Secret Access Key")

                # Check if the necessary columns are present and non-empty
                if not account_name or not access_key or not secret_key:
                    print(f"[WARNING] Skipping incomplete entry: {row}")
                    continue

                print(f"[INFO] Processing account: {account_name}")

                # Update credentials for the default profile before running the scan
                update_aws_credentials(access_key, secret_key)

                # Run the prowler scan using these updated credentials
                run_prowler_scan(region, account_name)

    except Exception as e:
        # Catch any unforeseen issues (like IO errors, CSV parsing, etc.)
        print(f"[ERROR] Failed to process CSV file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
