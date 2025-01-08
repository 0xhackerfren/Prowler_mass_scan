#!/usr/bin/env python3

"""
Prowler AWS Multi-Account Scanner

This script reads AWS account credentials (Access Key, Secret Key, and an Account Name)
from a CSV file, updates the default AWS credentials on the local machine, and runs a
Prowler scan for each account. The output of each scan is streamed directly to the console
so you can monitor progress in real time. The -F flag supplied to prowler parses the account name correctly into each output format  that is created. 

Prowler will create the follwing files for each account passed 
./output/{accountname}.[ocsf.json,csv,html]
./output/compliance/*

Usage:
    python script.py <path_to_csv> <aws_region>

Example:
    python script.py accounts.csv us-east-1

Author: Your Name
"""

import os
import csv
import subprocess
import sys
from pathlib import Path

def update_aws_credentials(access_key, secret_key):
    """
    Updates the default AWS credentials in the ~/.aws/credentials file.

    Args:
        access_key (str): The AWS access key ID.
        secret_key (str): The AWS secret access key.
    """
    credentials_path = Path.home() / ".aws" / "credentials"
    os.makedirs(credentials_path.parent, exist_ok=True)  # Ensure ~/.aws directory exists

    print("[DEBUG] Overwriting credentials for the default profile")

    # Write default profile to credentials file
    new_lines = [
        "[default]\n",
        f"aws_access_key_id = {access_key}\n",
        f"aws_secret_access_key = {secret_key}\n",
    ]

    with open(credentials_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)

    print("[DEBUG] Default profile credentials updated")

    # Print the newly updated credentials file to verify correctness
    print("[DEBUG] Printing current AWS credentials file content:")
    try:
        with open(credentials_path, "r", encoding="utf-8") as f:
            print(f.read().strip())
    except Exception as e:
        print(f"[ERROR] Unable to read the credentials file: {e}")


def run_prowler_scan(region, account_name):
    """
    Runs the Prowler scan for the default profile and a specified AWS region,
    streaming its output directly to the console.

    Args:
        region (str): The AWS region to scan (e.g., "us-east-1").
        account_name (str): The name of the account being scanned.
    """
    command = ["prowler", "aws", "-f", region, "-F", account_name]
    print(f"[DEBUG] Running Prowler scan with command: {' '.join(command)}")

    try:
        # By not using capture_output=True, the Prowler output goes straight to your terminal.
        subprocess.run(command, check=True)
        print(f"[INFO] Prowler scan completed for account: {account_name}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Prowler scan failed for account: {account_name}")
        print(f"[ERROR] Return Code: {e.returncode}")


def main():
    """
    Main function to:
    1. Validate script arguments.
    2. Read AWS account data from a CSV file.
    3. For each account, update the default AWS credentials and run a Prowler scan.
    """
    if len(sys.argv) != 3:
        print("Usage: python script.py <path_to_csv> <aws_region>")
        sys.exit(1)

    csv_path = sys.argv[1]
    region = sys.argv[2]

    print(f"[DEBUG] CSV file: {csv_path}")
    print(f"[DEBUG] AWS region: {region}")

    # Check if the CSV file exists
    if not os.path.isfile(csv_path):
        print(f"[ERROR] CSV file not found: {csv_path}")
        sys.exit(1)

    # Read the CSV file
    try:
        with open(csv_path, "r", encoding="utf-8") as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                account_name = row.get("Account Name")
                access_key = row.get("Access Key ID")
                secret_key = row.get("Secret Access Key")

                # Validate required fields
                if not account_name or not access_key or not secret_key:
                    print(f"[WARNING] Skipping incomplete entry: {row}")
                    continue

                print(f"[INFO] Processing account: {account_name}")

                # Update default AWS credentials and run Prowler
                update_aws_credentials(access_key, secret_key)
                run_prowler_scan(region, account_name)

    except Exception as e:
        print(f"[ERROR] Failed to process CSV file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
