Prowler AWS Multi-Account Scanner

This script reads AWS account credentials (Access Key, Secret Key, and an Account Name)
from a CSV file, updates the default AWS credentials on the local machine, and runs a
Prowler scan for each account. The output of each scan is streamed directly to the console
so you can monitor progress in real time. The -F flag supplied to prowler parses the account name correctly into each output format  that is created. 

Prowler will create the follwing files for each account passed 
./output/{accountname}.[ocsf.json,csv,html]
./output/compliance/*

Usage:
    python prowler_mass_scan.py <path_to_csv> <aws_region>

Example:
    python prowler_mass_scan.py accounts.csv us-east-1
