# Prowler AWS Multi-Account Scanner (In Development)

This project provides a Python-based solution to scan multiple AWS accounts using [Prowler](https://github.com/prowler-cloud/prowler). The script reads AWS credentials from a CSV file, updates the default credentials, and then runs Prowler for each account. It also outputs real-time scan results to the console.

## Features

- **Multiple Accounts**: Reads access keys and secret keys for multiple AWS accounts from a single CSV.
- **Real-time Output**: Prowler's console output is streamed immediately to your terminal.
- **Check Failures**: Return code `3` from Prowler is interpreted as some checks failing, not a complete error.
- **Credentials Check**: Automatically prints the local `~/.aws/credentials` file each time it's updated, so you can confirm the correct credentials are in place.

## Future Plans

1. **Azure**: Add support for scanning Azure environments using Prowler or related tooling.  
2. **GCP**: Extend scanning capabilities to Google Cloud Platform.  
3. **Kubernetes**: Incorporate checks for Kubernetes clusters, possibly leveraging additional container security tooling.

## Requirements

- Python 3.6+  
- [Prowler](https://github.com/prowler-cloud/prowler) installed on your machine and accessible in your `$PATH`.

## Installation

Clone this repository:
```
   git clone https://github.com/yourusername/prowler-multi-account-scan.git
```
Install Prowler (if not already installed):
```
pip install prowler-cloud
```
Or follow the official Prowler documentation for alternative installation methods.

## Usage:

Prepare your CSV file (for example, accounts.csv) with the columns:

Account Name
Access Key ID
Secret Access Key
Run the script:
\
```
python prowler_mass_scan.py accounts.csv us-east-1
```
Replace accounts.csv with your CSV file path and us-east-1 with the region you want to scan.

## View Results:

The script prints Prowler's output to the console as it runs each scan.
Prowler also generates multiple output files (e.g., csv, html, ocsf.json) in the ./output/ directory, organized by account name.

## Example CSV Format
```
Account Name,Access Key ID,Secret Access Key
dev_account,AKIAXXXXXXXX,xxxxxxxxxxxxxxxxxx
prod_account,AKIAYYYYYYYY,yyyyyyyyyyyyyyyyyy
...
