# GCP Reconnaissance Tool

A comprehensive Google Cloud Platform reconnaissance tool for defensive security assessments and authorized penetration testing.

## Overview

This tool provides automated enumeration and security assessment capabilities for GCP environments. It helps security professionals identify misconfigurations, exposed resources, and potential security risks in Google Cloud deployments.

## Features

### Resource Enumeration
- **Projects**: List all accessible GCP projects
- **Compute Engine**: Enumerate VM instances, identify public IPs
- **Cloud Storage**: List buckets and identify publicly accessible storage
- **Cloud SQL**: Enumerate database instances and check for public exposure
- **GKE Clusters**: List Kubernetes clusters and configurations
- **Firewall Rules**: Enumerate VPC firewall rules and identify overly permissive rules
- **IAM**: List service accounts and their configurations

### Security Analysis
- Automatically identifies security issues across multiple severity levels:
  - **Critical**: Public storage buckets
  - **High**: SQL instances with public IPs, missing SSL requirements, overly permissive firewalls
  - **Medium**: Compute instances with public IPs, SQL instances without backups
  - **Low**: Other configuration issues

### Output Formats
- Console summary with color-coded severity levels
- JSON export for integration with other tools
- Detailed findings for each resource type

## Installation

### Prerequisites
- Python 3.7 or higher
- GCP project with appropriate permissions
- Service account credentials or authenticated gcloud CLI

### Setup

1. Clone the repository:
```bash
git clone https://github.com/snorlax19/snorlax19.git
cd snorlax19
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up authentication (choose one):

   **Option A: Using gcloud CLI**
   ```bash
   gcloud auth application-default login
   ```

   **Option B: Using Service Account**
   ```bash
   export GOOGLE_APPLICATION_CREDENTIALS="/path/to/credentials.json"
   ```

## Usage

### Basic Scan

Scan a project using default credentials:
```bash
python gcp_recon.py --project my-project-id
```

### Full Scan with Credentials

Scan using service account credentials:
```bash
python gcp_recon.py --project my-project-id --credentials /path/to/creds.json
```

### Export Results

Export findings to JSON:
```bash
python gcp_recon.py --project my-project-id --output results.json
```

### Selective Enumeration

Enumerate specific resource types:

```bash
# Enumerate only compute instances
python gcp_recon.py --project my-project-id --compute

# Enumerate storage buckets and SQL instances
python gcp_recon.py --project my-project-id --storage --sql

# Enumerate firewall rules
python gcp_recon.py --project my-project-id --firewall

# Enumerate GKE clusters
python gcp_recon.py --project my-project-id --gke

# Enumerate IAM service accounts
python gcp_recon.py --project my-project-id --iam
```

### Verbose Output

Enable detailed logging:
```bash
python gcp_recon.py --project my-project-id --verbose
```

## Command-Line Options

```
usage: gcp_recon.py [-h] [--project PROJECT] [--credentials CREDENTIALS]
                    [--output OUTPUT] [--compute] [--storage] [--sql]
                    [--gke] [--firewall] [--iam] [--projects] [--verbose]

optional arguments:
  -h, --help            Show this help message and exit
  --project, -p         GCP Project ID to scan
  --credentials, -c     Path to service account credentials JSON
  --output, -o          Output JSON file for results
  --compute             Enumerate compute instances only
  --storage             Enumerate storage buckets only
  --sql                 Enumerate SQL instances only
  --gke                 Enumerate GKE clusters only
  --firewall            Enumerate firewall rules only
  --iam                 Enumerate IAM service accounts only
  --projects            Enumerate projects only
  --verbose, -v         Enable verbose logging
```

## Required Permissions

The service account or user running this tool needs the following IAM roles:

- **Viewer** or **Security Reviewer** (recommended for read-only access)
- Specific permissions:
  - `compute.instances.list`
  - `compute.zones.list`
  - `compute.firewalls.list`
  - `storage.buckets.list`
  - `storage.buckets.getIamPolicy`
  - `cloudsql.instances.list`
  - `container.clusters.list`
  - `iam.serviceAccounts.list`
  - `resourcemanager.projects.get`
  - `resourcemanager.projects.list`

## Example Output

```
================================================================================
GCP RECONNAISSANCE SUMMARY
================================================================================
Project ID: my-project-123
Scan Time: 2025-10-29T12:34:56.789012
================================================================================

Projects: 3
Compute Instances: 12
  - With public IPs: 5
Storage Buckets: 8
  - Public buckets: 1
SQL Instances: 2
  - With public IPs: 1
GKE Clusters: 1
Firewall Rules: 24
Service Accounts: 15

================================================================================
SECURITY ISSUES
================================================================================

CRITICAL (1):
  - Public storage bucket found: my-public-bucket

HIGH (3):
  - SQL instance with public IP: prod-database (35.123.45.67)
  - SQL instance without SSL requirement: prod-database
  - Overly permissive firewall rule: allow-all (allows 0.0.0.0/0)

MEDIUM (7):
  - Compute instance with public IP: web-server-1 (34.123.45.67)
  - Compute instance with public IP: web-server-2 (34.123.45.68)
  - SQL instance without backups: dev-database

================================================================================
```

## Security Considerations

### Legal and Ethical Use
- **Only use this tool on GCP projects you own or have explicit authorization to test**
- This tool is designed for defensive security purposes only
- Unauthorized scanning of GCP resources may violate terms of service and laws

### Credential Security
- Never commit GCP credentials to version control
- Use service accounts with minimal required permissions
- Rotate credentials regularly
- Store credentials securely

### Rate Limiting
- The tool respects GCP API rate limits
- For large environments, scans may take several minutes
- Consider running selective scans for specific resources

## Troubleshooting

### Authentication Errors
```
Error: Could not automatically determine credentials
```
**Solution**: Ensure you've authenticated using `gcloud auth application-default login` or set `GOOGLE_APPLICATION_CREDENTIALS`

### Permission Denied
```
Error: The caller does not have permission
```
**Solution**: Verify your service account has the required IAM roles listed above

### API Not Enabled
```
Error: API [service.googleapis.com] not enabled
```
**Solution**: Enable required APIs in your GCP project:
```bash
gcloud services enable compute.googleapis.com
gcloud services enable storage.googleapis.com
gcloud services enable sqladmin.googleapis.com
gcloud services enable container.googleapis.com
```

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description

## License

This tool is provided as-is for educational and authorized security testing purposes only.

## Disclaimer

This tool is intended for use by security professionals conducting authorized assessments. Users are responsible for ensuring they have proper authorization before scanning any GCP environment. The authors assume no liability for misuse or damage caused by this tool.

## Author

@snorlax19 - Sometimes I use solar beam
