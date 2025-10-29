#!/usr/bin/env python3
"""
GCP Reconnaissance Tool
A comprehensive tool for enumerating and assessing Google Cloud Platform resources.
For defensive security and authorized security assessments only.
"""

import argparse
import json
import sys
import logging
from datetime import datetime
from typing import Dict, List, Any
from google.cloud import compute_v1, storage, container_v1
from google.cloud import resourcemanager_v3
from google.cloud import sql_v1
from googleapiclient import discovery
from google.oauth2 import service_account
import google.auth

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class GCPRecon:
    """Main class for GCP reconnaissance operations."""

    def __init__(self, project_id: str = None, credentials_path: str = None):
        """
        Initialize GCP Recon tool.

        Args:
            project_id: GCP project ID to scan
            credentials_path: Path to service account credentials JSON
        """
        self.project_id = project_id
        self.credentials = None
        self.results = {
            'scan_time': datetime.utcnow().isoformat(),
            'project_id': project_id,
            'findings': {}
        }

        # Initialize credentials
        if credentials_path:
            self.credentials = service_account.Credentials.from_service_account_file(
                credentials_path,
                scopes=['https://www.googleapis.com/auth/cloud-platform']
            )
        else:
            # Use default credentials
            self.credentials, default_project = google.auth.default()
            if not self.project_id:
                self.project_id = default_project
                self.results['project_id'] = default_project

    def enumerate_projects(self) -> List[Dict[str, Any]]:
        """Enumerate all accessible GCP projects."""
        logger.info("Enumerating GCP projects...")
        projects = []

        try:
            client = resourcemanager_v3.ProjectsClient(credentials=self.credentials)
            request = resourcemanager_v3.ListProjectsRequest()

            for project in client.list_projects(request=request):
                project_info = {
                    'name': project.name,
                    'project_id': project.project_id,
                    'display_name': project.display_name,
                    'state': project.state.name,
                    'create_time': str(project.create_time)
                }
                projects.append(project_info)
                logger.info(f"Found project: {project.project_id}")
        except Exception as e:
            logger.error(f"Error enumerating projects: {e}")

        self.results['findings']['projects'] = projects
        return projects

    def enumerate_compute_instances(self) -> List[Dict[str, Any]]:
        """Enumerate Compute Engine instances."""
        logger.info("Enumerating Compute Engine instances...")
        instances = []

        try:
            client = compute_v1.InstancesClient(credentials=self.credentials)

            # Get all zones
            zones_client = compute_v1.ZonesClient(credentials=self.credentials)
            zones = zones_client.list(project=self.project_id)

            for zone in zones:
                try:
                    request = compute_v1.ListInstancesRequest(
                        project=self.project_id,
                        zone=zone.name
                    )

                    for instance in client.list(request=request):
                        # Check for public IPs
                        public_ips = []
                        for interface in instance.network_interfaces:
                            for access_config in interface.access_configs:
                                if access_config.nat_i_p:
                                    public_ips.append(access_config.nat_i_p)

                        instance_info = {
                            'name': instance.name,
                            'zone': zone.name,
                            'machine_type': instance.machine_type.split('/')[-1],
                            'status': instance.status,
                            'public_ips': public_ips,
                            'private_ip': instance.network_interfaces[0].network_i_p if instance.network_interfaces else None,
                            'disks': [disk.source.split('/')[-1] for disk in instance.disks],
                            'service_accounts': [sa.email for sa in instance.service_accounts] if instance.service_accounts else [],
                            'tags': list(instance.tags.items) if instance.tags else [],
                            'metadata': {item.key: item.value for item in instance.metadata.items} if instance.metadata else {},
                            'has_public_ip': len(public_ips) > 0
                        }
                        instances.append(instance_info)
                        logger.info(f"Found instance: {instance.name} in {zone.name}")
                except Exception as e:
                    logger.debug(f"Error scanning zone {zone.name}: {e}")
        except Exception as e:
            logger.error(f"Error enumerating compute instances: {e}")

        self.results['findings']['compute_instances'] = instances
        return instances

    def enumerate_storage_buckets(self) -> List[Dict[str, Any]]:
        """Enumerate Cloud Storage buckets."""
        logger.info("Enumerating Cloud Storage buckets...")
        buckets = []

        try:
            client = storage.Client(project=self.project_id, credentials=self.credentials)

            for bucket in client.list_buckets():
                # Check if bucket is publicly accessible
                is_public = False
                try:
                    policy = bucket.get_iam_policy()
                    for binding in policy.bindings:
                        if 'allUsers' in binding.get('members', []) or \
                           'allAuthenticatedUsers' in binding.get('members', []):
                            is_public = True
                            break
                except Exception as e:
                    logger.debug(f"Could not check IAM policy for {bucket.name}: {e}")

                bucket_info = {
                    'name': bucket.name,
                    'location': bucket.location,
                    'storage_class': bucket.storage_class,
                    'created': str(bucket.time_created),
                    'is_public': is_public,
                    'versioning_enabled': bucket.versioning_enabled,
                    'lifecycle_rules': len(bucket.lifecycle_rules) if bucket.lifecycle_rules else 0,
                    'labels': dict(bucket.labels) if bucket.labels else {}
                }
                buckets.append(bucket_info)
                logger.info(f"Found bucket: {bucket.name} (Public: {is_public})")
        except Exception as e:
            logger.error(f"Error enumerating storage buckets: {e}")

        self.results['findings']['storage_buckets'] = buckets
        return buckets

    def enumerate_sql_instances(self) -> List[Dict[str, Any]]:
        """Enumerate Cloud SQL instances."""
        logger.info("Enumerating Cloud SQL instances...")
        sql_instances = []

        try:
            client = sql_v1.SqlInstancesServiceClient(credentials=self.credentials)
            request = sql_v1.SqlInstancesListRequest(project=self.project_id)

            response = client.list(request=request)

            for instance in response.items:
                # Check for public IP
                has_public_ip = False
                public_ip = None
                if instance.ip_addresses:
                    for ip in instance.ip_addresses:
                        if ip.type_ == sql_v1.SqlIpAddressType.PRIMARY:
                            public_ip = ip.ip_address
                            has_public_ip = True

                instance_info = {
                    'name': instance.name,
                    'database_version': instance.database_version.name,
                    'state': instance.state.name,
                    'region': instance.region,
                    'tier': instance.settings.tier if instance.settings else None,
                    'has_public_ip': has_public_ip,
                    'public_ip': public_ip,
                    'backup_enabled': instance.settings.backup_configuration.enabled if instance.settings and instance.settings.backup_configuration else False,
                    'ssl_required': instance.settings.ip_configuration.require_ssl if instance.settings and instance.settings.ip_configuration else False
                }
                sql_instances.append(instance_info)
                logger.info(f"Found SQL instance: {instance.name}")
        except Exception as e:
            logger.error(f"Error enumerating SQL instances: {e}")

        self.results['findings']['sql_instances'] = sql_instances
        return sql_instances

    def enumerate_gke_clusters(self) -> List[Dict[str, Any]]:
        """Enumerate GKE clusters."""
        logger.info("Enumerating GKE clusters...")
        clusters = []

        try:
            client = container_v1.ClusterManagerClient(credentials=self.credentials)

            # Get all locations
            locations = ['us-central1', 'us-east1', 'us-west1', 'europe-west1', 'asia-east1']

            for location in locations:
                try:
                    parent = f"projects/{self.project_id}/locations/{location}"
                    response = client.list_clusters(parent=parent)

                    for cluster in response.clusters:
                        cluster_info = {
                            'name': cluster.name,
                            'location': cluster.location,
                            'status': cluster.status.name,
                            'node_count': cluster.current_node_count,
                            'endpoint': cluster.endpoint,
                            'master_version': cluster.current_master_version,
                            'network': cluster.network,
                            'subnetwork': cluster.subnetwork,
                            'logging_service': cluster.logging_service,
                            'monitoring_service': cluster.monitoring_service,
                            'private_cluster': cluster.private_cluster_config.enable_private_nodes if cluster.private_cluster_config else False
                        }
                        clusters.append(cluster_info)
                        logger.info(f"Found GKE cluster: {cluster.name}")
                except Exception as e:
                    logger.debug(f"Error scanning location {location}: {e}")
        except Exception as e:
            logger.error(f"Error enumerating GKE clusters: {e}")

        self.results['findings']['gke_clusters'] = clusters
        return clusters

    def enumerate_firewall_rules(self) -> List[Dict[str, Any]]:
        """Enumerate VPC firewall rules."""
        logger.info("Enumerating firewall rules...")
        firewall_rules = []

        try:
            client = compute_v1.FirewallsClient(credentials=self.credentials)
            request = compute_v1.ListFirewallsRequest(project=self.project_id)

            for firewall in client.list(request=request):
                # Check for overly permissive rules
                is_permissive = False
                if firewall.source_ranges and '0.0.0.0/0' in firewall.source_ranges:
                    is_permissive = True

                allowed_rules = []
                if firewall.allowed:
                    for rule in firewall.allowed:
                        allowed_rules.append({
                            'protocol': rule.I_p_protocol,
                            'ports': list(rule.ports) if rule.ports else ['all']
                        })

                rule_info = {
                    'name': firewall.name,
                    'network': firewall.network.split('/')[-1],
                    'direction': firewall.direction,
                    'priority': firewall.priority,
                    'source_ranges': list(firewall.source_ranges) if firewall.source_ranges else [],
                    'allowed': allowed_rules,
                    'target_tags': list(firewall.target_tags) if firewall.target_tags else [],
                    'is_permissive': is_permissive,
                    'disabled': firewall.disabled
                }
                firewall_rules.append(rule_info)
                logger.info(f"Found firewall rule: {firewall.name}")
        except Exception as e:
            logger.error(f"Error enumerating firewall rules: {e}")

        self.results['findings']['firewall_rules'] = firewall_rules
        return firewall_rules

    def enumerate_iam_service_accounts(self) -> List[Dict[str, Any]]:
        """Enumerate IAM service accounts."""
        logger.info("Enumerating IAM service accounts...")
        service_accounts = []

        try:
            service = discovery.build('iam', 'v1', credentials=self.credentials)

            request = service.projects().serviceAccounts().list(
                name=f'projects/{self.project_id}'
            )

            response = request.execute()

            for account in response.get('accounts', []):
                account_info = {
                    'email': account['email'],
                    'name': account['name'],
                    'display_name': account.get('displayName', ''),
                    'disabled': account.get('disabled', False),
                    'oauth2_client_id': account.get('oauth2ClientId', '')
                }
                service_accounts.append(account_info)
                logger.info(f"Found service account: {account['email']}")
        except Exception as e:
            logger.error(f"Error enumerating service accounts: {e}")

        self.results['findings']['service_accounts'] = service_accounts
        return service_accounts

    def analyze_security_issues(self) -> Dict[str, List[str]]:
        """Analyze findings for security issues."""
        logger.info("Analyzing security issues...")
        issues = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }

        # Check for public storage buckets
        if 'storage_buckets' in self.results['findings']:
            for bucket in self.results['findings']['storage_buckets']:
                if bucket['is_public']:
                    issues['critical'].append(
                        f"Public storage bucket found: {bucket['name']}"
                    )

        # Check for compute instances with public IPs
        if 'compute_instances' in self.results['findings']:
            for instance in self.results['findings']['compute_instances']:
                if instance['has_public_ip']:
                    issues['medium'].append(
                        f"Compute instance with public IP: {instance['name']} ({', '.join(instance['public_ips'])})"
                    )

        # Check for SQL instances with public IPs
        if 'sql_instances' in self.results['findings']:
            for instance in self.results['findings']['sql_instances']:
                if instance['has_public_ip']:
                    issues['high'].append(
                        f"SQL instance with public IP: {instance['name']} ({instance['public_ip']})"
                    )
                if not instance['backup_enabled']:
                    issues['medium'].append(
                        f"SQL instance without backups: {instance['name']}"
                    )
                if not instance['ssl_required']:
                    issues['high'].append(
                        f"SQL instance without SSL requirement: {instance['name']}"
                    )

        # Check for overly permissive firewall rules
        if 'firewall_rules' in self.results['findings']:
            for rule in self.results['findings']['firewall_rules']:
                if rule['is_permissive'] and not rule['disabled']:
                    issues['high'].append(
                        f"Overly permissive firewall rule: {rule['name']} (allows 0.0.0.0/0)"
                    )

        self.results['security_issues'] = issues
        return issues

    def run_full_scan(self) -> Dict[str, Any]:
        """Run a comprehensive scan of all GCP resources."""
        logger.info(f"Starting full GCP reconnaissance scan for project: {self.project_id}")

        # Run all enumeration functions
        self.enumerate_projects()
        self.enumerate_compute_instances()
        self.enumerate_storage_buckets()
        self.enumerate_sql_instances()
        self.enumerate_gke_clusters()
        self.enumerate_firewall_rules()
        self.enumerate_iam_service_accounts()

        # Analyze security issues
        self.analyze_security_issues()

        logger.info("Scan completed successfully")
        return self.results

    def export_json(self, output_file: str):
        """Export results to JSON file."""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        logger.info(f"Results exported to {output_file}")

    def print_summary(self):
        """Print a summary of findings to console."""
        print("\n" + "="*80)
        print("GCP RECONNAISSANCE SUMMARY")
        print("="*80)
        print(f"Project ID: {self.project_id}")
        print(f"Scan Time: {self.results['scan_time']}")
        print("="*80)

        findings = self.results['findings']

        if 'projects' in findings:
            print(f"\nProjects: {len(findings['projects'])}")

        if 'compute_instances' in findings:
            print(f"Compute Instances: {len(findings['compute_instances'])}")
            public_instances = sum(1 for i in findings['compute_instances'] if i['has_public_ip'])
            print(f"  - With public IPs: {public_instances}")

        if 'storage_buckets' in findings:
            print(f"Storage Buckets: {len(findings['storage_buckets'])}")
            public_buckets = sum(1 for b in findings['storage_buckets'] if b['is_public'])
            print(f"  - Public buckets: {public_buckets}")

        if 'sql_instances' in findings:
            print(f"SQL Instances: {len(findings['sql_instances'])}")
            public_sql = sum(1 for s in findings['sql_instances'] if s['has_public_ip'])
            print(f"  - With public IPs: {public_sql}")

        if 'gke_clusters' in findings:
            print(f"GKE Clusters: {len(findings['gke_clusters'])}")

        if 'firewall_rules' in findings:
            print(f"Firewall Rules: {len(findings['firewall_rules'])}")

        if 'service_accounts' in findings:
            print(f"Service Accounts: {len(findings['service_accounts'])}")

        # Print security issues
        if 'security_issues' in self.results:
            print("\n" + "="*80)
            print("SECURITY ISSUES")
            print("="*80)

            issues = self.results['security_issues']
            for severity in ['critical', 'high', 'medium', 'low']:
                if issues[severity]:
                    print(f"\n{severity.upper()} ({len(issues[severity])}):")
                    for issue in issues[severity]:
                        print(f"  - {issue}")

        print("\n" + "="*80)


def main():
    parser = argparse.ArgumentParser(
        description='GCP Reconnaissance Tool - For authorized security assessments only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan using default credentials
  python gcp_recon.py --project my-project-id

  # Scan with service account credentials
  python gcp_recon.py --project my-project-id --credentials /path/to/creds.json

  # Export results to JSON
  python gcp_recon.py --project my-project-id --output results.json

  # Enumerate specific resources
  python gcp_recon.py --project my-project-id --compute --storage
        """
    )

    parser.add_argument('--project', '-p', help='GCP Project ID to scan')
    parser.add_argument('--credentials', '-c', help='Path to service account credentials JSON')
    parser.add_argument('--output', '-o', help='Output JSON file for results')
    parser.add_argument('--compute', action='store_true', help='Enumerate compute instances only')
    parser.add_argument('--storage', action='store_true', help='Enumerate storage buckets only')
    parser.add_argument('--sql', action='store_true', help='Enumerate SQL instances only')
    parser.add_argument('--gke', action='store_true', help='Enumerate GKE clusters only')
    parser.add_argument('--firewall', action='store_true', help='Enumerate firewall rules only')
    parser.add_argument('--iam', action='store_true', help='Enumerate IAM service accounts only')
    parser.add_argument('--projects', action='store_true', help='Enumerate projects only')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    try:
        recon = GCPRecon(project_id=args.project, credentials_path=args.credentials)

        # Check if specific enumeration is requested
        specific_scan = any([
            args.compute, args.storage, args.sql, args.gke,
            args.firewall, args.iam, args.projects
        ])

        if specific_scan:
            if args.projects:
                recon.enumerate_projects()
            if args.compute:
                recon.enumerate_compute_instances()
            if args.storage:
                recon.enumerate_storage_buckets()
            if args.sql:
                recon.enumerate_sql_instances()
            if args.gke:
                recon.enumerate_gke_clusters()
            if args.firewall:
                recon.enumerate_firewall_rules()
            if args.iam:
                recon.enumerate_iam_service_accounts()

            recon.analyze_security_issues()
        else:
            # Run full scan
            recon.run_full_scan()

        # Print summary
        recon.print_summary()

        # Export if requested
        if args.output:
            recon.export_json(args.output)

    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
