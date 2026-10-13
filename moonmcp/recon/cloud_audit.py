"""Cloud security audit — 60+ misconfiguration checks for AWS / Azure / GCP.

Returns a structured catalog of cloud security checks, each with:
``service``, ``check_name``, ``severity``, ``description``, ``remediation``.

This is a **config-awareness** module: it enumerates the checks that should be
performed against a cloud account — it does not itself execute cloud API calls
(that requires provider credentials and the SDK).  The output is designed to be
fed into a cloud audit pipeline or used as a checklist for manual review.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class CloudCheck:
    """A single cloud security check."""

    provider: str
    service: str
    check_name: str
    severity: str  # critical, high, medium, low, info
    description: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# AWS checks — 30
# ---------------------------------------------------------------------------

_AWS_CHECKS: list[CloudCheck] = [
    # S3 (5)
    CloudCheck("aws", "S3", "s3-bucket-public-read-access",
               "high",
               "S3 bucket allows public read access via ACL or bucket policy.",
               "Disable public read access: set BlockPublicAcls and BlockPublicPolicy to True in S3 public access block settings, and remove any public ACLs or policy statements granting s3:GetObject to \"*\"."),
    CloudCheck("aws", "S3", "s3-bucket-public-write-access",
               "critical",
               "S3 bucket allows public write access, enabling data poisoning or destruction.",
               "Remove write permissions for allUsers/allAuthenticatedUsers. Enable S3 public access block. Review bucket policy for s3:PutObject grants to \"*\"."),
    CloudCheck("aws", "S3", "s3-bucket-no-encryption",
               "high",
               "S3 bucket does not enforce default encryption (SSE-S3, SSE-KMS, or SSE-C).",
               "Enable default encryption on the bucket using SSE-S3 or SSE-KMS. Use bucket policy to deny unencrypted PutObject requests."),
    CloudCheck("aws", "S3", "s3-bucket-versioning-disabled",
               "medium",
               "S3 bucket versioning is disabled, preventing recovery from accidental deletion or ransomware.",
               "Enable versioning on all S3 buckets. Optionally add MFA delete protection for critical buckets."),
    CloudCheck("aws", "S3", "s3-bucket-logging-disabled",
               "medium",
               "S3 bucket access logging is not configured, limiting forensic capability.",
               "Enable S3 server access logging to a central logging bucket. Alternatively use CloudTrail data events for S3."),

    # IAM (5)
    CloudCheck("aws", "IAM", "iam-root-account-active-access-key",
               "critical",
               "Root account has active access keys, creating a single point of failure and compromise.",
               "Delete all root account access keys. Use IAM users or roles for API access. Enable MFA on root account."),
    CloudCheck("aws", "IAM", "iam-mfa-not-enabled-for-root",
               "critical",
               "Root account does not have MFA enabled.",
               "Enable a hardware or virtual MFA device on the root account immediately."),
    CloudCheck("aws", "IAM", "iam-mfa-not-enforced-for-users",
               "high",
               "IAM users have console access but MFA is not enforced.",
               "Attach an IAM policy that denies all actions except iam:CreateVirtualMFADevice when MFA is not present. Use AWS IAM Access Advisor to audit."),
    CloudCheck("aws", "IAM", "iam-overprivileged-roles",
               "high",
               "IAM roles have overly permissive policies (e.g., AdministratorAccess or wildcards like Action: '*').",
               "Apply least-privilege: replace wildcard actions with specific service actions. Use IAM Access Analyzer to identify unused permissions and remove them."),
    CloudCheck("aws", "IAM", "iam-unused-access-keys",
               "medium",
               "IAM access keys have not been used in 90+ days.",
               "Identify unused access keys via IAM credential report and deactivate or delete them. Rotate keys regularly."),

    # EC2 / Security Groups (4)
    CloudCheck("aws", "EC2", "ec2-security-group-open-ssh-to-world",
               "high",
               "Security group allows inbound SSH (port 22) from 0.0.0.0/0.",
               "Restrict SSH to specific trusted IP ranges or CIDR blocks. Use Session Manager or a bastion host instead."),
    CloudCheck("aws", "EC2", "ec2-security-group-open-rdp-to-world",
               "high",
               "Security group allows inbound RDP (port 3389) from 0.0.0.0/0.",
               "Restrict RDP to specific trusted IP ranges. Use a VPN or bastion host for remote desktop access."),
    CloudCheck("aws", "EC2", "ec2-security-group-open-all-ports-to-world",
               "critical",
               "Security group allows all inbound traffic (0-65535) from 0.0.0.0/0.",
               "Remove the 0-65535/0.0.0.0/0 inbound rule. Define specific ports and source CIDRs per service."),
    CloudCheck("aws", "EC2", "ec2-security-group-open-database-to-world",
               "high",
               "Security group allows inbound database ports (MySQL 3306, PostgreSQL 5432, MSSQL 1433, Redis 6379) from 0.0.0.0/0.",
               "Restrict database security groups to application-tier security groups only. Never expose databases to the internet."),

    # RDS (3)
    CloudCheck("aws", "RDS", "rds-publicly-accessible",
               "high",
               "RDS instance has PubliclyAccessible=True, exposing the database to the internet.",
               "Set PubliclyAccessible=False on the RDS instance. Place RDS in private subnets. Use a bastion or VPN for access."),
    CloudCheck("aws", "RDS", "rds-encryption-disabled",
               "high",
               "RDS instance does not have storage encryption enabled.",
               "Enable encryption at rest for the RDS instance. Note: requires snapshot/restore for existing instances. Use KMS CMK."),
    CloudCheck("aws", "RDS", "rds-automated-backups-disabled",
               "medium",
               "RDS instance has automated backups disabled (backup retention period = 0).",
               "Set backup retention period to at least 7 days. Configure automated backup window and snapshot retention per compliance requirements."),

    # Lambda (2)
    CloudCheck("aws", "Lambda", "lambda-public-invoke-permissions",
               "high",
               "Lambda function has a resource-based policy granting invoke permission to all principals ('*').",
               "Remove wildcard principal from the function resource policy. Restrict invoke to specific AWS accounts or API Gateway ARNs."),
    CloudCheck("aws", "Lambda", "lambda-no-dead-letter-queue",
               "low",
               "Lambda function has no dead-letter queue (DLQ) configured, risking silent failure data loss.",
               "Configure an SQS queue or SNS topic as the DLQ for asynchronous invocations."),

    # CloudTrail (2)
    CloudCheck("aws", "CloudTrail", "cloudtrail-disabled",
               "high",
               "CloudTrail is not enabled, meaning all API activity goes unaudited.",
               "Enable CloudTrail in all regions with log file validation. Deliver logs to a centralized S3 bucket with restricted access."),
    CloudCheck("aws", "CloudTrail", "cloudtrail-log-encryption-disabled",
               "medium",
               "CloudTrail S3 bucket or log files are not encrypted with KMS.",
               "Enable SSE-KMS encryption on the CloudTrail S3 bucket. Use a dedicated KMS CMK for log encryption."),

    # KMS (2)
    CloudCheck("aws", "KMS", "kms-key-rotation-disabled",
               "medium",
               "KMS customer-managed key does not have automatic key rotation enabled.",
               "Enable automatic annual key rotation on all customer-managed KMS keys via KMS console or API."),
    CloudCheck("aws", "KMS", "kms-key-public-access",
               "high",
               "KMS key policy allows access from all principals or all AWS accounts.",
               "Restrict the KMS key policy to specific IAM roles/users. Remove any grants to 'arn:aws:iam::*:root' or principal '*'."),

    # Secrets Manager (2)
    CloudCheck("aws", "Secrets Manager", "secrets-manager-no-rotation",
               "medium",
               "Secret in Secrets Manager does not have automatic rotation configured.",
               "Enable automatic rotation for all secrets. Use Lambda rotation functions or AWS-managed rotation templates where available."),
    CloudCheck("aws", "Secrets Manager", "secrets-manager-no-resource-policy-restriction",
               "medium",
               "Secrets Manager secret has no resource-based policy restricting access.",
               "Apply a resource-based policy to each secret limiting access to specific IAM principals. Use resource tags for ABAC."),

    # EBS (3)
    CloudCheck("aws", "EBS", "ebs-snapshot-public",
               "critical",
               "EBS snapshot is publicly shared, exposing disk contents to any AWS account.",
               "Modify snapshot permissions to remove public sharing. Share only with specific AWS account IDs if needed."),
    CloudCheck("aws", "EBS", "ebs-volume-unencrypted",
               "high",
               "EBS volume does not have encryption enabled.",
               "Enable EBS encryption by default at the account/region level. For existing volumes, create encrypted copies via snapshot."),
    CloudCheck("aws", "EBS", "ebs-snapshot-shared-externally",
               "medium",
               "EBS snapshot is shared with external AWS accounts.",
               "Review and remove external account sharing. Use AWS Config rule 'ebs-snapshot-public-restore' for continuous compliance."),

    # Additional (2)
    CloudCheck("aws", "EC2", "ec2-instance-no-iam-role",
               "medium",
               "EC2 instance has no IAM instance profile attached, requiring long-term credentials in user-data.",
               "Attach an IAM instance profile with least-privilege permissions. Never embed access keys in EC2 user-data or AMIs."),
    CloudCheck("aws", "IAM", "iam-password-policy-weak",
               "medium",
               "IAM password policy does not meet minimum complexity requirements.",
               "Set password policy: minimum 14 chars, require uppercase, lowercase, numbers, symbols, password reuse prevention, and 90-day expiration."),
]


# ---------------------------------------------------------------------------
# Azure checks — 16
# ---------------------------------------------------------------------------

_AZURE_CHECKS: list[CloudCheck] = [
    # Storage (4)
    CloudCheck("azure", "Storage", "azure-storage-account-public-blob",
               "high",
               "Azure Storage account blob container allows anonymous public access.",
               "Disable allowBlobPublicAccess on the storage account. Set container access level to Private. Use SAS tokens for temporary access."),
    CloudCheck("azure", "Storage", "azure-storage-account-https-disabled",
               "medium",
               "Azure Storage account allows unencrypted HTTP traffic (enableHttpsTrafficOnly=False).",
               "Set enableHttpsTrafficOnly=True on the storage account to enforce secure transfer."),
    CloudCheck("azure", "Storage", "azure-storage-account-no-encryption",
               "high",
               "Azure Storage account does not use customer-managed keys (CMK) for encryption.",
               "Configure customer-managed keys via Azure Key Vault for storage encryption. Use Microsoft-managed keys as a minimum baseline."),
    CloudCheck("azure", "Storage", "azure-storage-account-network-access-unrestricted",
               "medium",
               "Azure Storage account network access is not restricted to specific virtual networks or IP ranges.",
               "Configure storage firewall rules to allow access only from specific VNets, subnets, and IP ranges. Set default action to Deny."),

    # NSG / Network Security Group (4)
    CloudCheck("azure", "NSG", "azure-nsg-open-ssh-to-world",
               "high",
               "Network Security Group has an inbound rule allowing SSH (port 22) from any source (0.0.0.0/0).",
               "Restrict the SSH rule to specific source IP prefixes. Use Azure Bastion for secure RDP/SSH access."),
    CloudCheck("azure", "NSG", "azure-nsg-open-rdp-to-world",
               "high",
               "Network Security Group has an inbound rule allowing RDP (port 3389) from any source.",
               "Restrict the RDP rule to specific source IPs. Use Azure Bastion or VPN gateway for remote desktop."),
    CloudCheck("azure", "NSG", "azure-nsg-open-all-ports-to-world",
               "critical",
               "Network Security Group allows all inbound ports from 0.0.0.0/0 (priority 100, port *).",
               "Remove the wildcard inbound rule. Create specific rules for each required service with restricted source ranges."),
    CloudCheck("azure", "NSG", "azure-nsg-open-database-to-world",
               "high",
               "Network Security Group allows inbound database ports (SQL 1433, PostgreSQL 5432, MySQL 3306) from the internet.",
               "Restrict database port rules to application-tier subnets only. Use Private Link for private connectivity to database services."),

    # Key Vault (3)
    CloudCheck("azure", "Key Vault", "azure-key-vault-public-access",
               "high",
               "Key Vault firewall allows access from all networks (defaultAction=Allow).",
               "Set Key Vault firewall defaultAction to Deny. Allow only specific VNets and IP addresses via network rules."),
    CloudCheck("azure", "Key Vault", "azure-key-vault-no-purge-protection",
               "medium",
               "Key Vault does not have purge protection enabled, allowing permanent deletion of keys/secrets.",
               "Enable purge protection (soft delete + purge protection) on all Key Vaults to prevent permanent deletion within retention period."),
    CloudCheck("azure", "Key Vault", "azure-key-vault-key-rotation-disabled",
               "medium",
               "Key Vault key does not have automatic rotation policy configured.",
               "Configure key rotation policy with a defined rotation cadence. Use Azure Policy to enforce rotation across all Key Vault keys."),

    # Azure AD / Entra ID (5)
    CloudCheck("azure", "AAD", "azure-ad-guest-users-present",
               "medium",
               "Azure AD tenant has guest users with broad access to subscriptions or resources.",
               "Review and restrict guest user access. Use Conditional Access policies to limit guest user permissions and require MFA."),
    CloudCheck("azure", "AAD", "azure-ad-mfa-not-required",
               "high",
               "Azure AD Conditional Access policy does not enforce MFA for all users.",
               "Create a Conditional Access policy requiring MFA for all users and all cloud apps. Exclude break-glass accounts with monitoring."),
    CloudCheck("azure", "AAD", "azure-ad-subscription-contributor-access",
               "high",
               "Azure subscription grants Contributor or Owner role to overly broad groups (e.g., all members).",
               "Apply least-privilege RBAC: use custom roles with specific actions. Restrict Owner/Contributor to named administrators only."),
    CloudCheck("azure", "AAD", "azure-ad-legacy-auth-enabled",
               "medium",
               "Azure AD allows legacy authentication protocols (IMAP, POP, SMTP, etc.), bypassing MFA.",
               "Block legacy authentication via Conditional Access policy. Set 'Configure legacy authentication' to 'Block' for all users."),
    CloudCheck("azure", "AAD", "azure-ad-admin-consent-not-required",
               "medium",
               "Azure AD allows users to consent to third-party app permissions without admin approval.",
               "Configure admin consent workflow. Require admin consent for application permissions and high-impact delegated permissions."),
]


# ---------------------------------------------------------------------------
# GCP checks — 16
# ---------------------------------------------------------------------------

_GCP_CHECKS: list[CloudCheck] = [
    # GCS (4)
    CloudCheck("gcp", "GCS", "gcs-bucket-public-read",
               "high",
               "GCS bucket allows public read access via IAM policy binding to allUsers.",
               "Remove the 'roles/storage.objectViewer' binding for 'allUsers'. Use signed URLs for temporary public access."),
    CloudCheck("gcp", "GCS", "gcs-bucket-public-write",
               "critical",
               "GCS bucket allows public write access (roles/storage.objectCreator or objectAdmin to allUsers).",
               "Remove the 'allUsers' binding with write roles immediately. Restrict write access to specific service accounts or users."),
    CloudCheck("gcp", "GCS", "gcs-bucket-no-encryption",
               "medium",
               "GCS bucket does not use customer-managed encryption keys (CMEK).",
               "Enable CMEK using Cloud KMS for bucket encryption. Default Google-managed encryption is the minimum baseline."),
    CloudCheck("gcp", "GCS", "gcs-bucket-uniform-access-disabled",
               "low",
               "GCS bucket does not have uniform bucket-level access enabled, leading to inconsistent ACL/IAM access control.",
               "Enable uniform bucket-level access to enforce consistent IAM-based access control and disable legacy ACLs."),

    # IAM (3)
    CloudCheck("gcp", "IAM", "gcp-iam-allusers-binding",
               "high",
               "GCP IAM policy binds 'allUsers' or 'allAuthenticatedUsers' to a resource with elevated roles.",
               "Remove 'allUsers' and 'allAuthenticatedUsers' bindings. Use specific service accounts, groups, or user principals."),
    CloudCheck("gcp", "IAM", "gcp-iam-owner-role-to-all",
               "critical",
               "GCP project IAM policy grants Owner or Editor role to allAuthenticatedUsers or a broad domain.",
               "Restrict Owner/Editor roles to named administrators. Use custom roles with least-privilege permissions for services."),
    CloudCheck("gcp", "IAM", "gcp-iam-service-account-key-external",
               "medium",
               "GCP service account has user-managed keys that may be shared externally or lack rotation.",
               "Audit and remove unused service account keys. Use short-lived credentials (Workload Identity) instead of long-lived keys."),

    # Compute Engine (3)
    CloudCheck("gcp", "Compute", "gcp-compute-public-ip-exposed",
               "medium",
               "Compute Engine instance has a public IP address assigned without a required use case.",
               "Remove external IP addresses from instances that don't require internet access. Use Cloud NAT for outbound traffic."),
    CloudCheck("gcp", "Compute", "gcp-compute-firewall-open-ssh-to-world",
               "high",
               "GCP firewall rule allows SSH (port 22) from 0.0.0.0/0.",
               "Restrict SSH firewall rule to specific source IP ranges. Use Identity-Aware Proxy (IAP) for SSH tunneling."),
    CloudCheck("gcp", "Compute", "gcp-compute-firewall-open-all-ports",
               "critical",
               "GCP firewall rule allows all incoming traffic (0-65535) from 0.0.0.0/0.",
               "Remove the 0.0.0.0/0 allow-all rule. Create specific firewall rules for each required service with restricted source ranges."),

    # Cloud SQL (3)
    CloudCheck("gcp", "Cloud SQL", "gcp-cloudsql-public-ip",
               "high",
               "Cloud SQL instance has a public IP address, exposing the database to the internet.",
               "Configure Cloud SQL with private IP only. Use Cloud SQL Auth Proxy or Private Service Connect for secure access."),
    CloudCheck("gcp", "Cloud SQL", "gcp-cloudsql-no-encryption",
               "medium",
               "Cloud SQL instance does not use CMEK for encryption at rest.",
               "Enable CMEK via Cloud KMS for the Cloud SQL instance. Default Google-managed encryption is the minimum."),
    CloudCheck("gcp", "Cloud SQL", "gcp-cloudsql-automated-backups-disabled",
               "medium",
               "Cloud SQL instance does not have automated backups enabled.",
               "Enable automated backups with a defined retention window. Configure point-in-time recovery for PITR capability."),

    # Firestore (3)
    CloudCheck("gcp", "Firestore", "gcp-firestore-rules-public-read",
               "high",
               "Firestore security rules allow public read access (allow read: if true).",
               "Replace permissive rules with user-based access control. Restrict read access to authenticated users with proper UID checks."),
    CloudCheck("gcp", "Firestore", "gcp-firestore-rules-public-write",
               "critical",
               "Firestore security rules allow public write access (allow write: if true).",
               "Restrict write rules to authenticated users with validation. Never use 'allow write: if true' in production security rules."),
    CloudCheck("gcp", "Firestore", "gcp-firestore-no-ttl-management",
               "low",
               "Firestore collections do not have TTL policies configured, leading to unbounded data growth.",
               "Configure TTL policies on collections to auto-delete expired documents. Monitor storage costs and set up data retention policies."),
]


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

_ALL_CHECKS: dict[str, list[CloudCheck]] = {
    "aws": _AWS_CHECKS,
    "azure": _AZURE_CHECKS,
    "gcp": _GCP_CHECKS,
}


def get_checks(provider: str = "all", check_type: str = "all") -> list[dict[str, Any]]:
    """Return cloud security audit checks filtered by provider and type.

    Args:
        provider: ``aws``, ``azure``, ``gcp``, or ``all``.
        check_type: ``all``, ``high``, ``critical``, ``medium``, ``low``,
                    or a service name (e.g., ``S3``, ``IAM``, ``Storage``).

    Returns:
        A list of check dictionaries with keys: ``provider``, ``service``,
        ``check_name``, ``severity``, ``description``, ``remediation``.
    """
    provider = provider.lower().strip()
    check_type = check_type.lower().strip()

    providers: list[str]
    if provider == "all":
        providers = ["aws", "azure", "gcp"]
    elif provider in _ALL_CHECKS:
        providers = [provider]
    else:
        return []

    severity_filter: set[str] | None = None
    if check_type in ("critical", "high", "medium", "low", "info"):
        severity_filter = {check_type}
    service_filter: str | None = None
    if check_type not in ("all", "critical", "high", "medium", "low", "info"):
        service_filter = check_type

    results: list[dict[str, Any]] = []
    for p in providers:
        for check in _ALL_CHECKS[p]:
            if severity_filter and check.severity not in severity_filter:
                continue
            if service_filter and check.service.lower() != service_filter:
                continue
            results.append(check.to_dict())
    return results


def count_checks(provider: str = "all") -> dict[str, int]:
    """Return a summary of check counts per provider."""
    if provider == "all":
        return {p: len(checks) for p, checks in _ALL_CHECKS.items()}
    return {provider: len(_ALL_CHECKS.get(provider, []))}


def providers() -> list[str]:
    """Return the list of supported cloud providers."""
    return list(_ALL_CHECKS.keys())