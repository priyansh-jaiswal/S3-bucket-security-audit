#!/usr/bin/env python3
"""
S3 Bucket Security Audit Tool — built from scratch, step by step.
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def get_session(profile=None, region=None):
    """
    A boto3 Session is what actually holds your credentials + region.
    Clients (like s3) are created FROM a session. Passing profile=None
    just means "use whatever's in ~/.aws/credentials as default."
    """
    kwargs = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    return boto3.Session(**kwargs)


def list_buckets(s3_client):
    """s3:ListAllMyBuckets — the one call that's account-wide, not per-bucket."""
    response = s3_client.list_buckets()
    return [b["Name"] for b in response.get("Buckets", [])]


def check_public_access_block(s3_client, bucket_name):
    """
    Block Public Access has 4 independent switches (BlockPublicAcls,
    IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets). All 4
    need to be True for a bucket to be fully protected.

    If it's never been configured, AWS doesn't return a default object —
    it raises a ClientError with a specific error code. That's not a
    real failure, it just means "nothing set," so we catch it deliberately.
    """
    try:
        resp = s3_client.get_public_access_block(Bucket=bucket_name)
        config = resp["PublicAccessBlockConfiguration"]
        return {"configured": True, "all_blocked": all(config.values()), "settings": config}
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return {"configured": False, "all_blocked": False, "settings": {}}
        raise  # anything else is a real error — don't swallow it


def check_bucket_acl(s3_client, bucket_name):
    """
    ACLs are the old (pre-2011) access control mechanism. Grants go to
    "grantees," identified by a URI. Two matter a lot:
      - AllUsers          = anyone on the internet, no AWS account needed
      - AuthenticatedUsers = deceptively named — this means ANY AWS
        account on Earth, not "authenticated users in your company."
        This is a very common real-world misconfiguration precisely
        because the name sounds safe.
    """
    findings = []
    acl = s3_client.get_bucket_acl(Bucket=bucket_name)
    for grant in acl.get("Grants", []):
        uri = grant.get("Grantee", {}).get("URI", "")
        if "AllUsers" in uri:
            findings.append({
                "severity": "HIGH",
                "detail": f"ACL grants '{grant.get('Permission')}' to AllUsers (anyone on the internet)",
            })
        elif "AuthenticatedUsers" in uri:
            findings.append({
                "severity": "MEDIUM",
                "detail": f"ACL grants '{grant.get('Permission')}' to AuthenticatedUsers (any AWS account, not just yours)",
            })
    return findings


import json


def check_bucket_policy(s3_client, bucket_name):
    """
    A bucket policy is a JSON document. "Principal": "*" with no
    "Condition" means "anyone, unconditionally" — the classic public-
    bucket breach pattern. A Condition (e.g., restricting by IP or
    requiring HTTPS) can make a "*" principal safe, so we specifically
    check for its absence, not just the presence of "*".
    """
    findings = []
    try:
        policy = json.loads(s3_client.get_bucket_policy(Bucket=bucket_name)["Policy"])
        for statement in policy.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue
            principal = statement.get("Principal")
            is_public = principal == "*" or principal == {"AWS": "*"}
            if is_public and "Condition" not in statement:
                findings.append({
                    "severity": "HIGH",
                    "detail": f"Bucket policy allows public access with no restricting condition "
                              f"(statement: {statement.get('Sid', 'unnamed')})",
                })
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
            raise
    return findings


def check_encryption(s3_client, bucket_name):
    """Same pattern as Block Public Access: no config = a specific ClientError, not a default."""
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return False
        raise


def check_versioning(s3_client, bucket_name):
    """Versioning protects against accidental delete/overwrite — and is a ransomware mitigation."""
    return s3_client.get_bucket_versioning(Bucket=bucket_name).get("Status", "Disabled") == "Enabled"


def check_logging(s3_client, bucket_name):
    """Logging is your forensic trail — without it you often can't tell what an attacker took."""
    return "LoggingEnabled" in s3_client.get_bucket_logging(Bucket=bucket_name)


def audit_bucket(s3_client, bucket_name):
    """
    Runs every check against one bucket and rolls the results up into
    a single risk_level. The logic is deliberately simple: if ANY
    finding is HIGH, the bucket is HIGH — one bad public-access hole
    matters more than five missing-logging notes combined.
    """
    findings = []

    pab = check_public_access_block(s3_client, bucket_name)
    if not pab["all_blocked"]:
        findings.append({
            "severity": "HIGH" if not pab["configured"] else "MEDIUM",
            "detail": "Block Public Access is not fully enabled on this bucket",
        })

    findings.extend(check_bucket_acl(s3_client, bucket_name))
    findings.extend(check_bucket_policy(s3_client, bucket_name))

    if not check_encryption(s3_client, bucket_name):
        findings.append({"severity": "LOW", "detail": "Default encryption is not enabled"})
    if not check_versioning(s3_client, bucket_name):
        findings.append({"severity": "LOW", "detail": "Versioning is not enabled"})
    if not check_logging(s3_client, bucket_name):
        findings.append({"severity": "LOW", "detail": "Access logging is not enabled"})

    severities = [f["severity"] for f in findings]
    if "HIGH" in severities:
        risk_level = "HIGH"
    elif "MEDIUM" in severities:
        risk_level = "MEDIUM"
    elif "LOW" in severities:
        risk_level = "LOW"
    else:
        risk_level = "CLEAN"

    return {"bucket": bucket_name, "findings": findings, "risk_level": risk_level}


def print_report(results):
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "CLEAN": 3}
    for r in sorted(results, key=lambda r: order[r["risk_level"]]):
        print(f"\n{r['bucket']}  [{r['risk_level']}]")
        for f in r["findings"]:
            print(f"  [{f['severity']}] {f['detail']}")
        if not r["findings"]:
            print("  No issues found.")


def remediate_bucket(s3_client, bucket_name, dry_run=True):
    """
    Only ever enables Block Public Access — never deletes data, never
    touches anything else. dry_run defaults to True on purpose: the
    caller (main, below) only flips it to False after a human has
    typed 'y' at a prompt. No silent automatic changes, ever.
    """
    if dry_run:
        return "would enable Block Public Access"
    s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )
    return "enabled Block Public Access"


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Audit S3 buckets for common misconfigurations.")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--region", default=None)
    parser.add_argument("--remediate", action="store_true", help="Offer to fix HIGH risk buckets (asks first)")
    args = parser.parse_args()

    try:
        s3 = get_session(args.profile, args.region).client("s3")
        buckets = list_buckets(s3)
    except NoCredentialsError:
        print("No AWS credentials found. Run `aws configure` or pass --profile.")
        return

    print(f"Scanning {len(buckets)} bucket(s)...")
    results = [audit_bucket(s3, b) for b in buckets]
    print_report(results)

    if args.remediate:
        for r in [r for r in results if r["risk_level"] == "HIGH"]:
            if input(f"\nEnable Block Public Access on '{r['bucket']}'? [y/N]: ").lower() == "y":
                print(" ->", remediate_bucket(s3, r["bucket"], dry_run=False))


if __name__ == "__main__":
    main()
