# S3 Bucket Security Audit Tool

Scans every S3 bucket in an AWS account for public access, missing
encryption, missing versioning, and missing logging — then risk-ranks
each bucket HIGH/MEDIUM/LOW. Built and tested one function at a time
(see build history / commits), each verified against a mock AWS account
before moving to the next.

## Setup
```bash
pip install -r requirements.txt
aws configure --profile s3-audit   # attach policies/audit-readonly-policy.json
```

## Usage
```bash
python s3_audit.py --profile s3-audit
python s3_audit.py --profile s3-audit --remediate   # asks before fixing anything
```

## Test without touching real AWS
```bash
python demo.py
```

## IAM
`policies/audit-readonly-policy.json` — attach for day-to-day scanning.
`policies/remediate-additional-policy.json` — attach only if using `--remediate`.
