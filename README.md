# S3 Bucket Security Audit Tool

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

A Python + boto3 CLI tool that scans every S3 bucket in an AWS account for
common security misconfigurations — public access, missing encryption,
missing versioning, missing logging — and risk-ranks each bucket
HIGH/MEDIUM/LOW. Includes an optional guided remediation mode that fixes
public-access issues with explicit per-bucket confirmation.

## Why this exists

Misconfigured S3 buckets are one of the most common sources of real-world
data breaches, and most small teams don't have anyone checking for this
regularly. This tool gives a fast, repeatable way to catch the issues that
matter most, without needing a dedicated security engineer.

## Features

- 🔍 Scans every bucket in an AWS account in one run
- 🚦 Risk-ranks findings (HIGH / MEDIUM / LOW) so the worst issues surface first
- 🛠️ Optional guided remediation — enables Block Public Access on flagged
  buckets, with a confirmation prompt per bucket (never silent, never automatic)
- 🔐 Least-privilege IAM by design — a read-only policy for scanning, with
  the extra remediation permission kept in a separate policy file
- 🧪 Fully testable without a real AWS account, via mocked infrastructure

## How it works

For every bucket, the tool checks:
1. **Block Public Access** — all 4 settings must be enabled for a bucket to be fully protected
2. **Bucket ACLs** — flags grants to `AllUsers` (anyone on the internet) or `AuthenticatedUsers` (any AWS account, not just yours)
3. **Bucket policy** — flags `Principal: "*"` statements with no restricting `Condition`
4. **Default encryption**
5. **Versioning**
6. **Access logging**

Each bucket gets an overall risk level based on its worst finding.

## Setup

```bash
git clone <this-repo-url>
cd s3-audit-scratch
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
aws configure --profile s3-audit   # attach policies/audit-readonly-policy.json to this identity
```

## Usage

```bash
# Scan and print to console
python s3_audit.py --profile s3-audit --region <your-region>

# Scan AND offer to fix HIGH risk public-access issues (asks before each change)
python s3_audit.py --profile s3-audit --region <your-region> --remediate
```

## Tested against real AWS infrastructure

This wasn't just run against the mocked demo — it was validated against a
real (deliberately misconfigured) test bucket on AWS:

**Before remediation:**
```
priyansh-test-audit-2026  [HIGH]
  [MEDIUM] Block Public Access is not fully enabled on this bucket
  [HIGH] Bucket policy allows public access with no restricting condition (statement: PublicRead)
  [LOW] Versioning is not enabled
  [LOW] Access logging is not enabled
```

**After running `--remediate`:**
```
priyansh-test-audit-2026  [HIGH]
  [HIGH] Bucket policy allows public access with no restricting condition (statement: PublicRead)
  [LOW] Versioning is not enabled
  [LOW] Access logging is not enabled
```

The Block Public Access finding clears after remediation; the bucket policy
finding correctly remains, since remediation only ever touches Block Public
Access — never bucket policies — by design. See `docs/screenshots/` for the
original terminal captures.

One real finding worth calling out from testing: attempting remediation
*before* attaching the separate remediate IAM policy correctly failed with
an `AccessDenied` error. That's least-privilege IAM working as intended —
a concrete example of the principle in action, not just a design claim.

## Test without touching real AWS

```bash
python demo.py
```

This spins up mock S3 buckets (via [moto](https://github.com/getmoto/moto))
with a mix of secure and insecure configurations and runs the real audit
logic against them — no AWS account, no cost, no risk.

## IAM setup (least privilege)

| File | Purpose |
|---|---|
| `policies/audit-readonly-policy.json` | Attach for day-to-day scanning. Read-only — can't modify anything. |
| `policies/remediate-additional-policy.json` | Attach only if you want `--remediate` to work. Grants exactly one additional permission: `s3:PutBucketPublicAccessBlock`. |

Keeping these separate means the everyday scanning identity has no ability
to change anything in the account, even by accident.

## Roadmap

- [ ] Cost-analysis module (idle EC2, unattached EBS volumes, old snapshots)
- [ ] Terraform module to deploy as a scheduled Lambda function
- [ ] Slack/email notification on new HIGH risk findings
- [ ] Historical tracking — diff against the previous run

## Tech stack

Python 3 · boto3 · moto (testing) · argparse

## License

MIT — see [LICENSE](LICENSE)
