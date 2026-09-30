from moto import mock_aws
import boto3
import s3_audit


@mock_aws
def run():
    s3 = boto3.client("s3", region_name="us-east-1")

    s3.create_bucket(Bucket="clean-bucket")
    s3.put_public_access_block(Bucket="clean-bucket", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_encryption(Bucket="clean-bucket", ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
    s3.put_bucket_versioning(Bucket="clean-bucket", VersioningConfiguration={"Status": "Enabled"})

    s3.create_bucket(Bucket="public-bucket")
    s3.put_bucket_policy(Bucket="public-bucket", Policy='{"Version":"2012-10-17","Statement":'
        '[{"Sid":"Pub","Effect":"Allow","Principal":"*","Action":"s3:GetObject",'
        '"Resource":"arn:aws:s3:::public-bucket/*"}]}')

    s3.create_bucket(Bucket="unconfigured-bucket")

    results = [s3_audit.audit_bucket(s3, b) for b in s3_audit.list_buckets(s3)]
    s3_audit.print_report(results)


if __name__ == "__main__":
    run()
