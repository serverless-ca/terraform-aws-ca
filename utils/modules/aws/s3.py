import boto3


def get_s3_bucket(bucket_purpose="internal"):
    """
    Get the full name of the S3 bucket based on its purpose
    """

    s3_client = boto3.client("s3")
    s3_buckets = s3_client.list_buckets()["Buckets"]
    return [b["Name"] for b in s3_buckets if f"-{bucket_purpose}-" in b["Name"]][0]


def put_s3_object(bucket_name, kms_arn, key, data, encryption_algorithm="aws:kms"):
    """
    Put an object in an S3 bucket
    """

    s3_client = boto3.client("s3")
    s3_client.put_object(
        Bucket=bucket_name, SSEKMSKeyId=kms_arn, ServerSideEncryption=encryption_algorithm, Key=key, Body=data
    )
