import boto3


def get_s3_bucket(bucket_purpose="internal"):
    """
    Get the full name of the S3 bucket based on its purpose
    """

    s3_client = boto3.client("s3")
    s3_buckets = s3_client.list_buckets()["Buckets"]
    return [b["Name"] for b in s3_buckets if f"-{bucket_purpose}-" in b["Name"]][0]


def list_s3_object_keys(bucket_name):
    """
    List object keys in S3 bucket
    """

    s3_client = boto3.client("s3")
    response = s3_client.list_objects_v2(Bucket=bucket_name)

    s3_objects = response["Contents"]

    return [s3_object["Key"] for s3_object in s3_objects]


def get_s3_object(bucket_name, key):
    """
    Get object from S3
    """

    s3_client = boto3.client("s3")
    response = s3_client.get_object(Bucket=bucket_name, Key=key)

    return response["Body"].read()


def put_s3_object(bucket_name, kms_arn, key, data, encryption_algorithm="aws:kms"):
    """
    Put object in S3 bucket
    """

    s3_client = boto3.client("s3")
    s3_client.put_object(
        Bucket=bucket_name, SSEKMSKeyId=kms_arn, ServerSideEncryption=encryption_algorithm, Key=key, Body=data
    )


def delete_s3_object(bucket_name, key):
    """
    Delete object from S3
    """

    s3_client = boto3.client("s3")
    s3_client.delete_object(Bucket=bucket_name, Key=key)
