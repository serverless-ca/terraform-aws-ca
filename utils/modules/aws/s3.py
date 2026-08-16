import boto3
import os


def get_s3_bucket(bucket_purpose="internal", session=None):
    """
    Get the full name of the S3 bucket based on its purpose
    """

    if session is None:
        s3_client = boto3.client("s3")
    else:
        s3_client = session.client("s3")

    s3_buckets = s3_client.list_buckets()["Buckets"]
    matches = [b["Name"] for b in s3_buckets if f"-{bucket_purpose}-" in b["Name"]]

    # optional CA_PROJECT filter to target one of several CA deployments in the same account
    project = os.environ.get("CA_PROJECT")
    if project:
        project_matches = [name for name in matches if f"-{project}-ca-" in name]
        if project_matches:
            return project_matches[0]
        # the external bucket may be shared between deployments and named after another
        # project; only accept a bucket not named after this project if it's unambiguous
        if len(matches) != 1:
            raise ValueError(
                f"Expected exactly one {bucket_purpose} S3 bucket for project {project}, found {matches or 'none'}"
            )

    return matches[0]


def list_s3_object_keys(bucket_name, session=None):
    """
    List object keys in S3 bucket
    """

    if session is None:
        s3_client = boto3.client("s3")
    else:
        s3_client = session.client("s3")

    response = s3_client.list_objects_v2(Bucket=bucket_name)

    s3_objects = response["Contents"]

    return [s3_object["Key"] for s3_object in s3_objects]


def get_s3_object(bucket_name, key, session=None):
    """
    Get object from S3
    """

    if session is None:
        s3_client = boto3.client("s3")
    else:
        s3_client = session.client("s3")

    response = s3_client.get_object(Bucket=bucket_name, Key=key)

    return response["Body"].read()


def put_s3_object(
    bucket_name, kms_arn, key, data, encryption_algorithm="aws:kms", session=None
):  # pylint:disable=too-many-arguments,too-many-positional-arguments
    """
    Put object in S3 bucket
    """

    if session is None:
        s3_client = boto3.client("s3")
    else:
        s3_client = session.client("s3")

    s3_client.put_object(
        Bucket=bucket_name, SSEKMSKeyId=kms_arn, ServerSideEncryption=encryption_algorithm, Key=key, Body=data
    )


def delete_s3_object(bucket_name, key, session=None):
    """
    Delete object from S3
    """

    if session is None:
        s3_client = boto3.client("s3")
    else:
        s3_client = session.client("s3")

    s3_client.delete_object(Bucket=bucket_name, Key=key)
