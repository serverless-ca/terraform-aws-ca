import os
import boto3


external_s3_bucket_name = os.environ["EXTERNAL_S3_BUCKET"]
internal_s3_bucket_name = os.environ["INTERNAL_S3_BUCKET"]


def s3_download(key, internal=True):
    client = boto3.client("s3")

    if internal:
        print(f"downloading {key} from s3 bucket {internal_s3_bucket_name}")

        try:
            return client.get_object(
                Bucket=internal_s3_bucket_name,
                Key=key,
            )
        except client.exceptions.NoSuchKey:
            print(f"file {key} not found in s3 bucket {internal_s3_bucket_name}")
            return None

    print(f"downloading {key} from s3 bucket {external_s3_bucket_name}")

    try:
        return client.get_object(
            Bucket=external_s3_bucket_name,
            Key=key,
        )
    except client.exceptions.NoSuchKey:
        print(f"file {key} not found in s3 bucket {external_s3_bucket_name}")
        return None


def s3_upload(file, key, content_type="application/x-pkcs7-crl", external=True):
    client = boto3.client("s3")

    if external:
        client.put_object(Body=file, Bucket=external_s3_bucket_name, Key=key, ContentType=content_type)
        print(f"uploaded {key} to s3 bucket {external_s3_bucket_name}")

        return

    client.put_object(Body=file, Bucket=internal_s3_bucket_name, Key=key, ContentType=content_type)
    print(f"uploaded {key} to s3 bucket {internal_s3_bucket_name}")

    return
