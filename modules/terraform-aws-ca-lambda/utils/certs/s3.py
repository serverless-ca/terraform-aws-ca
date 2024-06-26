import os
import boto3


def s3_download_file(bucket_name, key):
    client = boto3.client("s3")

    print(f"downloading {key} from s3 bucket {bucket_name}")

    try:
        return client.get_object(
            Bucket=bucket_name,
            Key=key,
        )
    except client.exceptions.NoSuchKey:
        print(f"file {key} not found in s3 bucket {bucket_name}")

    return None


def s3_download(external_s3_bucket_name, internal_s3_bucket_name, key, internal=True):
    if internal:
        return s3_download_file(internal_s3_bucket_name, key)

    return s3_download_file(external_s3_bucket_name, key)


def s3_upload_file(file, bucket_name, key, content_type):
    client = boto3.client("s3")

    client.put_object(Body=file, Bucket=bucket_name, Key=key, ContentType=content_type)
    print(f"uploaded {key} to s3 bucket {bucket_name}")


def s3_upload(
    external_s3_bucket_name, internal_s3_bucket_name, file, key, content_type="application/x-pkcs7-crl", external=True
):
    if external:
        return s3_upload_file(file, external_s3_bucket_name, key, content_type)

    return s3_upload_file(file, internal_s3_bucket_name, key, content_type)
