import boto3
import json


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


# pylint:disable=too-many-arguments
def s3_upload(
    external_s3_bucket_name, internal_s3_bucket_name, file, key, content_type="application/x-pkcs7-crl", external=True
):
    if external:
        return s3_upload_file(file, external_s3_bucket_name, key, content_type)

    return s3_upload_file(file, internal_s3_bucket_name, key, content_type)


def convert_x509_subject_str_to_dict(input_str):
    # split string by commas
    pairs = input_str.split(",")

    # split each pair by '=' and construct dictionary
    json_dictionary = {}
    for pair in pairs:
        key, value = pair.split("=")
        json_dictionary[key] = value

    return json_dictionary


def cert_issued_via_gitops(internal_s3_bucket_name, subject):
    # get list of GitOps certificates from internal S3 bucket
    tls_file = s3_download_file(internal_s3_bucket_name, "tls.json")

    return is_cert_gitops(tls_file, subject)


def is_cert_gitops(tls_file, subject):
    subject_json = convert_x509_subject_str_to_dict(subject)

    cn = subject_json["CN"]
    o = subject_json.get("O")
    ou = subject_json.get("OU")

    if tls_file is None:
        gitops_certs = []

    else:
        # convert to json dictionary
        gitops_certs = json.loads(tls_file["Body"].read())

    for cert in gitops_certs:
        common_name = cert["common_name"]
        organization = cert.get("organization")
        organizational_unit = cert.get("organizational_unit")

        # check if certificate is included in tls.json
        cn_matches = False
        o_matches = False
        ou_matches = False

        if cn == common_name:
            cn_matches = True

        if o is None or organization is None or o == organization:
            o_matches = True

        if ou is None or organizational_unit is None or ou == organizational_unit:
            ou_matches = True

        if cn_matches and o_matches and ou_matches:
            return True

    return False
