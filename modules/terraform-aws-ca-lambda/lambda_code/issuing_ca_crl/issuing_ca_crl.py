from cryptography.hazmat.primitives import serialization
from utils.aws.sns import publish_to_sns
from utils.certs.kms import kms_get_kms_key_id, kms_get_public_key, kms_describe_key
from utils.certs.crypto import (
    crypto_ca_key_info,
    crypto_revoked_certificate,
    crypto_convert_crl_to_pem,
)
from utils.certs.ca import ca_name, ca_kms_publish_crl, ca_get_ca_info
from utils.certs.db import (
    db_list_certificates,
    db_list_revoked_certificates,
    db_update_crl_number,
    db_revocation_date,
    db_get_certificate,
)
from utils.certs.s3 import s3_download, s3_upload
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.x509 import load_pem_x509_certificate
import base64
import datetime
import json
import os


def list_revoked_certs_from_db(project, env_name, ca_slug):
    """List revoked certificates from DynamoDB"""
    revoked_certs_db = db_list_revoked_certificates(project, env_name)

    # exclude revoked CA certificates
    # TODO: only include certs in database revoked by this Issuing CA
    revoked_certs_db = [cert for cert in revoked_certs_db if cert["CommonName"]["S"] != ca_slug]

    revoked_certs = []
    for revoked_cert_db in revoked_certs_db:
        serial_number = revoked_cert_db["SerialNumber"]["S"]
        revocation_date_str = revoked_cert_db["Revoked"]["S"]
        # Parse the stored date string to datetime object using the correct format
        revocation_date = datetime.datetime.strptime(revocation_date_str, "%Y-%m-%d %H:%M:%S")
        revoked_cert = crypto_revoked_certificate(serial_number, revocation_date)
        revoked_certs.append(revoked_cert)

    print(f"CA {ca_name(project, env_name, 'issuing')} has {len(revoked_certs)} revoked certificates from DB")
    return revoked_certs


# pylint:disable=too-many-locals
def list_revoked_certs_from_s3(project, env_name, external_s3_bucket_name, internal_s3_bucket_name):
    """List revoked certificates from S3"""
    newly_revoked_details = []
    # handle certificate revocation not enabled
    if not s3_download(external_s3_bucket_name, internal_s3_bucket_name, "revoked.json"):
        print("revoked.json not found")
        return [], []

    # get list of certificates to be revoked
    revocation_file = s3_download(external_s3_bucket_name, internal_s3_bucket_name, "revoked.json")["Body"]

    revocation_details = json.load(revocation_file)

    revoked_certs = []
    for revocation_detail in revocation_details:
        common_name = revocation_detail["common_name"]
        serial_number = revocation_detail["serial_number"]

        cert_item = db_get_certificate(project, env_name, common_name, serial_number)
        already_revoked = "Revoked" in cert_item

        revocation_date = db_revocation_date(project, env_name, common_name, serial_number)
        revoked_cert = crypto_revoked_certificate(serial_number, revocation_date)
        revoked_certs.append(revoked_cert)

        if not already_revoked:
            cert_bytes = base64.b64decode(cert_item["Certificate"]["B"])
            cert = load_pem_x509_certificate(cert_bytes)
            dn = cert.subject.rfc4514_string()
            newly_revoked_details.append(
                {
                    "CommonName": common_name,
                    "SerialNumber": serial_number,
                    "Revoked": str(revocation_date),
                    "DistinguishedName": dn,
                }
            )

    print(f"CA {ca_name(project, env_name, 'issuing')} has {len(revoked_certs)} revoked certificates from S3")
    return revoked_certs, newly_revoked_details


def build_list_of_revoked_certs(project, env_name, external_s3_bucket_name, internal_s3_bucket_name, ca_slug):
    revoked_certs_db = list_revoked_certs_from_db(project, env_name, ca_slug)
    revoked_certs_s3, newly_revoked_details = list_revoked_certs_from_s3(
        project, env_name, external_s3_bucket_name, internal_s3_bucket_name
    )

    # Use dict to deduplicate by serial number (keeps first occurrence)
    unique_certs = {cert.serial_number: cert for cert in revoked_certs_db + revoked_certs_s3}

    # Sort by serial number and return as list
    return sorted(unique_certs.values(), key=lambda cert: cert.serial_number), newly_revoked_details


def sns_notify_cert_revoked(cert_details, sns_topic_arn):
    keys_to_publish = ["CommonName", "SerialNumber", "Revoked", "DistinguishedName"]
    response = publish_to_sns(cert_details, "Certificate Revoked", sns_topic_arn, keys_to_publish)

    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    common_name = cert_details["CommonName"]
    print(f"Revocation details for {common_name} published to SNS")


def lambda_handler(event, context):  # pylint:disable=unused-argument,too-many-locals
    project = os.environ["PROJECT"]
    env_name = os.environ["ENVIRONMENT_NAME"]
    external_s3_bucket_name = os.environ["EXTERNAL_S3_BUCKET"]
    internal_s3_bucket_name = os.environ["INTERNAL_S3_BUCKET"]
    sns_topic_arn = os.environ["SNS_TOPIC_ARN"]

    issuing_ca_info = json.loads(os.environ["ISSUING_CA_INFO"])
    root_ca_info = json.loads(os.environ["ROOT_CA_INFO"])

    ca_slug = ca_name(project, env_name, "issuing")

    # check CA exists
    if not db_list_certificates(project, env_name, ca_slug):
        print(f"CA {ca_slug} not found")

        return

    # get key details from KMS
    kms_key_id = kms_get_kms_key_id(ca_slug)
    public_key = load_der_public_key(kms_get_public_key(kms_key_id))

    issuing_crl_days = int(os.environ["ISSUING_CRL_DAYS"])
    issuing_crl_seconds = int(os.environ["ISSUING_CRL_SECONDS"])

    # issue CRL valid for one day 10 minutes
    timedelta = datetime.timedelta(issuing_crl_days, issuing_crl_seconds, 0)
    ca_key_info = crypto_ca_key_info(public_key, kms_key_id, ca_slug)
    ca_info = ca_get_ca_info(issuing_ca_info, root_ca_info)

    revoked_certs, newly_revoked_details = build_list_of_revoked_certs(
        project, env_name, external_s3_bucket_name, internal_s3_bucket_name, ca_slug
    )

    crl = ca_kms_publish_crl(
        ca_info,
        ca_key_info,
        timedelta,
        revoked_certs,
        db_update_crl_number(
            project, env_name, ca_slug, db_list_certificates(project, env_name, ca_slug)[0]["SerialNumber"]["S"]
        ),
        kms_describe_key(kms_key_id)["SigningAlgorithms"][0],
    ).public_bytes(encoding=serialization.Encoding.DER)

    # convert CRL to PEM format
    crl_pem = crypto_convert_crl_to_pem(crl)

    # upload CRL to S3
    s3_upload(external_s3_bucket_name, internal_s3_bucket_name, crl, f"{ca_slug}.crl")
    s3_upload(external_s3_bucket_name, internal_s3_bucket_name, crl_pem, f"{ca_slug}.crl.pem")

    for revoked_cert in newly_revoked_details:
        sns_notify_cert_revoked(revoked_cert, sns_topic_arn)

    return
