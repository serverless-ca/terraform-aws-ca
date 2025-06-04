from cryptography.hazmat.primitives import serialization
from utils.certs.kms import kms_get_kms_key_id, kms_get_public_key, kms_describe_key
from utils.certs.crypto import (
    crypto_ca_key_info,
    crypto_revoked_certificate,
    crypto_convert_crl_to_pem,
)
from utils.certs.ca import ca_name, ca_kms_publish_crl, ca_get_ca_info
from utils.certs.db import (
    db_list_certificates,
    db_update_crl_number,
    db_revocation_date,
)
from utils.certs.s3 import s3_download, s3_upload
from cryptography.hazmat.primitives.serialization import load_der_public_key
import datetime
import json
import os


def build_list_of_revoked_certs(project, env_name, external_s3_bucket_name, internal_s3_bucket_name):
    """Build list of revoked certificates for CRL"""
    # handle certificate revocation not enabled
    if not s3_download(external_s3_bucket_name, internal_s3_bucket_name, "revoked.json"):
        print("revoked.json not found")
        return []

    # get list of certificates to be revoked
    revocation_file = s3_download(external_s3_bucket_name, internal_s3_bucket_name, "revoked.json")["Body"]

    revocation_details = json.load(revocation_file)

    revoked_certs = []
    for revocation_detail in revocation_details:
        common_name = revocation_detail["common_name"]
        serial_number = revocation_detail["serial_number"]
        revocation_date = db_revocation_date(project, env_name, common_name, serial_number)
        revoked_cert = crypto_revoked_certificate(serial_number, revocation_date)
        revoked_certs.append(revoked_cert)

    print(f"CA {ca_name(project, env_name, 'issuing')} has {len(revoked_certs)} revoked certificates")
    return revoked_certs


def lambda_handler(event, context):  # pylint:disable=unused-argument,too-many-locals
    project = os.environ["PROJECT"]
    env_name = os.environ["ENVIRONMENT_NAME"]
    external_s3_bucket_name = os.environ["EXTERNAL_S3_BUCKET"]
    internal_s3_bucket_name = os.environ["INTERNAL_S3_BUCKET"]

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

    crl = ca_kms_publish_crl(
        ca_info,
        ca_key_info,
        timedelta,
        build_list_of_revoked_certs(project, env_name, external_s3_bucket_name, internal_s3_bucket_name),
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

    return
