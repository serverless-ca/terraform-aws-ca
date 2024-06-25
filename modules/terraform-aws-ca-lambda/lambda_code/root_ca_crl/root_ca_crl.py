from cryptography.hazmat.primitives import serialization
from utils.certs.kms import kms_get_kms_key_id, kms_get_public_key, kms_describe_key
from utils.certs.crypto import crypto_ca_key_info, crypto_revoked_certificate
from utils.certs.ca import ca_name, ca_kms_publish_crl
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


def build_list_of_revoked_certs(project, env_name):
    """Build list of revoked certificates for CRL"""
    # handle certificate revocation not enabled
    if not s3_download("revoked-root-ca.json"):
        print("revoked-root-ca.json not found")
        return []

    # get list of certificates to be revoked
    revocation_file = s3_download("revoked-root-ca.json")["Body"]

    revocation_details = json.load(revocation_file)

    revoked_certs = []
    for revocation_detail in revocation_details:
        common_name = revocation_detail["common_name"]
        serial_number = revocation_detail["serial_number"]
        revocation_date = db_revocation_date(project, env_name, common_name, serial_number)
        revoked_cert = crypto_revoked_certificate(serial_number, revocation_date)
        revoked_certs.append(revoked_cert)

    print(f"CA {ca_name('root')} has {len(revoked_certs)} revoked certificates")
    return revoked_certs


def lambda_handler(event, context):  # pylint:disable=unused-argument
    project = os.environ["PROJECT"]
    env_name = os.environ["ENVIRONMENT_NAME"]

    ca_slug = ca_name("root")

    # check CA exists
    if not db_list_certificates(project, env_name, ca_slug):
        print(f"CA {ca_slug} not found")

        return

    # get key details from KMS
    kms_key_id = kms_get_kms_key_id(ca_slug)
    public_key = load_der_public_key(kms_get_public_key(kms_key_id))

    root_crl_days = int(os.environ["ROOT_CRL_DAYS"])
    root_crl_seconds = int(os.environ["ROOT_CRL_SECONDS"])

    # issue CRL valid for one day 10 minutes
    timedelta = datetime.timedelta(root_crl_days, root_crl_seconds, 0)
    ca_key_info = crypto_ca_key_info(public_key, kms_key_id, ca_slug)
    crl = ca_kms_publish_crl(
        ca_key_info,
        timedelta,
        build_list_of_revoked_certs(project, env_name),
        db_update_crl_number(
            project, env_name, ca_slug, db_list_certificates(project, env_name, ca_slug)[0]["SerialNumber"]["S"]
        ),
        kms_describe_key(kms_key_id)["SigningAlgorithms"][0],
    ).public_bytes(encoding=serialization.Encoding.DER)

    # upload CRL to S3
    s3_upload(crl, f"{ca_slug}.crl")

    return
