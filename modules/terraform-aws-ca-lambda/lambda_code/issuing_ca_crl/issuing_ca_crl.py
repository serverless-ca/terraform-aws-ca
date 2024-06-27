from cryptography.hazmat.primitives import serialization
from utils.certs.kms import kms_get_kms_key_id, kms_get_public_key, kms_describe_key
from utils.certs.crypto import crypto_ca_key_info, crypto_revoked_certificate
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

from utils.certs.config import Config


def build_list_of_revoked_certs(cfg: Config):
    """Build list of revoked certificates for CRL"""
    # handle certificate revocation not enabled
    if not s3_download(cfg.external_s3_bucket, cfg.internal_s3_bucket, "revoked.json"):
        print("revoked.json not found")
        return []

    # get list of certificates to be revoked
    revocation_file = s3_download(cfg.external_s3_bucket, cfg.internal_s3_bucket, "revoked.json")["Body"]

    revocation_details = json.load(revocation_file)

    revoked_certs = []
    for revocation_detail in revocation_details:
        common_name = revocation_detail["common_name"]
        serial_number = revocation_detail["serial_number"]
        revocation_date = db_revocation_date(cfg.project, cfg.environment_name, common_name, serial_number)
        revoked_cert = crypto_revoked_certificate(serial_number, revocation_date)
        revoked_certs.append(revoked_cert)

    print(f"CA {ca_name(cfg.project, cfg.environment_name, 'issuing')} has {len(revoked_certs)} revoked certificates")
    return revoked_certs


def lambda_handler(event, context):  # pylint:disable=unused-argument
    cfg = Config.from_env()

    ca_slug = ca_name(cfg.project, cfg.environment_name, "issuing")

    # check CA exists
    if not db_list_certificates(cfg.project, cfg.environment_name, ca_slug):
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
    ca_info = ca_get_ca_info(cfg.issuing_ca_info, cfg.root_ca_info)

    crl = ca_kms_publish_crl(
        ca_info,
        ca_key_info,
        timedelta,
        build_list_of_revoked_certs(cfg),
        db_update_crl_number(
            cfg.project,
            cfg.environment_name,
            ca_slug,
            db_list_certificates(cfg.project, cfg.environment_name, ca_slug)[0]["SerialNumber"]["S"],
        ),
        kms_describe_key(kms_key_id)["SigningAlgorithms"][0],
    ).public_bytes(encoding=serialization.Encoding.DER)

    # upload CRL to S3
    s3_upload(cfg.external_s3_bucket, cfg.internal_s3_bucket, crl, f"{ca_slug}.crl")

    return
