import base64

from utils.certs.kms import kms_get_kms_key_id, kms_get_public_key, kms_describe_key
from utils.certs.config import Config
from utils.certs.crypto import crypto_cert_info
from utils.certs.ca import ca_name, ca_create_kms_root_ca
from utils.certs.db import db_ca_cert_issued, db_list_certificates
from utils.certs.s3 import s3_upload
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_der_public_key


lifetime = 7300


def lambda_handler(event, context):  # pylint:disable=unused-argument
    cfg = Config.from_env()

    ca_slug = ca_name(cfg.project, cfg.environment_name, "root")

    # check if CA already exists
    if db_list_certificates(cfg.project, cfg.environment_name, ca_slug):
        print(f"CA {ca_slug} already exists. To recreate, first delete item in DynamoDB")

        return

    # get key details from KMS
    kms_key_id = kms_get_kms_key_id(ca_slug)
    cipher = kms_describe_key(kms_key_id)["KeySpec"]
    public_key = load_der_public_key(kms_get_public_key(kms_key_id))

    print(f"using {cipher} key pair in KMS for {ca_slug}")

    pem_certificate = ca_create_kms_root_ca(
        public_key, kms_key_id, cfg.root_ca_info, kms_describe_key(kms_key_id)["SigningAlgorithms"][0]
    )
    base64_certificate = base64.b64encode(pem_certificate)

    # get details to upload to DynamoDB
    cert = load_pem_x509_certificate(pem_certificate)
    info = crypto_cert_info(cert, ca_slug)

    # create entry in DynamoDB
    db_ca_cert_issued(cfg.project, cfg.environment_name, info, base64_certificate)

    # upload CRL to S3
    s3_upload(cfg.external_s3_bucket, cfg.internal_s3_bucket, pem_certificate, f"{ca_slug}.crt")

    return
