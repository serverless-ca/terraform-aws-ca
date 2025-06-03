import base64
import json
import os
from utils.certs.kms import kms_get_kms_key_id, kms_describe_key
from utils.certs.crypto import (
    crypto_kms_ca_cert_signing_request,
    crypto_cert_info,
    crypto_create_ca_bundle,
)
from utils.certs.ca import ca_kms_sign_ca_certificate_request, ca_name, ca_bundle_name
from utils.certs.db import db_ca_cert_issued, db_list_certificates
from utils.certs.s3 import s3_upload
from cryptography.x509 import load_pem_x509_certificate, load_pem_x509_csr


lifetime = 3650


def lambda_handler(event, context):  # pylint:disable=unused-argument,too-many-locals
    project = os.environ["PROJECT"]
    env_name = os.environ["ENVIRONMENT_NAME"]
    external_s3_bucket_name = os.environ["EXTERNAL_S3_BUCKET"]
    internal_s3_bucket_name = os.environ["INTERNAL_S3_BUCKET"]
    domain = os.environ.get("DOMAIN")

    public_crl = os.environ.get("PUBLIC_CRL")
    enable_public_crl = False
    if public_crl == "enabled":
        enable_public_crl = True

    issuing_ca_info = json.loads(os.environ["ISSUING_CA_INFO"])

    root_ca_name = ca_name(project, env_name, "root")
    ca_slug = ca_name(project, env_name, "issuing")

    # check Root CA exists
    if not db_list_certificates(project, env_name, root_ca_name):
        print(f"CA {root_ca_name} not found")

        return

    # check if Issuing CA already exists
    if db_list_certificates(project, env_name, ca_slug):
        print(f"CA {ca_slug} already exists. To recreate, first delete item in DynamoDB")

        return

    # get issuing CA key details from KMS
    kms_key_id = kms_get_kms_key_id(ca_slug)
    cipher = kms_describe_key(kms_key_id)["KeySpec"]

    print(f"using {cipher} key pair in KMS for {ca_slug}")

    # get root CA key details from KMS
    root_ca_kms_key_id = kms_get_kms_key_id(root_ca_name)

    # create certificate signing request
    csr = load_pem_x509_csr(
        crypto_kms_ca_cert_signing_request(ca_slug, kms_key_id, kms_describe_key(kms_key_id)["SigningAlgorithms"][0])
    )

    # get Root CA cert in PEM format
    root_ca_cert_pem = base64.b64decode(db_list_certificates(project, env_name, root_ca_name)[0]["Certificate"]["B"])

    # deserialize Root CA cert
    root_ca_cert = load_pem_x509_certificate(root_ca_cert_pem)

    # sign certificate
    pem_certificate = ca_kms_sign_ca_certificate_request(
        project,
        env_name,
        domain,
        csr,
        root_ca_cert,
        root_ca_kms_key_id,
        enable_public_crl,
        issuing_ca_info,
        kms_describe_key(root_ca_kms_key_id)["SigningAlgorithms"][0],
    )
    base64_certificate = base64.b64encode(pem_certificate)

    # get details to upload to DynamoDB
    cert = load_pem_x509_certificate(pem_certificate)
    info = crypto_cert_info(cert, ca_slug)

    # create entry in DynamoDB
    db_ca_cert_issued(project, env_name, info, base64_certificate)

    # create CA bundle
    cert_bundle_pem = crypto_create_ca_bundle([root_ca_cert_pem, pem_certificate])

    # upload certificate and CA bundle to S3
    s3_upload(
        external_s3_bucket_name,
        internal_s3_bucket_name,
        pem_certificate,
        f"{ca_slug}.crt",
    )
    s3_upload(
        external_s3_bucket_name,
        internal_s3_bucket_name,
        cert_bundle_pem,
        f"{ca_bundle_name(project, env_name)}.pem",
    )

    return
