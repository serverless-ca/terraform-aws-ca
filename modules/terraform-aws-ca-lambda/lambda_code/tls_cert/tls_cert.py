import base64
import os

from utils.certs.kms import kms_get_kms_key_id, kms_describe_key
from utils.certs.crypto import (
    crypto_cert_request_info,
    crypto_cert_info,
)
from utils.certs.types import (
    Subject,
    CsrInfo,
)
from utils.certs.ca import (
    ca_name,
    ca_kms_sign_tls_certificate_request,
)
from utils.certs.db import (
    db_tls_cert_issued,
    db_list_certificates,
    db_issue_certificate,
)
from utils.certs.s3 import s3_download
from cryptography.x509 import load_pem_x509_certificate, load_pem_x509_csr
from cryptography.hazmat.primitives import serialization


# pylint:disable=too-many-arguments
def sign_tls_certificate(project, env_name, csr, ca_name, csr_info, domain, max_cert_lifetime, enable_public_crl):
    # get CA cert from DynamoDB
    ca_cert_bytes_b64 = db_list_certificates(project, env_name, ca_name)[0]["Certificate"]["B"]
    ca_cert_bytes = base64.b64decode(ca_cert_bytes_b64)
    ca_cert = load_pem_x509_certificate(ca_cert_bytes)

    # get KMS Key ID for CA
    issuing_ca_kms_key_id = kms_get_kms_key_id(ca_name)

    # collect Certificate Request info
    cert_request_info = crypto_cert_request_info(csr, csr_info)

    # sign certificate
    return ca_kms_sign_tls_certificate_request(
        project,
        env_name,
        domain,
        max_cert_lifetime,
        cert_request_info,
        ca_cert,
        issuing_ca_kms_key_id,
        enable_public_crl,
        kms_describe_key(issuing_ca_kms_key_id)["SigningAlgorithms"][0],
    )


def select_csr_crypto(ca_slug):
    """Returns Key Pair Spec and Signing Algorithm for CSR generation based on Issuing CA Cryptography"""
    # get KMS Key ID for CA
    issuing_ca_kms_key_id = kms_get_kms_key_id(ca_slug)
    issuing_ca_key_spec = kms_describe_key(issuing_ca_kms_key_id)["KeySpec"]

    if "ECC_NIST" in issuing_ca_key_spec:
        return "ECC_NIST_P256", "ECDSA_SHA_256"

    return "RSA_2048", "RSASSA_PKCS1_V1_5_SHA_256"


# pylint:disable=too-many-arguments
def sign_csr(project, env_name, csr, ca_name, csr_info, domain, max_cert_lifetime, enable_public_crl):
    # sign certificate
    pem_certificate = sign_tls_certificate(
        project, env_name, csr, ca_name, csr_info, domain, max_cert_lifetime, enable_public_crl
    )

    # get details to upload to DynamoDB
    info = crypto_cert_info(load_pem_x509_certificate(pem_certificate), csr_info.subject.common_name)

    return base64.b64encode(pem_certificate), info


# pylint:disable=too-many-arguments
def is_invalid_certificate_request(project, env_name, ca_name, common_name, csr, lifetime, force_issue):
    if not db_list_certificates(project, env_name, ca_name):
        return {"error": f"CA {ca_name} not found"}

    # get public key from CSR
    public_key = csr.public_key()

    # Convert public key to PEM format
    request_public_key_pem = (
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode("utf-8")

    # check for private key reuse
    if not force_issue and not db_issue_certificate(project, env_name, common_name, request_public_key_pem):
        return {"error": "Private key has already been used for a certificate"}

    # check lifetime is at least 1 day
    if lifetime < 1:
        return {"error": f"{lifetime} is too short"}

    return None


def create_cert_bundle_from_certificate(project, env_name, base64_certificate):
    """
    Creates a certificate bundle in PEM format containing Client Issuing CA and Root CA Certificates
    """
    root_ca_name = ca_name(project, env_name, "root")
    issuing_ca_name = ca_name(project, env_name, "issuing")
    cert_bundle = ""
    return cert_bundle.join(
        [
            base64.b64decode(base64_certificate.decode("utf-8")).decode("utf-8"),
            base64.b64decode(db_list_certificates(project, env_name, issuing_ca_name)[0]["Certificate"]["B"]).decode(
                "utf-8"
            ),
            base64.b64decode(db_list_certificates(project, env_name, root_ca_name)[0]["Certificate"]["B"]).decode(
                "utf-8"
            ),
        ]
    )


def create_csr_subject(event) -> Subject:
    subject = Subject(event["common_name"])
    subject.locality = event.get("locality")  # string, location
    subject.organization = event.get("organization")  # string, organization name
    subject.organizational_unit = event.get("organizational_unit")  # string, organizational unit name
    subject.country = event.get("country")  # string, country code
    subject.email_address = event.get("email_address")
    subject.state = event.get("state")
    return subject


def create_csr_info(event) -> CsrInfo:
    lifetime = int(event.get("lifetime", 30))
    purposes = event.get("purposes")
    sans = event.get("sans")

    subject = create_csr_subject(event)

    csr_info = CsrInfo(subject, lifetime=lifetime, purposes=purposes, sans=sans)

    return csr_info


def lambda_handler(event, context):  # pylint:disable=unused-argument,too-many-locals
    project = os.environ["PROJECT"]
    env_name = os.environ["ENVIRONMENT_NAME"]
    external_s3_bucket_name = os.environ["EXTERNAL_S3_BUCKET"]
    internal_s3_bucket_name = os.environ["INTERNAL_S3_BUCKET"]
    max_cert_lifetime = int(os.environ["MAX_CERT_LIFETIME"])
    domain = os.environ.get("DOMAIN")

    public_crl = os.environ.get("PUBLIC_CRL")
    enable_public_crl = False
    if public_crl == "enabled":
        enable_public_crl = True

    # get Issuing CA name
    issuing_ca_name = ca_name(project, env_name, "issuing")

    # process input
    print(f"Input: {event}")

    csr_info = create_csr_info(event)

    csr_file = event.get("csr_file")  # string, reference to static file
    force_issue = event.get("force_issue")  # boolean, force certificate generation even if one already exists
    create_cert_bundle = event.get("cert_bundle")  # boolean, include Root CA and Issuing CA with client certificate
    base64_csr_data = event.get("base64_csr_data")  # base64 encoded CSR PEM file

    if csr_file:
        csr_file_contents = s3_download(external_s3_bucket_name, internal_s3_bucket_name, f"csrs/{csr_file}")[
            "Body"
        ].read()
        csr = load_pem_x509_csr(csr_file_contents)
    else:
        csr = load_pem_x509_csr(base64.standard_b64decode(base64_csr_data))

    validation_error = is_invalid_certificate_request(
        project,
        env_name,
        issuing_ca_name,
        csr_info.subject.common_name,
        csr,
        csr_info.lifetime,
        force_issue,
    )
    if validation_error:
        return validation_error

    base64_certificate, cert_info = sign_csr(
        project, env_name, csr, issuing_ca_name, csr_info, domain, max_cert_lifetime, enable_public_crl
    )

    db_tls_cert_issued(project, env_name, cert_info, base64_certificate)

    if create_cert_bundle:
        cert_bundle = create_cert_bundle_from_certificate(project, env_name, base64_certificate)
        base64_certificate = base64.b64encode(cert_bundle.encode("utf-8"))

    response_data = {
        "CertificateInfo": cert_info,
        "Base64Certificate": base64_certificate,
        "Subject": load_pem_x509_certificate(base64.b64decode(base64_certificate)).subject.rfc4514_string(),
    }

    return response_data
