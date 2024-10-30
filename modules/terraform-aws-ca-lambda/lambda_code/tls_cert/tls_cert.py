import base64
import os

from utils.aws.sns import publish_to_sns
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
from utils.certs.s3 import cert_issued_via_gitops, s3_download
from cryptography.x509 import load_pem_x509_certificate, load_pem_x509_csr
from cryptography.hazmat.primitives import serialization
from dataclasses import dataclass, field
from dataclasses_json import dataclass_json, LetterCase
from typing import Optional

# TODO: Request and Response classes use different naming convention


@dataclass_json
@dataclass
class Request:
    common_name: Optional[str] = None
    locality: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    country: Optional[str] = None
    email_address: Optional[str] = None
    state: Optional[str] = None
    lifetime: Optional[int] = 30
    purposes: Optional[list[str]] = field(default_factory=lambda: ["client_auth"])
    sans: Optional[list[str]] = None
    csr_file: Optional[str] = None
    base64_csr_data: Optional[str] = None
    force_issue: Optional[bool] = False
    cert_bundle: Optional[bool] = False
    ca_chain_only: Optional[bool] = False


@dataclass_json(letter_case=LetterCase.PASCAL)
@dataclass
class CertificateResponse:
    certificate_info: dict
    base64_certificate: str
    subject: str
    base64_issuing_ca_certificate: str
    base64_root_ca_certificate: str
    base64_ca_chain: str


@dataclass_json(letter_case=LetterCase.PASCAL)
@dataclass
class CaChainResponse:
    base64_issuing_ca_certificate: str
    base64_root_ca_certificate: str
    base64_ca_chain: str


# pylint:disable=too-many-arguments,too-many-positional-arguments
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

    # check CSR includes a Common Name
    if "CN=" not in csr.subject.rfc4514_string():
        return {"error": "CSR must include a Common Name"}

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


def create_cert_bundle_from_certificate(project, env_name, root_ca_name, issuing_ca_name, base64_certificate):
    """
    Creates a certificate bundle in PEM format containing Client Issuing CA and Root CA Certificates
    """
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


def create_ca_chain_response(project: str, env_name: str, root_ca_name: str, issuing_ca_name: str):
    root_ca_b64 = db_list_certificates(project, env_name, root_ca_name)[0]["Certificate"]["B"]
    issuing_ca_b64 = db_list_certificates(project, env_name, issuing_ca_name)[0]["Certificate"]["B"]

    # Need to decode base64 so we can append them together
    root_ca = base64.b64decode(root_ca_b64).decode("utf-8")
    issuing_ca = base64.b64decode(issuing_ca_b64).decode("utf-8")
    ca_chain = "\n".join([issuing_ca.strip(), root_ca.strip()])
    ca_chain_b64_bytes = base64.b64encode(ca_chain.encode("utf-8"))
    ca_chain_b64 = ca_chain_b64_bytes.decode("utf-8")

    return CaChainResponse(
        base64_issuing_ca_certificate=issuing_ca_b64,
        base64_root_ca_certificate=root_ca_b64,
        base64_ca_chain=ca_chain_b64,
    )


def sns_notify_cert_issued(cert_json, sns_topic_arn):
    keys_to_publish = ["CertificateInfo", "Base64Certificate", "Subject"]
    response = publish_to_sns(cert_json, "Certificate Issued", sns_topic_arn, keys_to_publish)

    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    common_name = cert_json["CertificateInfo"]["CommonName"]
    print(f"Certificate details for {common_name} published to SNS")


def lambda_handler(event, context):  # pylint:disable=unused-argument,too-many-locals
    project = os.environ["PROJECT"]
    env_name = os.environ["ENVIRONMENT_NAME"]
    external_s3_bucket_name = os.environ["EXTERNAL_S3_BUCKET"]
    internal_s3_bucket_name = os.environ["INTERNAL_S3_BUCKET"]
    max_cert_lifetime = int(os.environ["MAX_CERT_LIFETIME"])
    sns_topic_arn = os.environ["SNS_TOPIC_ARN"]
    domain = os.environ.get("DOMAIN")

    public_crl = os.environ.get("PUBLIC_CRL")
    enable_public_crl = False
    if public_crl == "enabled":
        enable_public_crl = True

    # get Issuing CA name
    issuing_ca_name = ca_name(project, env_name, "issuing")
    root_ca_name = ca_name(project, env_name, "root")

    request = Request.from_dict(event)

    # process input
    print(f"Input: {event}")

    ca_chain_response = create_ca_chain_response(project, env_name, root_ca_name, issuing_ca_name)

    if request.ca_chain_only:
        return ca_chain_response.to_dict()

    csr_info = create_csr_info(event)

    if request.csr_file:
        csr_file_contents = s3_download(external_s3_bucket_name, internal_s3_bucket_name, f"csrs/{request.csr_file}")[
            "Body"
        ].read()
        csr = load_pem_x509_csr(csr_file_contents)
    else:
        csr = load_pem_x509_csr(base64.standard_b64decode(request.base64_csr_data))

    validation_error = is_invalid_certificate_request(
        project,
        env_name,
        issuing_ca_name,
        csr_info.subject.common_name,
        csr,
        csr_info.lifetime,
        request.force_issue,
    )
    if validation_error:
        return validation_error

    base64_certificate, cert_info = sign_csr(
        project, env_name, csr, issuing_ca_name, csr_info, domain, max_cert_lifetime, enable_public_crl
    )

    db_tls_cert_issued(project, env_name, cert_info, base64_certificate)

    if request.cert_bundle:
        cert_bundle = create_cert_bundle_from_certificate(
            project, env_name, root_ca_name, issuing_ca_name, base64_certificate
        )
        base64_certificate = base64.b64encode(cert_bundle.encode("utf-8"))

    response = CertificateResponse(
        certificate_info=cert_info,
        base64_certificate=base64_certificate.decode("utf-8"),
        subject=load_pem_x509_certificate(base64.b64decode(base64_certificate)).subject.rfc4514_string(),
        base64_root_ca_certificate=ca_chain_response.base64_root_ca_certificate.decode("utf-8"),
        base64_issuing_ca_certificate=ca_chain_response.base64_issuing_ca_certificate.decode("utf-8"),
        base64_ca_chain=ca_chain_response.base64_ca_chain,
    )

    if cert_issued_via_gitops(internal_s3_bucket_name, response.subject):
        sns_notify_cert_issued(response.to_dict(), sns_topic_arn)

    return response.to_dict()
