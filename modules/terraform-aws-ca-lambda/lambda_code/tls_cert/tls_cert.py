import base64
import os
from utils.certs.kms_ca import kms_ca_generate_key_pair
from utils.certs.kms import kms_get_kms_key_id, kms_describe_key
from utils.certs.crypto import (
    crypto_cert_request_info,
    crypto_encode_private_key,
    crypto_cert_info,
    crypto_random_string,
)
from utils.certs.ca import ca_name, ca_kms_sign_tls_certificate_request, ca_client_tls_cert_signing_request
from utils.certs.db import db_tls_cert_issued, db_list_certificates, db_issue_certificate
from utils.certs.s3 import s3_download
from cryptography.x509 import load_pem_x509_certificate, load_pem_x509_csr
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives import serialization

# support legacy capability - to be removed in future release
client_keys_in_db = os.environ.get("CLIENT_KEYS_IN_DB")


def sign_tls_certificate(csr, ca_name, csr_info_1, csr_info_2):
    # get CA cert from DynamoDB
    ca_cert = load_pem_x509_certificate(base64.b64decode(db_list_certificates(ca_name)[0]["Certificate"]["B"]))

    # get KMS Key ID for CA
    issuing_ca_kms_key_id = kms_get_kms_key_id(ca_name)

    # collect Certificate Request info
    cert_request_info = crypto_cert_request_info(csr, csr_info_1, csr_info_2)

    # sign certificate
    return ca_kms_sign_tls_certificate_request(
        cert_request_info,
        ca_cert,
        issuing_ca_kms_key_id,
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


def create_csr(csr_info, ca_slug, generate_passphrase):
    """Creates a private key and CSR using KMS Key Pair Generation"""
    key_pair_spec, csr_algorithm = select_csr_crypto(ca_slug)
    response = kms_ca_generate_key_pair(key_pair_spec)
    private_key = load_der_private_key(response["PrivateKeyPlaintext"], None)
    csr = load_pem_x509_csr(ca_client_tls_cert_signing_request(private_key, csr_info, csr_algorithm))

    passphrase = None
    base64_passphrase = None
    if generate_passphrase:
        passphrase = crypto_random_string(30)
        base64_passphrase = base64.b64encode(passphrase.encode("utf-8"))

    private_key_bytes = crypto_encode_private_key(private_key, passphrase)
    base64_private_key = base64.b64encode(private_key_bytes)

    return (csr, base64_private_key, base64_passphrase)


def sign_csr(csr, ca_name, csr_info_1, csr_info_2):
    common_name = csr_info_1["commonName"]

    # sign certificate
    pem_certificate = sign_tls_certificate(csr, ca_name, csr_info_1, csr_info_2)

    # get details to upload to DynamoDB
    info = crypto_cert_info(load_pem_x509_certificate(pem_certificate), common_name)

    return base64.b64encode(pem_certificate), info


def is_invalid_certificate_request(ca_name, common_name, csr, lifetime, force_issue):
    if not db_list_certificates(ca_name):
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
    if not force_issue and not db_issue_certificate(common_name, request_public_key_pem):
        return {"error": "Private key has already been used for a certificate"}

    # check lifetime is at least 1 day
    if lifetime < 1:
        return {"error": f"{lifetime} is too short"}

    return None


def create_cert_bundle(base64_certificate):
    """
    Creates a certificate bundle in PEM format containing Client Issuing CA and Root CA Certificates
    """
    root_ca_name = ca_name("root")
    issuing_ca_name = ca_name("issuing")
    cert_bundle = ""
    return cert_bundle.join(
        [
            base64.b64decode(base64_certificate.decode("utf-8")).decode("utf-8"),
            base64.b64decode(db_list_certificates(issuing_ca_name)[0]["Certificate"]["B"]).decode("utf-8"),
            base64.b64decode(db_list_certificates(root_ca_name)[0]["Certificate"]["B"]).decode("utf-8"),
        ]
    )


def create_csr_info_1(common_name, locality=None, organization=None, organizational_unit=None, country=None):
    return {
        "commonName": common_name,
        "country": country,
        "locality": locality,
        "organization": organization,
        "organizationalUnit": organizational_unit,
    }


def create_csr_info_2(lifetime, email_address=None, purposes=None, sans=None, state=None):
    return {"lifetime": lifetime, "emailAddress": email_address, "sans": sans, "purposes": purposes, "state": state}


def get_csr_info(event):
    common_name = event["common_name"]  # string, DNS common name, also used for certificate SAN if no SANs provided
    country = event.get("country")  # string, country code
    email_address = event.get("email_address")  # string, email address
    lifetime = event.get("lifetime", 30)  # integer, days until certificate expires. Defaults to 30.
    locality = event.get("locality")  # string, location
    organization = event.get("organization")  # string, organization name
    organizational_unit = event.get("organizational_unit")  # string, organizational unit name
    purposes = event.get("purposes")  # list of strings, e.g. ["client_auth", "server_auth"]
    sans = event.get("sans")  # list of strings, DNS Subject Alternative Names
    state = event.get("state")  # string, state or province

    return create_csr_info_1(common_name, locality, organization, organizational_unit, country), create_csr_info_2(
        int(lifetime), email_address, purposes, sans, state
    )


def lambda_handler(event, context):  # pylint:disable=unused-argument, too-many-locals

    # get Issuing CA name
    issuing_ca_name = ca_name("issuing")

    # process input
    print(f"Input: {event}")

    csr_info_1, csr_info_2 = get_csr_info(event)

    common_name = csr_info_1["commonName"]
    lifetime = csr_info_2.get("lifetime")  # integer, days until certificate expires
    csr_file = event.get("csr_file")  # string, reference to static file
    force_issue = event.get("force_issue")  # boolean, force certificate generation even if one already exists
    cert_bundle = event.get("cert_bundle")  # boolean, include Root CA and Issuing CA with client certificate
    base64_csr_data = event.get("base64_csr_data")  # base64 encoded CSR PEM file

    if csr_file:
        csr = load_pem_x509_csr(s3_download(f"csrs/{csr_file}")["Body"].read())
    else:
        csr = load_pem_x509_csr(base64.standard_b64decode(base64_csr_data))

    validation_error = is_invalid_certificate_request(issuing_ca_name, common_name, csr, lifetime, force_issue)
    if validation_error:
        return validation_error

    base64_certificate, cert_info = sign_csr(csr, issuing_ca_name, csr_info_1, csr_info_2)

    db_tls_cert_issued(cert_info, base64_certificate)

    if cert_bundle:
        base64_certificate = base64.b64encode(create_cert_bundle(base64_certificate).encode("utf-8"))

    response_data = {
        "CertificateInfo": cert_info,
        "Base64Certificate": base64_certificate,
        "Subject": load_pem_x509_certificate(base64.b64decode(base64_certificate)).subject.rfc4514_string(),
    }

    return response_data
