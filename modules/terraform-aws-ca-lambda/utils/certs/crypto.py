import random
import string
import base64
import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from .crypto_kms_classes import (
    AWSKMSEllipticCurvePrivateKey,
    AWSKMSRSAPrivateKey,
)


def crypto_cert_info(cert, common_name):
    return {
        "CommonName": common_name,
        "SerialNumber": str(cert.serial_number),
        "Issued": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S"),
        "Expires": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S"),
    }


def crypto_ca_key_info(public_key, kms_key_id, common_name):
    return {
        "CommonName": common_name,
        "KmsKeyId": kms_key_id,
        "PublicKey": public_key,
    }


def crypto_cert_request_info(csr_cert, csr_info):
    """Creates a dictionary with the information needed to sign a certificate"""
    # get common name from csr_info
    common_name = csr_info.subject.common_name

    # get values from csr_info
    purposes = csr_info.purposes
    extended_key_usages = csr_info.extended_key_usages
    sans = csr_info.sans

    # convert to x509 cryptography format
    x509_sans = convert_sans_to_x509(sans)

    return {
        "CommonName": common_name,
        "Country": csr_info.subject.country,
        "CsrCert": csr_cert,
        "EmailAddress": csr_info.subject.email_address,
        "ExtendedKeyUsages": extended_key_usages,
        "Lifetime": csr_info.lifetime,
        "Locality": csr_info.subject.locality,
        "Organization": csr_info.subject.organization,
        "OrganizationalUnit": csr_info.subject.organizational_unit,
        "Purposes": purposes,
        "State": csr_info.subject.state,
        "x509Sans": x509_sans,
    }


def convert_sans_to_x509(sans: list[dict[str, str]]) -> list:
    """
    Convert a list of typed SANs to x509 GeneralName objects.

    Args:
        sans: List of dicts with 'type' and 'value' keys

    Returns:
        List of x509 GeneralName objects (DNSName, IPAddress, RFC822Name, etc.)
    """
    x509_sans = []

    for san in sans:
        san_type = san.get("type", "DNS_NAME")
        value = san.get("value", "")

        try:
            if san_type == "DNS_NAME":
                x509_sans.append(x509.DNSName(value))
            elif san_type == "IP_ADDRESS":
                # Convert string to ip_address object
                ip_addr = ipaddress.ip_address(value)
                x509_sans.append(x509.IPAddress(ip_addr))
            elif san_type == "EMAIL_ADDRESS":
                x509_sans.append(x509.RFC822Name(value))
            elif san_type == "URL":
                x509_sans.append(x509.UniformResourceIdentifier(value))
            elif san_type == "DN":
                # Parse DN string to x509.Name
                x509_name = parse_dn_to_x509_name(value)
                x509_sans.append(x509.DirectoryName(x509_name))
        except Exception as e:
            print(f"Error converting SAN {san_type}:{value} to x509 format: {e}")
            continue

    return x509_sans


def parse_dn_to_x509_name(dn_string: str) -> x509.Name:
    """
    Parse a Distinguished Name string to an x509.Name object.

    Supports common DN attributes: CN, O, OU, C, ST, L, E, DC

    Args:
        dn_string: DN string like "CN=example,O=Org,C=US"

    Returns:
        x509.Name object
    """
    # Map of DN attribute names to OIDs
    oid_map = {
        "CN": NameOID.COMMON_NAME,
        "O": NameOID.ORGANIZATION_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "C": NameOID.COUNTRY_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME,
        "L": NameOID.LOCALITY_NAME,
        "E": NameOID.EMAIL_ADDRESS,
        "DC": NameOID.DOMAIN_COMPONENT,
    }

    attributes = []

    # Split by comma, but handle escaped commas
    parts = dn_string.split(",")

    for part in parts:
        part = part.strip()
        if "=" not in part:
            continue

        key, value = part.split("=", 1)
        key = key.strip().upper()
        value = value.strip()

        if key in oid_map:
            attributes.append(x509.NameAttribute(oid_map[key], value))

    return x509.Name(attributes)


def crypto_encode_private_key(key, passphrase=None):
    """Encodes private key to bytes,
    if a passphrase is specified it is used to encrypt to private key before encoding"""
    encryption_algorithm = serialization.NoEncryption()
    if passphrase:
        private_key_password = bytes(passphrase, "ascii")
        encryption_algorithm = serialization.BestAvailableEncryption(private_key_password)

    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption_algorithm,
    )


def crypto_select_class(kms_signing_algorithm):
    """Selects class for private key based on KMS signing algorithm"""
    if kms_signing_algorithm == "RSASSA_PKCS1_V1_5_SHA_256":
        return AWSKMSRSAPrivateKey
    if kms_signing_algorithm in ["ECDSA_SHA_256", "ECDSA_SHA_384", "ECDSA_SHA_512"]:
        return AWSKMSEllipticCurvePrivateKey

    raise ValueError(f"Unsupported key algorithm {kms_signing_algorithm}")


def crypto_hash_algorithm(kms_signing_algorithm):
    """Returns hash algorithm in format expected by Python Cryptography library"""
    if kms_signing_algorithm in ["RSASSA_PKCS1_V1_5_SHA_256", "ECDSA_SHA_256"]:
        return "sha256"
    if kms_signing_algorithm == "ECDSA_SHA_384":
        return "sha384"
    if kms_signing_algorithm == "ECDSA_SHA_512":
        return "sha512"

    raise ValueError(f"Unsupported key algorithm {kms_signing_algorithm}")


def crypto_hash_class(kms_signing_algorithm):
    """Returns arguments used to sign certificate"""
    if kms_signing_algorithm in ["RSASSA_PKCS1_V1_5_SHA_256", "ECDSA_SHA_256"]:
        return hashes.SHA256()
    if kms_signing_algorithm == "ECDSA_SHA_384":
        return hashes.SHA384()
    if kms_signing_algorithm == "ECDSA_SHA_512":
        return hashes.SHA512()

    raise ValueError(f"Unsupported key algorithm {kms_signing_algorithm}")


def crypto_kms_ca_cert_signing_request(common_name, kms_key_id, kms_signing_algorithm="RSASSA_PKCS1_V1_5_SHA_256"):
    """CA certificate signing request created using private key in AWS KMS"""
    private_key = crypto_select_class(kms_signing_algorithm)(kms_key_id, crypto_hash_algorithm(kms_signing_algorithm))

    return crypto_tls_ca_cert_signing_request(private_key, common_name)


def crypto_revoked_certificate(serial_number, revocation_date):
    """creates revoked certificate object to be used in CRL"""
    builder = x509.RevokedCertificateBuilder()
    builder = builder.revocation_date(revocation_date)
    builder = builder.serial_number(int(serial_number))
    revoked_certificate = builder.build()

    return revoked_certificate


def crypto_tls_ca_cert_signing_request(private_key, common_name):
    """CA certificate signing request created using private key"""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(private_key, hashes.SHA256())
    )

    return csr.public_bytes(serialization.Encoding.PEM)


def crypto_random_string(length):
    return "".join(
        random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits)
        for _ in range(length)
    )


def crypto_create_ca_bundle(ca_pem_certs):
    """Creates CA bundle from list of PEM certificates"""
    ca_bundle = ""
    for cert in ca_pem_certs:
        ca_bundle += cert.decode("utf-8")

    return ca_bundle


def certificate_metadata(common_name, csr, passphrase=False, lifetime=1):
    """
    Create JSON metadata to pass to Lambda function
    """
    base64_csr_data = base64.b64encode(csr).decode("utf-8")
    certificate_json = {
        "common_name": common_name,
        "lifetime": lifetime,
        "passphrase": passphrase,
        "force_issue": True,
        "base64_csr_data": base64_csr_data,
    }

    return certificate_json


def crypto_convert_crl_to_pem(crl_der):
    """Converts CRL from DER to PEM format"""
    crl = x509.load_der_x509_crl(crl_der)
    return crl.public_bytes(serialization.Encoding.PEM).decode("utf-8")
