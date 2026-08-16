import random
import string
import base64
import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mldsa
from .crypto_kms_classes import (
    AWSKMSEllipticCurvePrivateKey,
    AWSKMSMLDSA44PrivateKey,
    AWSKMSMLDSA65PrivateKey,
    AWSKMSMLDSA87PrivateKey,
    AWSKMSRSAPrivateKey,
)

_ML_DSA_PRIVATE_KEY_TYPES = (mldsa.MLDSA44PrivateKey, mldsa.MLDSA65PrivateKey, mldsa.MLDSA87PrivateKey)


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
    x509_extensions = convert_extensions_to_x509(csr_info.extensions)

    return {
        "CommonName": common_name,
        "Country": csr_info.subject.country,
        "CsrCert": csr_cert,
        "EmailAddress": csr_info.subject.email_address,
        "ExtendedKeyUsages": extended_key_usages,
        "Extensions": x509_extensions,
        "Lifetime": csr_info.lifetime,
        "Locality": csr_info.subject.locality,
        "Organization": csr_info.subject.organization,
        "OrganizationalUnit": csr_info.subject.organizational_unit,
        "Purposes": purposes,
        "State": csr_info.subject.state,
        "x509Sans": x509_sans,
    }


def convert_extensions_to_x509(extensions: list[dict]) -> list:
    """
    Convert validated custom extension dicts to (UnrecognizedExtension, critical) tuples.

    Args:
        extensions: List of dicts with 'oid', 'value_b64' and optional 'critical' keys.
            These must already have been authorised and validated (see
            utils.certs.types.validate_custom_extensions).

    Returns:
        List of (x509.UnrecognizedExtension, critical) tuples ready to add to a certificate.
    """
    x509_extensions = []

    for extension in extensions:
        oid = x509.ObjectIdentifier(extension["oid"])
        der_bytes = base64.b64decode(extension["value_b64"])
        critical = bool(extension.get("critical", False))
        x509_extensions.append((x509.UnrecognizedExtension(oid, der_bytes), critical))

    return x509_extensions


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


# The KMS key spec (from kms:DescribeKey) drives class and hash selection, not the KMS
# signing algorithm string: all three ML-DSA key specs share the single signing algorithm
# ML_DSA_SHAKE_256, so the signing algorithm alone cannot identify the parameter set
_KMS_KEY_SPEC_CLASSES = {
    "RSA_2048": AWSKMSRSAPrivateKey,
    "RSA_3072": AWSKMSRSAPrivateKey,
    "RSA_4096": AWSKMSRSAPrivateKey,
    "ECC_NIST_P256": AWSKMSEllipticCurvePrivateKey,
    "ECC_NIST_P384": AWSKMSEllipticCurvePrivateKey,
    "ECC_NIST_P521": AWSKMSEllipticCurvePrivateKey,
    "ML_DSA_44": AWSKMSMLDSA44PrivateKey,
    "ML_DSA_65": AWSKMSMLDSA65PrivateKey,
    "ML_DSA_87": AWSKMSMLDSA87PrivateKey,
}

# ML-DSA signs the full message without a pre-hash, so its hash entries are None
_KMS_KEY_SPEC_HASH_NAMES = {
    "RSA_2048": "sha256",
    "RSA_3072": "sha256",
    "RSA_4096": "sha256",
    "ECC_NIST_P256": "sha256",
    "ECC_NIST_P384": "sha384",
    "ECC_NIST_P521": "sha512",
    "ML_DSA_44": None,
    "ML_DSA_65": None,
    "ML_DSA_87": None,
}

_KMS_KEY_SPEC_HASH_CLASSES = {
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


def crypto_select_class(kms_key_spec):
    """Selects class for private key based on KMS key spec"""
    try:
        return _KMS_KEY_SPEC_CLASSES[kms_key_spec]
    except KeyError as exc:
        raise ValueError(f"Unsupported key spec {kms_key_spec}") from exc


def crypto_hash_algorithm(kms_key_spec):
    """Returns hash algorithm in format expected by Python Cryptography library, None for ML-DSA"""
    try:
        return _KMS_KEY_SPEC_HASH_NAMES[kms_key_spec]
    except KeyError as exc:
        raise ValueError(f"Unsupported key spec {kms_key_spec}") from exc


def crypto_hash_class(kms_key_spec):
    """Returns hash algorithm instance used to sign certificate, None for ML-DSA"""
    hash_name = crypto_hash_algorithm(kms_key_spec)
    if hash_name is None:
        return None

    return _KMS_KEY_SPEC_HASH_CLASSES[hash_name]()


def crypto_kms_ca_cert_signing_request(common_name, kms_key_id, kms_key_spec="RSA_2048"):
    """CA certificate signing request created using private key in AWS KMS"""
    private_key = crypto_select_class(kms_key_spec)(kms_key_id, crypto_hash_algorithm(kms_key_spec))

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
    # ML-DSA keys sign without a separate hash algorithm
    algorithm = None if isinstance(private_key, _ML_DSA_PRIVATE_KEY_TYPES) else hashes.SHA256()

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(private_key, algorithm)
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
