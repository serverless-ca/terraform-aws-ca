import random
import string
import base64

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from .crypto_kms_classes import (
    AWSKMSEllipticCurvePrivateKey,
    AWSKMSRSAPrivateKey,
)
from validators import domain as domain_validator

from typing import Optional


def get_subject_attribute_or_none(x509_subject, attribute):
    if x509_subject.get_attributes_for_oid(attribute):
        return x509_subject.get_attributes_for_oid(attribute)[0].value
    return None


class Subject:
    def __init__(self, common_name: str):
        self.common_name = common_name
        self.locality: Optional[str] = None
        self.organization: Optional[str] = None
        self.organizational_unit: Optional[str] = None
        self.country: Optional[str] = None
        self.state: Optional[str] = None
        self.email_address: Optional[str] = None

    def x509_name(self):
        attributes = [x509.NameAttribute(NameOID.COMMON_NAME, self.common_name)]

        if self.country:
            attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, self.country))

        if self.email_address:
            attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.email_address))

        if self.locality:
            attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, self.locality))

        if self.organization:
            attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization))

        if self.organizational_unit:
            attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.organizational_unit))

        if self.state:
            attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.state))

        return x509.Name(attributes)

    @staticmethod
    def from_x509_subject(x509_subject: "Subject"):
        common_name = x509_subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        subject = Subject(common_name)
        subject.country = get_subject_attribute_or_none(x509_subject, NameOID.COUNTRY_NAME)
        subject.email_address = get_subject_attribute_or_none(x509_subject, NameOID.EMAIL_ADDRESS)
        subject.locality = get_subject_attribute_or_none(x509_subject, NameOID.LOCALITY_NAME)
        subject.state = get_subject_attribute_or_none(x509_subject, NameOID.STATE_OR_PROVINCE_NAME)
        subject.organization = get_subject_attribute_or_none(x509_subject, NameOID.ORGANIZATION_NAME)
        subject.organizational_unit = get_subject_attribute_or_none(x509_subject, NameOID.ORGANIZATIONAL_UNIT_NAME)

        return subject


class CsrInfo:
    def __init__(self, common_name, lifetime: int = 30, purposes=None, sans=None):
        self.subject = Subject(common_name)

        self.lifetime: int = lifetime

        self._purposes = ["client_auth"]
        if purposes is not None:
            self._purposes = purposes

        self._sans = []
        if sans is not None:
            self._sans = sans

    def get_purposes(self):
        # only allowed purposes are client_auth and server_auth
        purposes = list(filter(lambda x: x in ["client_auth", "server_auth"], self._purposes))
        # purposes = [p for p in purposes if p in ["client_auth", "server_auth"]]

        # if purposes list is empty, default to client auth
        if not purposes:
            purposes = ["client_auth"]

        return purposes

    def get_sans(self):
        sans = self._sans

        valid_common_name = domain_validator(self.subject.common_name)

        # no SANs and common name is not a valid domain
        if (sans is None or sans == []) and not valid_common_name:
            sans = []

        # no SANs and common name is a valid domain
        if (sans is None or sans == []) and valid_common_name:
            sans = [self.subject.common_name]

        # remove invalid SANs
        sans = [s for s in sans if domain_validator(s)]

        return sans


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
    purposes = csr_info.get_purposes()
    sans = csr_info.get_sans()

    # convert to x509 cryptography format
    x509_sans = []
    for san in sans:
        x509_sans.append(x509.DNSName(san))

    return {
        "CommonName": common_name,
        "Country": csr_info.subject.country,
        "CsrCert": csr_cert,
        "EmailAddress": csr_info.subject.email_address,
        "Lifetime": csr_info.lifetime,
        "Locality": csr_info.subject.locality,
        "Organization": csr_info.subject.organization,
        "OrganizationalUnit": csr_info.subject.organizational_unit,
        "Purposes": purposes,
        "State": csr_info.subject.state,
        "x509Sans": x509_sans,
    }


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
