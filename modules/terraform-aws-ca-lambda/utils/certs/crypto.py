import random
import string
import base64

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from utils.certs.crypto_kms_classes import AWSKMSEllipticCurvePrivateKey, AWSKMSRSAPrivateKey
from validators import domain as domain_validator


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


def crypto_cert_request_info(csr_cert, common_name, lifetime, purposes, sans):
    """Creates a dictionary with the information needed to sign a certificate"""
    # if no purposes are specified, default to both client auth
    if purposes is None:
        purposes = ["client_auth"]

    # only allowed purposes are client_auth and server_auth
    purposes = [p for p in purposes if p in ["client_auth", "server_auth"]]

    # if purposes list is empty, default to client auth
    if purposes == []:
        purposes = ["client_auth"]

    # no SANs and common name is not a valid domain
    if (sans is None or sans == []) and not domain_validator(common_name):
        sans = []

    # no SANs and common name is a valid domain
    if (sans is None or sans == []) and domain_validator(common_name):
        sans = [common_name]

    # remove invalid SANs
    sans = [s for s in sans if domain_validator(s)]

    # convert to x509 cryptography format
    x509_sans = []
    for san in sans:
        x509_sans.append(x509.DNSName(san))

    return {
        "CsrCert": csr_cert,
        "x509Sans": x509_sans,
        "Lifetime": lifetime,
        "Purposes": purposes,
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
