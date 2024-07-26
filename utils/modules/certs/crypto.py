from asn1crypto import pem
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from validators import domain as domain_validator
from certvalidator import CertificateValidator, ValidationContext


def convert_pem_to_der(pem_bytes: bytes):
    all_certs = []
    for _, _, der_bytes in pem.unarmor(pem_bytes, multiple=True):
        all_certs.append(der_bytes)

    return all_certs


def convert_truststore(cert_bundle: str):
    """Convert bundle to trust store in correct format"""

    all_certs = convert_pem_to_der(cert_bundle.encode(encoding="utf-8"))

    # strip the 1st cert as that's the end entity certificate
    trust_roots = all_certs[1:]
    return trust_roots


def certificate_validated(pem_cert, trust_roots, purposes=None, check_crl=True):
    """
    Validate certificate
    """
    if purposes is None:
        purposes = ["server_auth", "client_auth"]

    cert = pem_cert.encode(encoding="utf-8")
    if check_crl:
        cert_context = ValidationContext(allow_fetching=True, revocation_mode="hard-fail", trust_roots=trust_roots)
    else:
        cert_context = ValidationContext(trust_roots=trust_roots)

    validator = CertificateValidator(cert, validation_context=cert_context)
    validator.validate_usage({"digital_signature", "key_encipherment"}, set(purposes), True)
    return True


def create_csr_info(  # pylint:disable=too-many-arguments
    common_name,
    country=None,
    locality=None,
    organization=None,
    organizational_unit=None,
    state=None,
    email_address=None,
):
    return {
        "commonName": common_name,
        "country": country,
        "emailAddress": email_address,
        "locality": locality,
        "organization": organization,
        "organizationalUnit": organizational_unit,
        "state": state,
    }


def build_subject_dn(csr_info):
    country = csr_info.get("country")
    state = csr_info.get("state")
    locality = csr_info.get("locality")
    organization = csr_info.get("organization")
    organizational_unit = csr_info.get("organizationalUnit")
    common_name = csr_info.get("commonName")
    email_address = csr_info.get("emailAddress")

    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]

    if country:
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))

    if email_address:
        attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address))

    if locality:
        attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))

    if organization:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))

    if organizational_unit:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))

    if state:
        attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))

    subject = x509.Name(attributes)

    return subject


def build_x509_sans(sans):
    sans = [s for s in sans if domain_validator(s)]

    x509_sans = []
    for san in sans:
        x509_sans.append(x509.DNSName(san))

    return x509_sans


def crypto_tls_cert_signing_request(private_key, csr_info):
    subject = build_subject_dn(csr_info)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(subject))
    csr = csr.sign(private_key, hashes.SHA256())

    return csr.public_bytes(serialization.Encoding.PEM)


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


def generate_key(algorithm="ecdsa", key_length=256):
    """Generate key pair"""
    if algorithm == "rsa":
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_length,
        )

    if algorithm == "ecdsa":
        if key_length == 256:
            return ec.generate_private_key(ec.SECP256R1())
        if key_length == 384:
            return ec.generate_private_key(ec.SECP384R1())
        if key_length == 521:
            return ec.generate_private_key(ec.SECP521R1())
        raise ValueError(f"Unsupported key length: {key_length}")

    raise ValueError(f"Unsupported algorithm: {algorithm}")


def write_key_to_disk(key, filepath):
    """Write RSA key to disk"""
    with open(filepath, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
