from asn1crypto import pem
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from validators import domain as domain_validator
from certvalidator import CertificateValidator, ValidationContext


def convert_truststore(cert_bundle):
    """Convert bundle to trust store in correct format"""

    all_certs = []
    for _, _, der_bytes in pem.unarmor(cert_bundle.encode(encoding="utf-8"), multiple=True):
        all_certs.append(der_bytes)

    # strip the 1st cert as that's the end entity certificate
    trust_roots = all_certs[1:]
    return trust_roots


def certificate_validated(pem_cert, trust_roots, check_crl=True):
    """
    Validate certificate
    """
    cert = pem_cert.encode(encoding="utf-8")
    if check_crl:
        cert_context = ValidationContext(allow_fetching=True, revocation_mode="hard-fail", trust_roots=trust_roots)

    else:
        cert_context = ValidationContext(trust_roots=trust_roots)

    validator = CertificateValidator(cert, validation_context=cert_context)
    validator.validate_usage({"digital_signature", "key_encipherment"}, {"server_auth", "client_auth"}, True)
    return True


def create_csr_info(  # pylint:disable=too-many-arguments
    common_name,
    country=None,
    locality=None,
    organization=None,
    organizational_unit=None,
    state=None,
    sans=[],
    email_address=None,
):
    return {
        "commonName": common_name,
        "subjectAlternativeNames": sans,
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
    common_name = csr_info["commonName"]
    subject = build_subject_dn(csr_info)
    sans = csr_info.get("subjectAlternativeNames", [])

    if len(sans) == 0:
        sans.append(common_name)

    x509_sans = build_x509_sans(sans)

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(subject))

    if len(x509_sans) > 0:
        csr = csr.add_extension(
            x509.SubjectAlternativeName(x509_sans),
            critical=False,
        )

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
