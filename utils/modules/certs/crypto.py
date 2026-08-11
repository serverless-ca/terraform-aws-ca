import urllib.request
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID
from cryptography.x509.verification import ExtensionPolicy, PolicyBuilder, Store, VerificationError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, mldsa
from validators import domain as domain_validator

_CRL_FETCH_TIMEOUT_SECONDS = 30

_ML_DSA_PRIVATE_KEY_TYPES = (mldsa.MLDSA44PrivateKey, mldsa.MLDSA65PrivateKey, mldsa.MLDSA87PrivateKey)

_PURPOSE_EKU_OIDS = {
    "server_auth": ExtendedKeyUsageOID.SERVER_AUTH,
    "client_auth": ExtendedKeyUsageOID.CLIENT_AUTH,
}


class InvalidCertificateError(Exception):
    """Certificate failed chain, purpose or revocation validation"""


def convert_pem_to_der(pem_bytes: bytes):
    all_certs = []
    for cert in x509.load_pem_x509_certificates(pem_bytes):
        all_certs.append(cert.public_bytes(serialization.Encoding.DER))

    return all_certs


def convert_truststore(cert_bundle: str):
    """Convert bundle to trust store in correct format"""

    all_certs = convert_pem_to_der(cert_bundle.encode(encoding="utf-8"))

    # strip the 1st cert as that's the end entity certificate
    trust_roots = all_certs[1:]
    return trust_roots


def _validate_purposes(certificate, purposes):
    """Check Extended Key Usage of certificate includes all requested purposes"""
    try:
        extended_key_usages = list(certificate.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value)
    except x509.ExtensionNotFound:
        extended_key_usages = []

    invalid_purposes = [p for p in purposes if _PURPOSE_EKU_OIDS[p] not in extended_key_usages]
    if invalid_purposes:
        raise InvalidCertificateError(
            "The X.509 certificate provided is not valid for the purpose of "
            + ", ".join(p.replace("_", " ") for p in invalid_purposes)
        )


def _validate_key_usage(certificate):
    """Check Key Usage of certificate includes digital signature and key encipherment"""
    try:
        key_usage = certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound as e:
        raise InvalidCertificateError("The X.509 certificate provided has no keyUsage extension") from e

    if not (key_usage.digital_signature and key_usage.key_encipherment):
        raise InvalidCertificateError(
            "The X.509 certificate provided is not valid for the purpose of digital signature, key encipherment"
        )


def _fetch_crl(url: str):
    """Download and parse a CRL from an HTTP(S) CRL Distribution Point URL, in DER or PEM format"""
    if not url.startswith(("http://", "https://")):
        raise InvalidCertificateError(f"Unsupported CRL Distribution Point URL scheme: {url}")

    with urllib.request.urlopen(url, timeout=_CRL_FETCH_TIMEOUT_SECONDS) as response:  # nosec B310 - scheme checked
        crl_data = response.read()

    try:
        return x509.load_der_x509_crl(crl_data)
    except ValueError:
        return x509.load_pem_x509_crl(crl_data)


def _crl_distribution_point_urls(certificate):
    try:
        distribution_points = certificate.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
    except x509.ExtensionNotFound:
        return []

    return [
        general_name.value
        for distribution_point in distribution_points
        for general_name in distribution_point.full_name or []
        if isinstance(general_name, x509.UniformResourceIdentifier)
    ]


def _validate_revocation(chain):
    """Check revocation status of each certificate in the chain that publishes a CRL Distribution Point,
    hard-failing if the CRL can't be retrieved or its signature can't be verified with the issuer's public key"""
    for certificate, issuer in zip(chain, chain[1:]):
        urls = _crl_distribution_point_urls(certificate)
        if not urls:
            continue

        subject = certificate.subject.rfc4514_string()

        crl = None
        errors = []
        for url in urls:
            try:
                crl = _fetch_crl(url)
                break
            except (OSError, ValueError) as e:
                errors.append(f"{url}: {e}")
        if crl is None:
            raise InvalidCertificateError(f"Unable to retrieve CRL for certificate {subject}: {'; '.join(errors)}")

        if not crl.is_signature_valid(issuer.public_key()):
            raise InvalidCertificateError(f"CRL signature verification failed for certificate {subject}")

        if crl.next_update_utc is not None and crl.next_update_utc < datetime.now(timezone.utc):
            raise InvalidCertificateError(f"CRL for certificate {subject} is expired")

        if crl.get_revoked_certificate_by_serial_number(certificate.serial_number) is not None:
            raise InvalidCertificateError(f"The X.509 certificate provided is revoked: {subject}")


def certificate_validated(pem_cert, trust_roots, purposes=None, check_crl=True):
    """
    Validate certificate chain to a trusted root, purposes (Extended Key Usage), and optionally
    revocation status via CRL, using cryptography.x509.verification.
    Supports RSA, ECDSA and ML-DSA certificate chains.

    pem_cert: PEM certificate, optionally bundled with its CA chain
    trust_roots: list of trusted CA certificates in DER format
    """
    if purposes is None:
        purposes = ["server_auth", "client_auth"]

    certs = x509.load_pem_x509_certificates(pem_cert.encode(encoding="utf-8"))
    leaf = certs[0]
    intermediates = certs[1:]

    store = Store([x509.load_der_x509_certificate(der) for der in trust_roots])

    # a client verifier is used for chain building with both client and server certificates, as unlike
    # a server verifier it doesn't require a Subject Alternative Name matching an expected hostname.
    # EKU purpose checks are applied to the leaf certificate separately below, so the extension
    # policy is permissive; CA certificates are still validated against CA/B Forum guidelines
    verifier = (
        PolicyBuilder()
        .store(store)
        .extension_policies(
            ca_policy=ExtensionPolicy.webpki_defaults_ca(),
            ee_policy=ExtensionPolicy.permit_all(),
        )
        .build_client_verifier()
    )

    try:
        chain = verifier.verify(leaf, intermediates).chain
    except VerificationError as e:
        raise InvalidCertificateError(f"The X.509 certificate provided could not be validated: {e}") from e

    _validate_key_usage(leaf)
    _validate_purposes(leaf, purposes)

    if check_crl:
        _validate_revocation(chain)

    return True


def create_csr_info(  # pylint:disable=too-many-arguments,too-many-positional-arguments
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

    # ML-DSA keys sign without a separate hash algorithm
    if isinstance(private_key, _ML_DSA_PRIVATE_KEY_TYPES):
        csr = csr.sign(private_key, None)
    else:
        csr = csr.sign(private_key, hashes.SHA256())

    return csr.public_bytes(serialization.Encoding.PEM)


def _private_key_format(key):
    """ML-DSA private keys can only be serialized in PKCS8 format"""
    if isinstance(key, _ML_DSA_PRIVATE_KEY_TYPES):
        return serialization.PrivateFormat.PKCS8

    return serialization.PrivateFormat.TraditionalOpenSSL


def crypto_encode_private_key(key, passphrase=None):
    """Encodes private key to bytes,
    if a passphrase is specified it is used to encrypt to private key before encoding"""
    encryption_algorithm = serialization.NoEncryption()
    if passphrase:
        private_key_password = bytes(passphrase, "ascii")
        encryption_algorithm = serialization.BestAvailableEncryption(private_key_password)

    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=_private_key_format(key),
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

    if algorithm == "ml-dsa-44":
        return mldsa.MLDSA44PrivateKey.generate()

    if algorithm == "ml-dsa-65":
        return mldsa.MLDSA65PrivateKey.generate()

    if algorithm == "ml-dsa-87":
        return mldsa.MLDSA87PrivateKey.generate()

    raise ValueError(f"Unsupported algorithm: {algorithm}")


def write_key_to_disk(key, filepath):
    """Write private key to disk"""
    with open(filepath, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=_private_key_format(key),
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
