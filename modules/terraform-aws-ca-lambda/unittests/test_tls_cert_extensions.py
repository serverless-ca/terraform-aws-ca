from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID

from utils.certs.ca import ca_build_cert

# Tests for the X.509 extensions the CA always emits on issued end-entity (TLS)
# certificates - the default extension chain, independent of the opt-in custom
# extensions feature (see test_custom_extensions.py for that).


def _build_csr(common_name="leaf.example.com"):
    key = ec.generate_private_key(ec.SECP256R1())
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )


def _build_ca_cert():
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuing CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _issue_leaf():
    """Build and sign a leaf certificate, returning it with its issuing CA cert."""
    csr = _build_csr()
    ca_cert, ca_key = _build_ca_cert()
    cert_request_info = {"Purposes": ["client_auth"], "Extensions": []}
    builder = ca_build_cert(csr, ca_cert, lifetime=30, delta=timedelta(minutes=5), cert_request_info=cert_request_info)
    return builder.sign(ca_key, hashes.SHA256()), ca_cert


def test_leaf_includes_subject_key_identifier():
    cert, _ = _issue_leaf()

    ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    assert ski.critical is False


def test_leaf_includes_authority_key_identifier():
    # Regression test for serverless-ca/terraform-aws-ca#621: leaf certificates
    # must carry an Authority Key Identifier so strict (RFC 5280) validators can
    # construct the certification path. Its key identifier must match the key
    # identifier derived from the issuing CA's public key.
    cert, ca_cert = _issue_leaf()

    aki = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    assert aki.critical is False
    expected_key_id = x509.SubjectKeyIdentifier.from_public_key(ca_cert.public_key()).digest
    assert aki.value.key_identifier == expected_key_id
