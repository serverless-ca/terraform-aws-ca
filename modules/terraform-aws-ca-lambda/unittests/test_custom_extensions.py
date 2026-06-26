import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID

from lambda_code.tls_cert.tls_cert import create_csr_info, get_custom_extension_allowlist
from utils.certs.ca import ca_build_cert
from utils.certs.crypto import convert_extensions_to_x509
from utils.certs.types import DENYLISTED_EXTENSION_OIDS, validate_custom_extensions

# A private-enterprise OID used as the allowlisted example throughout these tests
EXAMPLE_OID = "1.3.6.1.4.1.55555.1.1"
EXAMPLE_VALUE = b"device-class-a"
EXAMPLE_VALUE_B64 = base64.b64encode(EXAMPLE_VALUE).decode("utf-8")


def _extension(oid=EXAMPLE_OID, value_b64=EXAMPLE_VALUE_B64, critical=False):
    return {"oid": oid, "value_b64": value_b64, "critical": critical}


# ---------------------------------------------------------------------------
# validate_custom_extensions - allowlist / denylist authorisation
# ---------------------------------------------------------------------------


def test_validate_allowlisted_extension_passes():
    extensions = [_extension()]
    assert validate_custom_extensions(extensions, [EXAMPLE_OID]) == extensions


def test_validate_empty_extensions_always_passes():
    # No requested extensions is always fine, even with an empty allowlist;
    # the input list is returned unchanged
    empty = []
    assert validate_custom_extensions(empty, []) is empty


def test_validate_non_allowlisted_extension_rejected():
    with pytest.raises(ValueError) as exc_info:
        validate_custom_extensions([_extension()], ["1.2.3.4"])
    assert "not in the configured allowlist" in str(exc_info.value)
    assert EXAMPLE_OID in str(exc_info.value)


def test_validate_empty_allowlist_rejects_all_extensions():
    # Default deployment behaviour: empty allowlist means the feature is disabled
    with pytest.raises(ValueError) as exc_info:
        validate_custom_extensions([_extension()], [])
    assert "not in the configured allowlist" in str(exc_info.value)


def test_validate_denylist_always_wins_even_if_allowlisted():
    # Defense in depth: every extension the CA emits (incl. subjectAltName 2.5.29.17 and
    # extendedKeyUsage 2.5.29.37) is rejected even when an operator puts it on the
    # allowlist - the CA must control these unconditionally, so a caller cannot forge a
    # SAN/identity or shadow a CA-managed extension
    for denylisted_oid in DENYLISTED_EXTENSION_OIDS:
        with pytest.raises(ValueError) as exc_info:
            validate_custom_extensions([_extension(oid=denylisted_oid)], allowlist=[denylisted_oid])
        assert "reserved" in str(exc_info.value)
        assert denylisted_oid in str(exc_info.value)


def test_validate_subject_alt_name_oid_denylisted():
    # Explicit guard for the identity-forgery case: subjectAltName must never be
    # caller-settable, even if allowlisted
    assert "2.5.29.17" in DENYLISTED_EXTENSION_OIDS
    with pytest.raises(ValueError) as exc_info:
        validate_custom_extensions([_extension(oid="2.5.29.17")], allowlist=["2.5.29.17"])
    assert "reserved" in str(exc_info.value)


def test_validate_duplicate_oid_rejected():
    # Two entries with the same OID would raise an uncaught error at signing time;
    # the request must be rejected cleanly instead
    with pytest.raises(ValueError) as exc_info:
        validate_custom_extensions([_extension(), _extension()], [EXAMPLE_OID])
    assert "more than once" in str(exc_info.value)


def test_validate_missing_oid_rejected():
    with pytest.raises(ValueError) as exc_info:
        validate_custom_extensions([{"value_b64": EXAMPLE_VALUE_B64}], [EXAMPLE_OID])
    assert "missing required field 'oid'" in str(exc_info.value)


def test_validate_missing_value_rejected():
    with pytest.raises(ValueError) as exc_info:
        validate_custom_extensions([{"oid": EXAMPLE_OID}], [EXAMPLE_OID])
    assert "missing required field 'value_b64'" in str(exc_info.value)


def test_validate_invalid_oid_format_rejected():
    # The malformed OID must be on the allowlist so we reach the OID-format check
    with pytest.raises(ValueError) as exc_info:
        validate_custom_extensions([_extension(oid="not-an-oid")], ["not-an-oid"])
    assert "not a valid object identifier" in str(exc_info.value)


def test_validate_invalid_base64_rejected():
    with pytest.raises(ValueError) as exc_info:
        validate_custom_extensions([_extension(value_b64="not base64!!")], [EXAMPLE_OID])
    assert "invalid base64" in str(exc_info.value)


# ---------------------------------------------------------------------------
# convert_extensions_to_x509 - DER conversion
# ---------------------------------------------------------------------------


def test_convert_produces_unrecognized_extension():
    converted = convert_extensions_to_x509([_extension(critical=True)])
    assert len(converted) == 1

    extension, critical = converted[0]
    assert isinstance(extension, x509.UnrecognizedExtension)
    assert extension.oid == x509.ObjectIdentifier(EXAMPLE_OID)
    assert extension.value == EXAMPLE_VALUE
    assert critical is True


def test_convert_critical_defaults_to_false():
    converted = convert_extensions_to_x509([{"oid": EXAMPLE_OID, "value_b64": EXAMPLE_VALUE_B64}])
    _, critical = converted[0]
    assert critical is False


def test_convert_empty_list():
    converted = convert_extensions_to_x509([])
    assert isinstance(converted, list)
    assert not converted


# ---------------------------------------------------------------------------
# create_csr_info / allowlist env helper - request-layer plumbing
# ---------------------------------------------------------------------------


def test_create_csr_info_carries_extensions():
    event = {"common_name": "blah.example.com", "extensions": [_extension()]}
    csr_info = create_csr_info(event)
    assert csr_info.extensions == [_extension()]


def test_create_csr_info_defaults_extensions_to_empty():
    csr_info = create_csr_info({"common_name": "blah.example.com"})
    assert not csr_info.extensions


def test_get_custom_extension_allowlist_from_env(monkeypatch):
    monkeypatch.setenv("CUSTOM_EXTENSION_ALLOWLIST", '["1.2.3.4", "1.3.6.1.4.1.55555.1.1"]')
    assert get_custom_extension_allowlist() == ["1.2.3.4", "1.3.6.1.4.1.55555.1.1"]


def test_get_custom_extension_allowlist_defaults_to_empty(monkeypatch):
    monkeypatch.delenv("CUSTOM_EXTENSION_ALLOWLIST", raising=False)
    assert get_custom_extension_allowlist() == []


# ---------------------------------------------------------------------------
# ca_build_cert - end-to-end: the extension lands in the issued certificate
# ---------------------------------------------------------------------------


def _build_csr(common_name="custom-ext.example.com"):
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr


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


def _issue_leaf(extensions):
    """Build and sign a leaf certificate with the given custom extension dicts."""
    csr = _build_csr()
    ca_cert, ca_key = _build_ca_cert()
    cert_request_info = {
        "Purposes": ["client_auth"],
        "Extensions": convert_extensions_to_x509(extensions),
    }
    builder = ca_build_cert(csr, ca_cert, lifetime=30, delta=timedelta(minutes=5), cert_request_info=cert_request_info)
    return builder.sign(ca_key, hashes.SHA256())


def test_ca_build_cert_includes_custom_extension():
    cert = _issue_leaf([_extension(critical=False)])

    extension = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(EXAMPLE_OID))
    assert extension.critical is False
    assert extension.value.value == EXAMPLE_VALUE


def test_ca_build_cert_preserves_extension_criticality():
    cert = _issue_leaf([_extension(critical=True)])

    extension = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(EXAMPLE_OID))
    assert extension.critical is True


def test_ca_build_cert_is_additive_not_replacing():
    # The default extension chain must be untouched when a custom extension is added
    cert = _issue_leaf([_extension()])

    # custom extension present
    cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(EXAMPLE_OID))
    # default CA-controlled extensions still present
    cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
    cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
    cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)


def test_ca_build_cert_without_extensions_adds_nothing_extra():
    cert = _issue_leaf([])
    with pytest.raises(x509.ExtensionNotFound):
        cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(EXAMPLE_OID))
