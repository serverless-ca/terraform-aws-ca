from lambda_code.expiry.expiry import get_latest_certificate, _get_subject_from_csr_match
from unittest.mock import patch
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timedelta, timezone
import base64


def _generate_test_key():
    return ec.generate_private_key(ec.SECP256R1())


def _generate_test_cert(private_key, common_name="test.example.com", not_valid_before=None, x509_subject=None):
    if not_valid_before is None:
        not_valid_before = datetime(2026, 3, 1, 8, 0, 0, tzinfo=timezone.utc)

    if x509_subject is None:
        x509_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    return (
        x509.CertificateBuilder()
        .subject_name(x509_subject)
        .issuer_name(x509_subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_before + timedelta(days=31))
        .sign(private_key, hashes.SHA256())
    )


def _make_db_certificate(cert, common_name="test.example.com"):
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return {
        "CommonName": {"S": common_name},
        "SerialNumber": {"S": str(cert.serial_number)},
        "Certificate": {"B": base64.b64encode(pem)},
        "Issued": {"S": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S")},
        "Expires": {"S": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S")},
    }


def _get_public_key_pem(private_key):
    return (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )


# --- Tests for _get_subject_from_csr_match ---


def test_get_subject_from_csr_match_found():
    """Test returns subject when CSR public key matches a certificate"""
    key = _generate_test_key()
    cert = _generate_test_cert(key)
    db_cert = _make_db_certificate(cert)
    csr_pub_pem = _get_public_key_pem(key)

    result = _get_subject_from_csr_match([db_cert], csr_pub_pem, "test.example.com")
    assert result == cert.subject.rfc4514_string()


def test_get_subject_from_csr_match_not_found():
    """Test returns None when no certificate matches the CSR public key"""
    cert_key = _generate_test_key()
    csr_key = _generate_test_key()
    cert = _generate_test_cert(cert_key)
    db_cert = _make_db_certificate(cert)
    csr_pub_pem = _get_public_key_pem(csr_key)

    result = _get_subject_from_csr_match([db_cert], csr_pub_pem, "test.example.com")
    assert result is None


def test_get_subject_from_csr_match_multiple_certs():
    """Test returns subject from the correct matching certificate among multiple"""
    key1 = _generate_test_key()
    key2 = _generate_test_key()

    full_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Corp"),
        ]
    )

    cert1 = _generate_test_cert(key1)
    cert2 = _generate_test_cert(key2, x509_subject=full_subject)

    db_certs = [_make_db_certificate(cert1), _make_db_certificate(cert2)]
    csr_pub_pem = _get_public_key_pem(key2)

    result = _get_subject_from_csr_match(db_certs, csr_pub_pem, "test.example.com")
    assert result == cert2.subject.rfc4514_string()


# --- Tests for get_latest_certificate ---


@patch("lambda_code.expiry.expiry.db_list_certificates")
def test_get_latest_certificate_no_certificates(mock_db_list):
    """Test returns None when no certificates found for common name"""
    mock_db_list.return_value = []
    key = _generate_test_key()
    csr_pub_pem = _get_public_key_pem(key)

    result = get_latest_certificate("test-project", "dev", "test.example.com", csr_pub_pem)
    assert result is None


@patch("lambda_code.expiry.expiry.db_list_certificates")
def test_get_latest_certificate_no_key_match(mock_db_list):
    """Test returns None when no certificate matches the CSR public key"""
    cert_key = _generate_test_key()
    csr_key = _generate_test_key()
    cert = _generate_test_cert(cert_key)
    mock_db_list.return_value = [_make_db_certificate(cert)]
    csr_pub_pem = _get_public_key_pem(csr_key)

    result = get_latest_certificate("test-project", "dev", "test.example.com", csr_pub_pem)
    assert result is None


@patch("lambda_code.expiry.expiry.db_list_certificates")
def test_get_latest_certificate_single_cert(mock_db_list):
    """Test returns the single matching certificate"""
    key = _generate_test_key()
    cert = _generate_test_cert(key)
    db_cert = _make_db_certificate(cert)
    mock_db_list.return_value = [db_cert]
    csr_pub_pem = _get_public_key_pem(key)

    result = get_latest_certificate("test-project", "dev", "test.example.com", csr_pub_pem)
    assert result is not None
    assert result["SerialNumber"]["S"] == str(cert.serial_number)


@patch("lambda_code.expiry.expiry.db_list_certificates")
def test_get_latest_certificate_picks_latest_expiry(mock_db_list):
    """Test returns the certificate with the latest expiry date when multiple match"""
    key = _generate_test_key()

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        ]
    )

    cert_old = _generate_test_cert(
        key,
        not_valid_before=datetime(2025, 6, 1, 8, 0, 0, tzinfo=timezone.utc),
        x509_subject=subject,
    )
    cert_new = _generate_test_cert(
        key,
        not_valid_before=datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc),
        x509_subject=subject,
    )

    # Use a different key for the newer cert to simulate re-issuance with same subject
    key2 = _generate_test_key()
    cert_newest = _generate_test_cert(
        key2,
        not_valid_before=datetime(2026, 2, 1, 8, 0, 0, tzinfo=timezone.utc),
        x509_subject=subject,
    )

    db_certs = [
        _make_db_certificate(cert_old),
        _make_db_certificate(cert_new),
        _make_db_certificate(cert_newest),
    ]
    mock_db_list.return_value = db_certs
    csr_pub_pem = _get_public_key_pem(key)

    result = get_latest_certificate("test-project", "dev", "test.example.com", csr_pub_pem)
    assert result is not None
    # Should return cert_newest as it has the latest expiry and same subject
    assert result["SerialNumber"]["S"] == str(cert_newest.serial_number)


@patch("lambda_code.expiry.expiry.db_list_certificates")
def test_get_latest_certificate_ignores_different_subject(mock_db_list):
    """Test ignores certificates with different subjects when finding latest"""
    key = _generate_test_key()

    subject_a = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Org A"),
        ]
    )
    subject_b = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Org B"),
        ]
    )

    # CSR key matches cert_a, so subject_a is selected
    cert_a = _generate_test_cert(
        key,
        not_valid_before=datetime(2025, 6, 1, 8, 0, 0, tzinfo=timezone.utc),
        x509_subject=subject_a,
    )

    # Different key, different subject, later expiry - should be ignored
    key_b = _generate_test_key()
    cert_b = _generate_test_cert(
        key_b,
        not_valid_before=datetime(2026, 6, 1, 8, 0, 0, tzinfo=timezone.utc),
        x509_subject=subject_b,
    )

    mock_db_list.return_value = [_make_db_certificate(cert_a), _make_db_certificate(cert_b)]
    csr_pub_pem = _get_public_key_pem(key)

    result = get_latest_certificate("test-project", "dev", "test.example.com", csr_pub_pem)
    assert result is not None
    assert result["SerialNumber"]["S"] == str(cert_a.serial_number)
