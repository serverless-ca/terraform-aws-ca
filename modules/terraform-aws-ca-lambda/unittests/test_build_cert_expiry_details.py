from lambda_code.expiry.expiry import build_cert_expiry_details
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timedelta, timezone
import base64


def _generate_test_key():
    return ec.generate_private_key(ec.SECP256R1())


def _generate_test_cert(private_key, common_name="test-expiry.example.com", not_valid_before=None, x509_subject=None):
    if not_valid_before is None:
        not_valid_before = datetime(2026, 3, 1, 8, 44, 45, tzinfo=timezone.utc)

    if x509_subject is None:
        x509_subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "London"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Corp"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "DevOps"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "England"),
            ]
        )

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


def _make_db_certificate(cert, common_name="test-expiry.example.com"):
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return {
        "CommonName": {"S": common_name},
        "SerialNumber": {"S": str(cert.serial_number)},
        "Certificate": {"B": base64.b64encode(pem)},
        "Issued": {"S": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S")},
        "Expires": {"S": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S")},
    }


def test_build_cert_expiry_details_structure():
    """Test that build_cert_expiry_details returns the correct structure"""
    key = _generate_test_key()
    cert = _generate_test_cert(key)
    db_cert = _make_db_certificate(cert)

    result = build_cert_expiry_details(db_cert, "test-expiry.example.com", 30)

    assert "CertificateInfo" in result
    assert "Base64Certificate" in result
    assert "Subject" in result
    assert "DaysRemaining" in result


def test_build_cert_expiry_details_certificate_info():
    """Test that CertificateInfo contains expected keys and values"""
    key = _generate_test_key()
    cert = _generate_test_cert(key)
    db_cert = _make_db_certificate(cert)

    result = build_cert_expiry_details(db_cert, "test-expiry.example.com", 30)

    cert_info = result["CertificateInfo"]
    assert cert_info["CommonName"] == "test-expiry.example.com"
    assert cert_info["SerialNumber"] == str(cert.serial_number)
    assert cert_info["Issued"] == cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S")
    assert cert_info["Expires"] == cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S")


def test_build_cert_expiry_details_days_remaining():
    """Test that DaysRemaining is set correctly"""
    key = _generate_test_key()
    cert = _generate_test_cert(key)
    db_cert = _make_db_certificate(cert)

    result = build_cert_expiry_details(db_cert, "test-expiry.example.com", 15)
    assert result["DaysRemaining"] == 15


def test_build_cert_expiry_details_subject():
    """Test that Subject is the RFC 4514 string of the certificate subject"""
    key = _generate_test_key()
    cert = _generate_test_cert(key)
    db_cert = _make_db_certificate(cert)

    result = build_cert_expiry_details(db_cert, "test-expiry.example.com", 30)
    assert result["Subject"] == cert.subject.rfc4514_string()
    assert "CN=test-expiry.example.com" in result["Subject"]


def test_build_cert_expiry_details_base64_certificate_string():
    """Test that Base64Certificate is a string regardless of input type"""
    key = _generate_test_key()
    cert = _generate_test_cert(key)
    db_cert = _make_db_certificate(cert)

    result = build_cert_expiry_details(db_cert, "test-expiry.example.com", 30)
    assert isinstance(result["Base64Certificate"], str)


def test_build_cert_expiry_details_base64_certificate_str_input():
    """Test Base64Certificate when input is already a string"""
    key = _generate_test_key()
    cert = _generate_test_cert(key)
    pem = cert.public_bytes(serialization.Encoding.PEM)
    b64_str = base64.b64encode(pem).decode("utf-8")

    db_cert = {
        "CommonName": {"S": "test-expiry.example.com"},
        "SerialNumber": {"S": str(cert.serial_number)},
        "Certificate": {"B": b64_str},
        "Issued": {"S": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S")},
        "Expires": {"S": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S")},
    }

    result = build_cert_expiry_details(db_cert, "test-expiry.example.com", 7)
    assert isinstance(result["Base64Certificate"], str)
    assert result["Base64Certificate"] == b64_str
