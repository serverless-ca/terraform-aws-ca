from lambda_code.tls_cert.tls_cert import certificate_already_issued
from utils.certs.types import Subject
from unittest.mock import patch
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timedelta, timezone
from dateutil.tz import tzutc
import base64


def _generate_test_key():
    return ec.generate_private_key(ec.SECP256R1())


def _generate_test_csr(private_key, common_name="test.example.com"):
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(private_key, hashes.SHA256())
    )


def _generate_test_cert(private_key, common_name="test.example.com", not_valid_before=None, x509_subject=None):
    if not_valid_before is None:
        not_valid_before = datetime(2025, 11, 30, 15, 0, 0, tzinfo=timezone.utc)

    if x509_subject is None:
        x509_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509_subject)
        .issuer_name(x509_subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_before + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    return cert


def _make_db_certificate(cert):
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return {
        "CommonName": {"S": "test.example.com"},
        "SerialNumber": {"S": str(cert.serial_number)},
        "Certificate": {"B": base64.b64encode(pem)},
        "Issued": {"S": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S")},
        "Expires": {"S": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S")},
    }


@patch("lambda_code.tls_cert.tls_cert.db_list_certificates")
def test_certificate_already_issued_matching(mock_db_list):
    """Test returns True when CSR matches an existing certificate"""
    private_key = _generate_test_key()
    csr = _generate_test_csr(private_key)
    cert = _generate_test_cert(private_key, not_valid_before=datetime(2025, 11, 30, 15, 0, 0, tzinfo=timezone.utc))

    mock_db_list.return_value = [_make_db_certificate(cert)]
    subject = Subject("test.example.com")
    last_modified = datetime(2025, 11, 30, 20, 36, 36, tzinfo=tzutc())

    result = certificate_already_issued(csr, subject, last_modified, "test-project", "dev", False)
    assert result is True


@patch("lambda_code.tls_cert.tls_cert.db_list_certificates")
def test_certificate_already_issued_force_issue(mock_db_list):
    """Test returns False when force_issue is True"""
    private_key = _generate_test_key()
    csr = _generate_test_csr(private_key)
    subject = Subject("test.example.com")
    last_modified = datetime(2025, 11, 30, 20, 36, 36, tzinfo=tzutc())

    result = certificate_already_issued(csr, subject, last_modified, "test-project", "dev", True)
    assert result is False
    mock_db_list.assert_not_called()


@patch("lambda_code.tls_cert.tls_cert.db_list_certificates")
def test_certificate_already_issued_last_modified_none(mock_db_list):
    """Test returns False when last_modified is None"""
    private_key = _generate_test_key()
    csr = _generate_test_csr(private_key)
    subject = Subject("test.example.com")

    result = certificate_already_issued(csr, subject, None, "test-project", "dev", False)
    assert result is False
    mock_db_list.assert_not_called()


@patch("lambda_code.tls_cert.tls_cert.db_list_certificates")
def test_certificate_already_issued_no_certificates(mock_db_list):
    """Test returns False when no certificates exist in DynamoDB"""
    private_key = _generate_test_key()
    csr = _generate_test_csr(private_key)
    subject = Subject("test.example.com")
    last_modified = datetime(2025, 11, 30, 20, 36, 36, tzinfo=tzutc())

    mock_db_list.return_value = []

    result = certificate_already_issued(csr, subject, last_modified, "test-project", "dev", False)
    assert result is False


@patch("lambda_code.tls_cert.tls_cert.db_list_certificates")
def test_certificate_already_issued_different_key(mock_db_list):
    """Test returns False when public key does not match"""
    csr_key = _generate_test_key()
    cert_key = _generate_test_key()
    csr = _generate_test_csr(csr_key)
    cert = _generate_test_cert(cert_key, not_valid_before=datetime(2025, 11, 30, 15, 0, 0, tzinfo=timezone.utc))

    mock_db_list.return_value = [_make_db_certificate(cert)]
    subject = Subject("test.example.com")
    last_modified = datetime(2025, 11, 30, 20, 36, 36, tzinfo=tzutc())

    result = certificate_already_issued(csr, subject, last_modified, "test-project", "dev", False)
    assert result is False


@patch("lambda_code.tls_cert.tls_cert.db_list_certificates")
def test_certificate_already_issued_different_date(mock_db_list):
    """Test returns False when last_modified date does not match certificate valid_from date"""
    private_key = _generate_test_key()
    csr = _generate_test_csr(private_key)
    cert = _generate_test_cert(private_key, not_valid_before=datetime(2025, 11, 30, 15, 0, 0, tzinfo=timezone.utc))

    mock_db_list.return_value = [_make_db_certificate(cert)]
    subject = Subject("test.example.com")
    # last_modified is a different day
    last_modified = datetime(2025, 12, 1, 20, 36, 36, tzinfo=tzutc())

    result = certificate_already_issued(csr, subject, last_modified, "test-project", "dev", False)
    assert result is False


@patch("lambda_code.tls_cert.tls_cert.db_list_certificates")
def test_certificate_already_issued_cert_has_full_subject_event_has_cn_only(mock_db_list):
    """Test returns True when certificate has full subject from CSR but event only has common_name"""
    private_key = _generate_test_key()
    csr = _generate_test_csr(private_key, common_name="Cloud Architect")

    # Certificate has full subject (added during signing from CSR file fields)
    full_x509_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Cloud Architect"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "London"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Serverless Inc"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Security Operations"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "England"),
        ]
    )

    cert = _generate_test_cert(
        private_key,
        not_valid_before=datetime(2025, 11, 30, 15, 0, 0, tzinfo=timezone.utc),
        x509_subject=full_x509_subject,
    )

    mock_db_list.return_value = [_make_db_certificate(cert)]
    # Subject only has common_name (as built from event with no org/state fields)
    subject = Subject("Cloud Architect")
    last_modified = datetime(2025, 11, 30, 20, 36, 36, tzinfo=tzutc())

    result = certificate_already_issued(csr, subject, last_modified, "test-project", "dev", False)
    assert result is True


@patch("lambda_code.tls_cert.tls_cert.db_list_certificates")
def test_certificate_already_issued_full_subject(mock_db_list):
    """Test returns True when CSR has only CN but certificate and Subject have full org details"""
    private_key = _generate_test_key()
    csr = _generate_test_csr(private_key, common_name="Cloud Architect")

    # Certificate has full subject like in production
    full_subject = Subject("Cloud Architect")
    full_subject.country = "GB"
    full_subject.locality = "London"
    full_subject.organization = "Serverless Inc"
    full_subject.organizational_unit = "Security Operations"
    full_subject.state = "England"

    cert = _generate_test_cert(
        private_key,
        not_valid_before=datetime(2025, 11, 30, 15, 0, 0, tzinfo=timezone.utc),
        x509_subject=full_subject.x509_name(),
    )

    mock_db_list.return_value = [_make_db_certificate(cert)]
    last_modified = datetime(2025, 11, 30, 20, 36, 36, tzinfo=tzutc())

    result = certificate_already_issued(csr, full_subject, last_modified, "test-project", "dev", False)
    assert result is True
