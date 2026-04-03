from lambda_code.expiry.expiry import process_certificate_expiry, process_certificate_expired, _collect_certificates
from unittest.mock import patch, MagicMock
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timedelta, timezone
import base64


def _generate_test_key():
    return ec.generate_private_key(ec.SECP256R1())


def _generate_test_cert(private_key, common_name="direct-invoke.example.com", not_valid_before=None):
    if not_valid_before is None:
        not_valid_before = datetime(2026, 3, 1, 8, 44, 45, tzinfo=timezone.utc)

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


def _make_db_certificate_with_notify(cert, common_name="direct-invoke.example.com", notify_expiry=True):
    """Create a DynamoDB certificate item with NotifyExpiry attribute"""
    pem = cert.public_bytes(serialization.Encoding.PEM)
    item = {
        "CommonName": {"S": common_name},
        "SerialNumber": {"S": str(cert.serial_number)},
        "Certificate": {"B": base64.b64encode(pem)},
        "Issued": {"S": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S")},
        "Expires": {"S": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S")},
        "NotifyExpiry": {"BOOL": notify_expiry},
    }
    return item


@patch("lambda_code.expiry.expiry.publish_to_sns")
@patch("lambda_code.expiry.expiry.db_expiry_reminder_already_sent")
def test_non_gitops_cert_with_notify_expiry_gets_reminder(mock_already_sent, mock_sns):
    """Non-GitOps cert with NotifyExpiry=true should get expiry warning"""
    key = _generate_test_key()
    now = datetime(2026, 3, 1, 12, 0, 0)
    expiry = now + timedelta(days=30)
    cert = _generate_test_cert(key, not_valid_before=expiry - timedelta(days=31))
    db_cert = _make_db_certificate_with_notify(cert, notify_expiry=True)
    db_cert["Expires"]["S"] = expiry.strftime("%Y-%m-%d %H:%M:%S")

    mock_already_sent.return_value = False
    mock_sns.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

    result = process_certificate_expiry(
        db_cert, "direct-invoke.example.com", [30, 15, 7, 1], "arn:aws:sns:eu-west-2:123456789012:test-topic", now
    )

    assert result == 30
    mock_sns.assert_called_once()


@patch("lambda_code.expiry.expiry.publish_to_sns")
@patch("lambda_code.expiry.expiry.db_expiry_reminder_already_sent")
def test_non_gitops_cert_with_notify_expiry_gets_expired_notification(mock_already_sent, mock_sns):
    """Non-GitOps cert with NotifyExpiry=true should get expired notification"""
    key = _generate_test_key()
    now = datetime(2026, 3, 2, 12, 0, 0)
    expiry = now - timedelta(hours=6)
    cert = _generate_test_cert(key, not_valid_before=expiry - timedelta(days=31))
    db_cert = _make_db_certificate_with_notify(cert, notify_expiry=True)
    db_cert["Expires"]["S"] = expiry.strftime("%Y-%m-%d %H:%M:%S")

    mock_already_sent.return_value = False
    mock_sns.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

    result = process_certificate_expired(
        db_cert, "direct-invoke.example.com", "arn:aws:sns:eu-west-2:123456789012:test-topic", now
    )

    assert result == 0
    mock_sns.assert_called_once()


@patch("lambda_code.expiry.expiry.publish_to_sns")
@patch("lambda_code.expiry.expiry.db_expiry_reminder_already_sent")
def test_non_gitops_cert_no_reminder_when_not_in_schedule(
    mock_already_sent, mock_sns
):  # pylint:disable=unused-argument
    """Non-GitOps cert should not get reminder when days remaining not in schedule"""
    key = _generate_test_key()
    now = datetime(2026, 3, 1, 12, 0, 0)
    expiry = now + timedelta(days=25)
    cert = _generate_test_cert(key, not_valid_before=expiry - timedelta(days=31))
    db_cert = _make_db_certificate_with_notify(cert, notify_expiry=True)
    db_cert["Expires"]["S"] = expiry.strftime("%Y-%m-%d %H:%M:%S")

    result = process_certificate_expiry(
        db_cert, "direct-invoke.example.com", [30, 15, 7, 1], "arn:aws:sns:eu-west-2:123456789012:test-topic", now
    )

    assert result is None
    mock_sns.assert_not_called()


@patch("lambda_code.expiry.expiry.get_latest_certificate")
@patch("lambda_code.expiry.expiry.load_pem_x509_csr")
@patch("lambda_code.expiry.expiry.s3_download")
@patch("lambda_code.expiry.expiry.db_list_notify_expiry_certificates")
def test_gitops_cert_with_notify_expiry_false_excluded(mock_db_scan, mock_s3, mock_load_csr, mock_get_cert):
    """GitOps cert with NotifyExpiry=false should be excluded from expiry processing"""

    # no certs from DynamoDB scan
    mock_db_scan.return_value = []

    # tls.json returns one GitOps cert
    mock_s3_body = MagicMock()
    mock_s3_body.read.return_value = b'[{"common_name": "gitops.example.com", "csr_file": "gitops.csr"}]'
    mock_s3.return_value = {"Body": mock_s3_body}

    mock_csr = MagicMock()
    mock_csr.public_key.return_value.public_bytes.return_value = b"fake-public-key"
    mock_load_csr.return_value = mock_csr

    # DynamoDB record with NotifyExpiry=false
    mock_get_cert.return_value = {
        "CommonName": {"S": "gitops.example.com"},
        "SerialNumber": {"S": "123456"},
        "NotifyExpiry": {"BOOL": False},
        "Expires": {"S": "2026-04-01 12:00:00"},
    }

    result = _collect_certificates("test-project", "dev", "ext-bucket", "int-bucket")
    assert len(result) == 0


@patch("lambda_code.expiry.expiry.get_latest_certificate")
@patch("lambda_code.expiry.expiry.load_pem_x509_csr")
@patch("lambda_code.expiry.expiry.s3_download")
@patch("lambda_code.expiry.expiry.db_list_notify_expiry_certificates")
def test_gitops_cert_without_notify_expiry_attr_included(mock_db_scan, mock_s3, mock_load_csr, mock_get_cert):
    """GitOps cert without NotifyExpiry attribute (legacy) should still be processed"""

    mock_db_scan.return_value = []

    mock_s3_body = MagicMock()
    mock_s3_body.read.return_value = b'[{"common_name": "gitops.example.com", "csr_file": "gitops.csr"}]'
    mock_s3.return_value = {"Body": mock_s3_body}

    mock_csr = MagicMock()
    mock_csr.public_key.return_value.public_bytes.return_value = b"fake-public-key"
    mock_load_csr.return_value = mock_csr

    # DynamoDB record without NotifyExpiry attribute (legacy GitOps cert)
    mock_get_cert.return_value = {
        "CommonName": {"S": "gitops.example.com"},
        "SerialNumber": {"S": "123456"},
        "Expires": {"S": "2026-04-01 12:00:00"},
    }

    result = _collect_certificates("test-project", "dev", "ext-bucket", "int-bucket")
    assert len(result) == 1
    assert ("gitops.example.com", "123456") in result


@patch("lambda_code.expiry.expiry.publish_to_sns")
@patch("lambda_code.expiry.expiry.db_expiry_reminder_already_sent")
def test_non_gitops_cert_no_duplicate_reminder(mock_already_sent, mock_sns):
    """Non-GitOps cert should not get duplicate reminder"""
    key = _generate_test_key()
    now = datetime(2026, 3, 1, 12, 0, 0)
    expiry = now + timedelta(days=30)
    cert = _generate_test_cert(key, not_valid_before=expiry - timedelta(days=31))
    db_cert = _make_db_certificate_with_notify(cert, notify_expiry=True)
    db_cert["Expires"]["S"] = expiry.strftime("%Y-%m-%d %H:%M:%S")
    db_cert["ExpiryReminders"] = {"L": [{"S": "2026-03-01 08:00:00"}]}

    mock_already_sent.return_value = True

    result = process_certificate_expiry(
        db_cert, "direct-invoke.example.com", [30, 15, 7, 1], "arn:aws:sns:eu-west-2:123456789012:test-topic", now
    )

    assert result is None
    mock_sns.assert_not_called()
