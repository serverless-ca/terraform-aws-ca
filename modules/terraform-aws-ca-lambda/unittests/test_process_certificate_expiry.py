from lambda_code.expiry.expiry import process_certificate_expiry
from unittest.mock import patch
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timedelta, timezone
import base64


def _generate_test_key():
    return ec.generate_private_key(ec.SECP256R1())


def _generate_test_cert(private_key, common_name="test-expiry.example.com", not_valid_before=None):
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


def _make_db_certificate(cert, common_name="test-expiry.example.com"):
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return {
        "CommonName": {"S": common_name},
        "SerialNumber": {"S": str(cert.serial_number)},
        "Certificate": {"B": base64.b64encode(pem)},
        "Issued": {"S": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S")},
        "Expires": {"S": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S")},
    }


@patch("lambda_code.expiry.expiry.publish_to_sns")
@patch("lambda_code.expiry.expiry.db_expiry_reminder_already_sent")
def test_process_certificate_expiry_reminder_sent(mock_already_sent, mock_sns):
    """Test that a reminder is sent when days_remaining matches a reminder setting"""
    key = _generate_test_key()
    # Certificate expires in exactly 30 days from 'now'
    now = datetime(2026, 3, 1, 12, 0, 0)
    expiry = now + timedelta(days=30)
    cert = _generate_test_cert(key, not_valid_before=expiry - timedelta(days=31))
    db_cert = _make_db_certificate(cert)
    db_cert["Expires"]["S"] = expiry.strftime("%Y-%m-%d %H:%M:%S")

    mock_already_sent.return_value = False
    mock_sns.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

    result = process_certificate_expiry(
        db_cert, "test-expiry.example.com", [30, 15, 7, 1], "arn:aws:sns:eu-west-2:123456789012:test-topic", now
    )

    assert result == 30
    mock_sns.assert_called_once()


@patch("lambda_code.expiry.expiry.publish_to_sns")
@patch("lambda_code.expiry.expiry.db_expiry_reminder_already_sent")
def test_process_certificate_expiry_no_reminder_needed(mock_already_sent, mock_sns):
    """Test that no reminder is sent when days_remaining does not match any setting"""
    key = _generate_test_key()
    # Certificate expires in 25 days - not in the reminder list
    now = datetime(2026, 3, 1, 12, 0, 0)
    expiry = now + timedelta(days=25)
    cert = _generate_test_cert(key, not_valid_before=expiry - timedelta(days=31))
    db_cert = _make_db_certificate(cert)
    db_cert["Expires"]["S"] = expiry.strftime("%Y-%m-%d %H:%M:%S")

    result = process_certificate_expiry(
        db_cert, "test-expiry.example.com", [30, 15, 7, 1], "arn:aws:sns:eu-west-2:123456789012:test-topic", now
    )

    assert result is None
    mock_already_sent.assert_not_called()
    mock_sns.assert_not_called()


@patch("lambda_code.expiry.expiry.publish_to_sns")
@patch("lambda_code.expiry.expiry.db_expiry_reminder_already_sent")
def test_process_certificate_expiry_already_sent_today(mock_already_sent, mock_sns):
    """Test that no reminder is sent if one was already sent today"""
    key = _generate_test_key()
    now = datetime(2026, 3, 1, 12, 0, 0)
    expiry = now + timedelta(days=30)
    cert = _generate_test_cert(key, not_valid_before=expiry - timedelta(days=31))
    db_cert = _make_db_certificate(cert)
    db_cert["Expires"]["S"] = expiry.strftime("%Y-%m-%d %H:%M:%S")
    # Simulate that a reminder has already been recorded today
    db_cert["ExpiryReminders"] = {"L": [{"S": "2026-03-01 08:00:00"}]}

    mock_already_sent.return_value = True

    result = process_certificate_expiry(
        db_cert, "test-expiry.example.com", [30, 15, 7, 1], "arn:aws:sns:eu-west-2:123456789012:test-topic", now
    )

    assert result is None
    mock_sns.assert_not_called()


@patch("lambda_code.expiry.expiry.publish_to_sns")
@patch("lambda_code.expiry.expiry.db_expiry_reminder_already_sent")
def test_process_certificate_expiry_15_days(mock_already_sent, mock_sns):
    """Test reminder at 15 days before expiry"""
    key = _generate_test_key()
    now = datetime(2026, 3, 1, 12, 0, 0)
    expiry = now + timedelta(days=15)
    cert = _generate_test_cert(key, not_valid_before=expiry - timedelta(days=31))
    db_cert = _make_db_certificate(cert)
    db_cert["Expires"]["S"] = expiry.strftime("%Y-%m-%d %H:%M:%S")

    mock_already_sent.return_value = False
    mock_sns.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

    result = process_certificate_expiry(
        db_cert, "test-expiry.example.com", [30, 15, 7, 1], "arn:aws:sns:eu-west-2:123456789012:test-topic", now
    )

    assert result == 15
    mock_sns.assert_called_once()


@patch("lambda_code.expiry.expiry.publish_to_sns")
@patch("lambda_code.expiry.expiry.db_expiry_reminder_already_sent")
def test_process_certificate_expiry_7_days(mock_already_sent, mock_sns):
    """Test reminder at 7 days before expiry"""
    key = _generate_test_key()
    now = datetime(2026, 3, 1, 12, 0, 0)
    expiry = now + timedelta(days=7)
    cert = _generate_test_cert(key, not_valid_before=expiry - timedelta(days=31))
    db_cert = _make_db_certificate(cert)
    db_cert["Expires"]["S"] = expiry.strftime("%Y-%m-%d %H:%M:%S")

    mock_already_sent.return_value = False
    mock_sns.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

    result = process_certificate_expiry(
        db_cert, "test-expiry.example.com", [30, 15, 7, 1], "arn:aws:sns:eu-west-2:123456789012:test-topic", now
    )

    assert result == 7
    mock_sns.assert_called_once()


@patch("lambda_code.expiry.expiry.publish_to_sns")
@patch("lambda_code.expiry.expiry.db_expiry_reminder_already_sent")
def test_process_certificate_expiry_1_day(mock_already_sent, mock_sns):
    """Test reminder at 1 day before expiry"""
    key = _generate_test_key()
    now = datetime(2026, 3, 1, 12, 0, 0)
    expiry = now + timedelta(days=1)
    cert = _generate_test_cert(key, not_valid_before=expiry - timedelta(days=31))
    db_cert = _make_db_certificate(cert)
    db_cert["Expires"]["S"] = expiry.strftime("%Y-%m-%d %H:%M:%S")

    mock_already_sent.return_value = False
    mock_sns.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

    result = process_certificate_expiry(
        db_cert, "test-expiry.example.com", [30, 15, 7, 1], "arn:aws:sns:eu-west-2:123456789012:test-topic", now
    )

    assert result == 1
    mock_sns.assert_called_once()


@patch("lambda_code.expiry.expiry.publish_to_sns")
@patch("lambda_code.expiry.expiry.db_expiry_reminder_already_sent")
def test_process_certificate_expiry_already_expired(_mock_already_sent, mock_sns):
    """Test that no reminder is sent when certificate is already expired"""
    key = _generate_test_key()
    now = datetime(2026, 3, 1, 12, 0, 0)
    expiry = now - timedelta(days=5)  # expired 5 days ago
    cert = _generate_test_cert(key, not_valid_before=expiry - timedelta(days=31))
    db_cert = _make_db_certificate(cert)
    db_cert["Expires"]["S"] = expiry.strftime("%Y-%m-%d %H:%M:%S")

    result = process_certificate_expiry(
        db_cert, "test-expiry.example.com", [30, 15, 7, 1], "arn:aws:sns:eu-west-2:123456789012:test-topic", now
    )

    assert result is None
    mock_sns.assert_not_called()


@patch("lambda_code.expiry.expiry.publish_to_sns")
@patch("lambda_code.expiry.expiry.db_expiry_reminder_already_sent")
def test_process_certificate_expiry_previous_reminder_different_day(mock_already_sent, mock_sns):
    """Test reminder is sent when previous reminder was on a different day"""
    key = _generate_test_key()
    now = datetime(2026, 3, 1, 12, 0, 0)
    expiry = now + timedelta(days=15)
    cert = _generate_test_cert(key, not_valid_before=expiry - timedelta(days=31))
    db_cert = _make_db_certificate(cert)
    db_cert["Expires"]["S"] = expiry.strftime("%Y-%m-%d %H:%M:%S")
    # Previous reminder was at 30 days, on a different day
    db_cert["ExpiryReminders"] = {"L": [{"S": "2026-02-14 08:00:00"}]}

    mock_already_sent.return_value = False
    mock_sns.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

    result = process_certificate_expiry(
        db_cert, "test-expiry.example.com", [30, 15, 7, 1], "arn:aws:sns:eu-west-2:123456789012:test-topic", now
    )

    assert result == 15
    mock_sns.assert_called_once()


@patch("lambda_code.expiry.expiry.publish_to_sns")
@patch("lambda_code.expiry.expiry.db_expiry_reminder_already_sent")
def test_process_certificate_expiry_sns_message_contents(mock_already_sent, mock_sns):
    """Test that the SNS message contains expected keys and values"""
    key = _generate_test_key()
    now = datetime(2026, 3, 1, 12, 0, 0)
    expiry = now + timedelta(days=30)
    cert = _generate_test_cert(key, not_valid_before=expiry - timedelta(days=31))
    db_cert = _make_db_certificate(cert)
    db_cert["Expires"]["S"] = expiry.strftime("%Y-%m-%d %H:%M:%S")

    mock_already_sent.return_value = False
    mock_sns.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

    process_certificate_expiry(
        db_cert, "test-expiry.example.com", [30, 15, 7, 1], "arn:aws:sns:eu-west-2:123456789012:test-topic", now
    )

    # Verify the SNS call arguments
    call_args = mock_sns.call_args
    cert_details = call_args[0][0]
    subject_text = call_args[0][1]
    topic_arn = call_args[0][2]
    keys_to_publish = call_args[0][3]

    assert subject_text == "Certificate Expiry Warning"
    assert topic_arn == "arn:aws:sns:eu-west-2:123456789012:test-topic"
    assert cert_details["DaysRemaining"] == 30
    assert cert_details["CertificateInfo"]["CommonName"] == "test-expiry.example.com"
    assert "CN=test-expiry.example.com" in cert_details["Subject"]
    assert keys_to_publish == ["CertificateInfo", "Base64Certificate", "Subject", "DaysRemaining"]
