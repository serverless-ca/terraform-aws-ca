"""
Unit tests for issuing_ca_crl.py — regression tests for issue #590.

Covers the fix that ensures revoked.json entries with a serial number absent
from the CA database are skipped gracefully rather than crashing the Lambda.
"""

import datetime
import io
import json
from unittest.mock import MagicMock, patch

from lambda_code.issuing_ca_crl.issuing_ca_crl import list_revoked_certs_from_s3
from utils.certs.db import db_get_certificate


def _make_s3_response(data):
    """Return a minimal mock S3 GetObject response whose Body contains JSON."""
    return {"Body": io.BytesIO(json.dumps(data).encode())}


# ---------------------------------------------------------------------------
# Tests for list_revoked_certs_from_s3
# ---------------------------------------------------------------------------


@patch("lambda_code.issuing_ca_crl.issuing_ca_crl.db_get_certificate")
@patch("lambda_code.issuing_ca_crl.issuing_ca_crl.s3_download")
def test_list_revoked_certs_from_s3_skips_entry_with_unknown_serial_number(mock_s3_download, mock_db_get_cert):
    """Entries in revoked.json whose serial number is absent from the DB are skipped."""
    revoked_json = [{"common_name": "test.example.com", "serial_number": "999999999999"}]

    # Provide a fresh BytesIO body on every call so both the truthiness check
    # and the actual read succeed.
    mock_s3_download.side_effect = lambda *a, **kw: _make_s3_response(revoked_json)

    # db_get_certificate now returns None when the serial number is not found.
    mock_db_get_cert.return_value = None

    revoked_certs, newly_revoked_details = list_revoked_certs_from_s3(
        "test-project", "dev", "external-bucket", "internal-bucket"
    )

    assert not revoked_certs
    assert not newly_revoked_details


@patch("lambda_code.issuing_ca_crl.issuing_ca_crl.crypto_revoked_certificate")
@patch("lambda_code.issuing_ca_crl.issuing_ca_crl.db_revocation_date")
@patch("lambda_code.issuing_ca_crl.issuing_ca_crl.db_get_certificate")
@patch("lambda_code.issuing_ca_crl.issuing_ca_crl.s3_download")
def test_list_revoked_certs_from_s3_skips_unknown_serial_among_valid_entries(
    mock_s3_download, mock_db_get_cert, mock_db_revocation_date, mock_crypto_revoked_cert
):
    """Unknown serial entries are skipped; valid entries are still included in the revoked list."""
    revoked_json = [
        {"common_name": "valid.example.com", "serial_number": "111111111111"},
        {"common_name": "unknown.example.com", "serial_number": "000000000000"},
    ]

    mock_s3_download.side_effect = lambda *a, **kw: _make_s3_response(revoked_json)

    # First call returns a valid (already-revoked) cert; second call returns None.
    valid_cert_item = {
        "CommonName": {"S": "valid.example.com"},
        "SerialNumber": {"S": "111111111111"},
        "Revoked": {"S": "2026-01-01 00:00:00"},
    }
    mock_db_get_cert.side_effect = [valid_cert_item, None]
    mock_db_revocation_date.return_value = datetime.datetime(2026, 1, 1)
    mock_crypto_revoked_cert.return_value = MagicMock()

    revoked_certs, newly_revoked_details = list_revoked_certs_from_s3(
        "test-project", "dev", "external-bucket", "internal-bucket"
    )

    assert len(revoked_certs) == 1
    assert not newly_revoked_details


# ---------------------------------------------------------------------------
# Tests for db_get_certificate
# ---------------------------------------------------------------------------


@patch("utils.certs.db.boto3")
def test_db_get_certificate_returns_none_when_serial_not_found(mock_boto3):
    """Returns None when the common name exists in DynamoDB but the serial number does not."""
    mock_client = MagicMock()
    mock_boto3.client.return_value = mock_client
    mock_client.query.return_value = {
        "Items": [
            # An entry exists for the common name, but with a *different* serial number
            {"CommonName": {"S": "test.example.com"}, "SerialNumber": {"S": "111111111111"}}
        ]
    }

    result = db_get_certificate("test-project", "dev", "test.example.com", "999999999999")

    assert result is None


@patch("utils.certs.db.boto3")
def test_db_get_certificate_returns_none_when_no_items_for_common_name(mock_boto3):
    """Returns None when DynamoDB holds no items at all for the given common name."""
    mock_client = MagicMock()
    mock_boto3.client.return_value = mock_client
    mock_client.query.return_value = {"Items": []}

    result = db_get_certificate("test-project", "dev", "nonexistent.example.com", "999999999999")

    assert result is None
