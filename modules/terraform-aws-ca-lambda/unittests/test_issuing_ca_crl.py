"""
Unit tests for issuing_ca_crl.py

Regression tests for issue #590:
  "Issuing CA CRL Lambda fails if revoked certificate serial number not in CA database"

When revoked.json contains a valid common name but a serial number that does not
exist in the CA database, the Lambda currently crashes with:
  IndexError: list index out of range
  (in utils/certs/db.py, db_get_certificate)

Desired behaviour:
  - Ignore the revocation entry and log a message
  - Continue and issue the CRL successfully
"""

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
    """
    When revoked.json references a serial number absent from the CA database,
    list_revoked_certs_from_s3 must skip the entry rather than propagating the
    IndexError raised by db_get_certificate.

    Expected: returns ([], []) without raising an exception.
    """
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


@patch("lambda_code.issuing_ca_crl.issuing_ca_crl.db_get_certificate")
@patch("lambda_code.issuing_ca_crl.issuing_ca_crl.s3_download")
def test_list_revoked_certs_from_s3_skips_unknown_serial_among_valid_entries(mock_s3_download, mock_db_get_cert):
    """
    When revoked.json has a mix of a valid entry and an entry whose serial number
    is absent from the database, only the unknown entry should be skipped; the
    function must not raise and the unknown entry must not appear in the returned
    revoked list.
    """
    revoked_json = [
        {"common_name": "unknown.example.com", "serial_number": "000000000000"},
    ]

    mock_s3_download.side_effect = lambda *a, **kw: _make_s3_response(revoked_json)
    mock_db_get_cert.return_value = None

    revoked_certs, newly_revoked_details = list_revoked_certs_from_s3(
        "test-project", "dev", "external-bucket", "internal-bucket"
    )

    assert not revoked_certs
    assert not newly_revoked_details


# ---------------------------------------------------------------------------
# Tests for db_get_certificate
# ---------------------------------------------------------------------------


@patch("utils.certs.db.boto3")
def test_db_get_certificate_returns_none_when_serial_not_found(mock_boto3):
    """
    db_get_certificate should return None when the requested serial number is
    not present in the DynamoDB items for the given common name, rather than
    raising an IndexError.
    """
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
    """
    db_get_certificate should return None when DynamoDB holds no items at all
    for the given common name.
    """
    mock_client = MagicMock()
    mock_boto3.client.return_value = mock_client
    mock_client.query.return_value = {"Items": []}

    result = db_get_certificate("test-project", "dev", "nonexistent.example.com", "999999999999")

    assert result is None
