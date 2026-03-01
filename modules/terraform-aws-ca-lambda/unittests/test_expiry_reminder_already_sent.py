from utils.certs.db import db_expiry_reminder_already_sent
from unittest.mock import patch
from datetime import datetime


@patch("utils.certs.db.datetime")
def test_expiry_reminder_already_sent_today(mock_datetime):
    """Test returns True when a reminder was already sent today"""
    mock_datetime.now.return_value = datetime(2026, 3, 1, 14, 0, 0)

    certificate = {
        "CommonName": {"S": "test.example.com"},
        "SerialNumber": {"S": "123456"},
        "ExpiryReminders": {"L": [{"S": "2026-03-01 08:30:00"}]},
    }

    assert db_expiry_reminder_already_sent(certificate) is True


@patch("utils.certs.db.datetime")
def test_expiry_reminder_not_sent_today(mock_datetime):
    """Test returns False when reminder was sent on a different day"""
    mock_datetime.now.return_value = datetime(2026, 3, 1, 14, 0, 0)

    certificate = {
        "CommonName": {"S": "test.example.com"},
        "SerialNumber": {"S": "123456"},
        "ExpiryReminders": {"L": [{"S": "2026-02-28 08:30:00"}]},
    }

    assert db_expiry_reminder_already_sent(certificate) is False


@patch("utils.certs.db.datetime")
def test_expiry_reminder_no_reminders_attribute(mock_datetime):
    """Test returns False when ExpiryReminders attribute does not exist"""
    mock_datetime.now.return_value = datetime(2026, 3, 1, 14, 0, 0)

    certificate = {
        "CommonName": {"S": "test.example.com"},
        "SerialNumber": {"S": "123456"},
    }

    assert db_expiry_reminder_already_sent(certificate) is False


@patch("utils.certs.db.datetime")
def test_expiry_reminder_empty_list(mock_datetime):
    """Test returns False when ExpiryReminders list is empty"""
    mock_datetime.now.return_value = datetime(2026, 3, 1, 14, 0, 0)

    certificate = {
        "CommonName": {"S": "test.example.com"},
        "SerialNumber": {"S": "123456"},
        "ExpiryReminders": {"L": []},
    }

    assert db_expiry_reminder_already_sent(certificate) is False


@patch("utils.certs.db.datetime")
def test_expiry_reminder_multiple_reminders_today_present(mock_datetime):
    """Test returns True when multiple reminders exist and one matches today"""
    mock_datetime.now.return_value = datetime(2026, 3, 1, 14, 0, 0)

    certificate = {
        "CommonName": {"S": "test.example.com"},
        "SerialNumber": {"S": "123456"},
        "ExpiryReminders": {
            "L": [
                {"S": "2026-02-14 08:30:00"},
                {"S": "2026-02-28 09:00:00"},
                {"S": "2026-03-01 07:00:00"},
            ]
        },
    }

    assert db_expiry_reminder_already_sent(certificate) is True


@patch("utils.certs.db.datetime")
def test_expiry_reminder_multiple_reminders_today_absent(mock_datetime):
    """Test returns False when multiple reminders exist but none match today"""
    mock_datetime.now.return_value = datetime(2026, 3, 1, 14, 0, 0)

    certificate = {
        "CommonName": {"S": "test.example.com"},
        "SerialNumber": {"S": "123456"},
        "ExpiryReminders": {
            "L": [
                {"S": "2026-02-14 08:30:00"},
                {"S": "2026-02-28 09:00:00"},
            ]
        },
    }

    assert db_expiry_reminder_already_sent(certificate) is False
