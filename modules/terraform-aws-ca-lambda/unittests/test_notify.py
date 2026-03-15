import os

os.environ.setdefault("SLACK_SECRET_ARN", "arn:aws:secretsmanager:eu-west-1:123456789012:secret:test")
os.environ.setdefault("SLACK_CHANNELS", "test-channel")
os.environ.setdefault("SLACK_BAD_EMOJI", ":octagonal_sign:")
os.environ.setdefault("SLACK_GOOD_EMOJI", ":white_check_mark:")
os.environ.setdefault("SLACK_USERNAME", "Serverless CA")
os.environ.setdefault("SLACK_WARNING_EMOJI", ":warning:")
os.environ.setdefault("PROJECT", "serverless")

# Environment variables must be set before importing notify module
from lambda_code.notify.notify import (  # pylint: disable=wrong-import-position
    build_divider_block,
    build_fields_block,
    build_header_block,
    build_section_block,
    cert_expired_message,
    cert_expiry_warning_message,
    cert_issued_message,
    cert_request_rejected_message,
    cert_revoked_message,
    classify_and_build_message,
    format_cert_info_fields,
    _classify_by_payload,
)

# --- Sample payloads based on docs/notifications.md ---

CERT_EXPIRED_PAYLOAD = {
    "CertificateInfo": {
        "CommonName": "test-expiry.example.com",
        "SerialNumber": "430630438465918376136249210634111108993623737029",
        "Issued": "2026-03-01 20:28:22",
        "Expires": "2026-03-02 20:33:22",
    },
    "Base64Certificate": "LS0tLS1CRUd...",
    "Subject": "CN=test-expiry.example.com",
    "DaysRemaining": 0,
}

CERT_EXPIRY_WARNING_PAYLOAD = {
    "CertificateInfo": {
        "CommonName": "pipeline-test-expiry-reminder",
        "SerialNumber": "430630438465918376136249210634111108993623737029",
        "Issued": "2026-03-01 20:28:22",
        "Expires": "2026-03-03 20:33:22",
    },
    "Base64Certificate": "LS0tLS1CRUd...",
    "Subject": "CN=pipeline-test-expiry-reminder",
    "DaysRemaining": 1,
}

CERT_ISSUED_PAYLOAD = {
    "CertificateInfo": {
        "CommonName": "pipeline-test-csr-s3-upload",
        "SerialNumber": "725732270238932467356021650679497159468001185756",
        "Issued": "2026-02-08 08:11:41",
        "Expires": "2026-02-09 08:16:41",
    },
    "Base64Certificate": "LS0tLS1CRUd...",
    "Subject": "ST=New York,OU=DevOps,O=Org,L=New York,C=US,CN=pipeline-test-csr-s3-upload",
}

CERT_REQUEST_REJECTED_PAYLOAD = {
    "CSRInfo": {
        "CommonName": "test-client-cert",
        "Lifetime": 1,
        "Purposes": ["client_auth"],
        "SANs": [],
    },
    "Base64CSR": "LS0tLS1CRUd...",
    "Subject": "ST=England,OU=Security Operations,O=Serverless Inc,L=London,C=GB,CN=Cloud Architect",
    "Reason": "Private key has already been used for a certificate",
}

CERT_REQUEST_REJECTED_WITH_SANS_PAYLOAD = {
    "CSRInfo": {
        "CommonName": "test.example.com",
        "Lifetime": 1,
        "Purposes": ["server_auth"],
        "SANs": [{"type": "DNS_NAME", "value": "test.example.com"}],
    },
    "Base64CSR": "LS0tLS1CRUd...",
    "Subject": "CN=test.example.com",
    "Reason": "Private key has already been used for a certificate",
}

CERT_REVOKED_PAYLOAD = {
    "CommonName": "pipeline-test-csr-s3-upload",
    "SerialNumber": "253508645453578743400361452260705386159413554723",
    "Revoked": "2026-02-03 21:34:04.753865",
    "Subject": "ST=New York,OU=DevOps,O=Org,L=New York,C=US,CN=pipeline-test-csr-s3-upload",
}


# --- Block builder tests ---


def test_build_section_block():
    block = build_section_block("hello")
    assert block == {"type": "section", "text": {"type": "mrkdwn", "text": "hello"}}


def test_build_header_block():
    block = build_header_block("My Header")
    assert block["type"] == "header"
    assert block["text"]["type"] == "plain_text"
    assert block["text"]["text"] == "My Header"
    assert block["text"]["emoji"] is True


def test_build_divider_block():
    assert build_divider_block() == {"type": "divider"}


def test_build_fields_block():
    block = build_fields_block(["*A:*\nval1", "*B:*\nval2"])
    assert block["type"] == "section"
    assert len(block["fields"]) == 2
    assert block["fields"][0] == {"type": "mrkdwn", "text": "*A:*\nval1"}


# --- format_cert_info_fields tests ---


def test_format_cert_info_fields_all_keys():
    cert_info = {
        "CommonName": "test.example.com",
        "SerialNumber": "12345",
        "Issued": "2026-01-01 00:00:00",
        "Expires": "2026-12-31 23:59:59",
    }
    fields = format_cert_info_fields(cert_info)
    assert len(fields) == 4
    assert "*Common Name:*\ntest.example.com" in fields
    assert "*Serial Number:*\n`12345`" in fields
    assert "*Issued:*\n2026-01-01 00:00:00" in fields
    assert "*Expires:*\n2026-12-31 23:59:59" in fields


def test_format_cert_info_fields_custom_expires_label():
    cert_info = {"Expires": "2026-01-01 00:00:00"}
    fields = format_cert_info_fields(cert_info, expires_label="Expired")
    assert fields == ["*Expired:*\n2026-01-01 00:00:00"]


def test_format_cert_info_fields_partial_keys():
    cert_info = {"CommonName": "test.example.com"}
    fields = format_cert_info_fields(cert_info)
    assert len(fields) == 1
    assert "*Common Name:*\ntest.example.com" in fields


def test_format_cert_info_fields_empty():
    assert not format_cert_info_fields({})


# --- cert_expired_message tests ---


def test_cert_expired_message():
    blocks = cert_expired_message(CERT_EXPIRED_PAYLOAD)
    assert blocks is not None
    assert blocks[0]["type"] == "header"
    assert "Certificate Expired" in blocks[0]["text"]["text"]


def test_cert_expired_message_uses_expired_label():
    blocks = cert_expired_message(CERT_EXPIRED_PAYLOAD)
    fields_block = [b for b in blocks if b["type"] == "section" and "fields" in b][0]
    expires_field = [f["text"] for f in fields_block["fields"] if "Expired" in f["text"]]
    assert len(expires_field) == 1
    assert "*Expired:*" in expires_field[0]


def test_cert_expired_message_no_days_remaining_line():
    blocks = cert_expired_message(CERT_EXPIRED_PAYLOAD)
    text_blocks = [b for b in blocks if b["type"] == "section" and "text" in b and isinstance(b["text"], dict)]
    days_blocks = [b for b in text_blocks if "Days Remaining" in b["text"]["text"]]
    assert len(days_blocks) == 0


def test_cert_expired_message_includes_subject():
    blocks = cert_expired_message(CERT_EXPIRED_PAYLOAD)
    subject_blocks = [
        b
        for b in blocks
        if b["type"] == "section" and "text" in b and isinstance(b["text"], dict) and "Subject" in b["text"]["text"]
    ]
    assert len(subject_blocks) == 1


def test_cert_expired_message_missing_keys():
    assert cert_expired_message({"CertificateInfo": {}}) is None
    assert cert_expired_message({}) is None


# --- cert_expiry_warning_message tests ---


def test_cert_expiry_warning_message():
    blocks = cert_expiry_warning_message(CERT_EXPIRY_WARNING_PAYLOAD)
    assert blocks is not None
    assert "Certificate Expiry Warning" in blocks[0]["text"]["text"]


def test_cert_expiry_warning_message_includes_days_remaining():
    blocks = cert_expiry_warning_message(CERT_EXPIRY_WARNING_PAYLOAD)
    text_blocks = [b for b in blocks if b["type"] == "section" and "text" in b and isinstance(b["text"], dict)]
    days_blocks = [b for b in text_blocks if "Days Remaining" in b["text"]["text"]]
    assert len(days_blocks) == 1
    assert "1" in days_blocks[0]["text"]["text"]


def test_cert_expiry_warning_message_uses_expires_label():
    blocks = cert_expiry_warning_message(CERT_EXPIRY_WARNING_PAYLOAD)
    fields_block = [b for b in blocks if b["type"] == "section" and "fields" in b][0]
    expires_field = [f["text"] for f in fields_block["fields"] if "Expires" in f["text"]]
    assert len(expires_field) == 1


def test_cert_expiry_warning_returns_none_for_zero_days():
    payload = {**CERT_EXPIRY_WARNING_PAYLOAD, "DaysRemaining": 0}
    assert cert_expiry_warning_message(payload) is None


def test_cert_expiry_warning_returns_none_for_negative_days():
    payload = {**CERT_EXPIRY_WARNING_PAYLOAD, "DaysRemaining": -1}
    assert cert_expiry_warning_message(payload) is None


def test_cert_expiry_warning_missing_keys():
    assert cert_expiry_warning_message({}) is None


# --- cert_issued_message tests ---


def test_cert_issued_message():
    blocks = cert_issued_message(CERT_ISSUED_PAYLOAD)
    assert blocks is not None
    assert "Certificate Issued" in blocks[0]["text"]["text"]


def test_cert_issued_message_includes_subject():
    blocks = cert_issued_message(CERT_ISSUED_PAYLOAD)
    subject_blocks = [
        b
        for b in blocks
        if b["type"] == "section" and "text" in b and isinstance(b["text"], dict) and "Subject" in b["text"]["text"]
    ]
    assert len(subject_blocks) == 1


def test_cert_issued_message_returns_none_if_days_remaining_present():
    payload = {**CERT_ISSUED_PAYLOAD, "DaysRemaining": 5}
    assert cert_issued_message(payload) is None


def test_cert_issued_message_missing_keys():
    assert cert_issued_message({}) is None


# --- cert_request_rejected_message tests ---


def test_cert_request_rejected_message():
    blocks = cert_request_rejected_message(CERT_REQUEST_REJECTED_PAYLOAD)
    assert blocks is not None
    assert "Certificate Request Rejected" in blocks[0]["text"]["text"]


def test_cert_request_rejected_message_includes_reason():
    blocks = cert_request_rejected_message(CERT_REQUEST_REJECTED_PAYLOAD)
    text_blocks = [b for b in blocks if b["type"] == "section" and "text" in b and isinstance(b["text"], dict)]
    reason_blocks = [b for b in text_blocks if "Reason" in b["text"]["text"]]
    assert len(reason_blocks) == 1
    assert "Private key has already been used" in reason_blocks[0]["text"]["text"]


def test_cert_request_rejected_message_with_sans_dicts():
    blocks = cert_request_rejected_message(CERT_REQUEST_REJECTED_WITH_SANS_PAYLOAD)
    assert blocks is not None
    fields_block = [b for b in blocks if b["type"] == "section" and "fields" in b][0]
    sans_field = [f["text"] for f in fields_block["fields"] if "SANs" in f["text"]]
    assert len(sans_field) == 1
    assert "test.example.com" in sans_field[0]


def test_cert_request_rejected_message_empty_sans_omitted():
    blocks = cert_request_rejected_message(CERT_REQUEST_REJECTED_PAYLOAD)
    fields_block = [b for b in blocks if b["type"] == "section" and "fields" in b][0]
    sans_fields = [f["text"] for f in fields_block["fields"] if "SANs" in f["text"]]
    assert len(sans_fields) == 0


def test_cert_request_rejected_missing_keys():
    assert cert_request_rejected_message({}) is None
    assert cert_request_rejected_message({"CSRInfo": {}}) is None


# --- cert_revoked_message tests ---


def test_cert_revoked_message():
    blocks = cert_revoked_message(CERT_REVOKED_PAYLOAD)
    assert blocks is not None
    assert "Certificate Revoked" in blocks[0]["text"]["text"]


def test_cert_revoked_message_truncates_microseconds():
    blocks = cert_revoked_message(CERT_REVOKED_PAYLOAD)
    fields_block = [b for b in blocks if b["type"] == "section" and "fields" in b][0]
    revoked_field = [f["text"] for f in fields_block["fields"] if "Revoked" in f["text"]]
    assert len(revoked_field) == 1
    assert "2026-02-03 21:34:04" in revoked_field[0]
    assert ".753865" not in revoked_field[0]


def test_cert_revoked_message_includes_subject():
    blocks = cert_revoked_message(CERT_REVOKED_PAYLOAD)
    subject_blocks = [
        b
        for b in blocks
        if b["type"] == "section" and "text" in b and isinstance(b["text"], dict) and "Subject" in b["text"]["text"]
    ]
    assert len(subject_blocks) == 1


def test_cert_revoked_missing_keys():
    assert cert_revoked_message({}) is None
    assert cert_revoked_message({"CommonName": "test"}) is None


# --- _classify_by_payload tests ---


def test_classify_by_payload_rejected():
    handler, emoji = _classify_by_payload(CERT_REQUEST_REJECTED_PAYLOAD)
    assert handler is cert_request_rejected_message
    assert emoji == ":octagonal_sign:"


def test_classify_by_payload_revoked():
    handler, emoji = _classify_by_payload(CERT_REVOKED_PAYLOAD)
    assert handler is cert_revoked_message
    assert emoji == ":octagonal_sign:"


def test_classify_by_payload_expired():
    handler, emoji = _classify_by_payload(CERT_EXPIRED_PAYLOAD)
    assert handler is cert_expired_message
    assert emoji == ":octagonal_sign:"


def test_classify_by_payload_expiry_warning():
    handler, emoji = _classify_by_payload(CERT_EXPIRY_WARNING_PAYLOAD)
    assert handler is cert_expiry_warning_message
    assert emoji == ":warning:"


def test_classify_by_payload_issued():
    handler, emoji = _classify_by_payload(CERT_ISSUED_PAYLOAD)
    assert handler is cert_issued_message
    assert emoji == ":white_check_mark:"


def test_classify_by_payload_unknown():
    handler, emoji = _classify_by_payload({"Unknown": "data"})
    assert handler is None
    assert emoji is None


# --- classify_and_build_message tests ---


def test_classify_by_subject_revoked():
    text, blocks = classify_and_build_message("Certificate Revoked", CERT_REVOKED_PAYLOAD)
    assert ":octagonal_sign:" in text
    assert blocks is not None
    assert "Certificate Revoked" in blocks[0]["text"]["text"]


def test_classify_by_subject_rejected():
    text, blocks = classify_and_build_message("Certificate Request Rejected", CERT_REQUEST_REJECTED_PAYLOAD)
    assert ":octagonal_sign:" in text
    assert "Certificate Request Rejected" in blocks[0]["text"]["text"]


def test_classify_by_subject_expired():
    text, blocks = classify_and_build_message("Certificate Expired", CERT_EXPIRED_PAYLOAD)
    assert ":octagonal_sign:" in text
    assert "Certificate Expired" in blocks[0]["text"]["text"]


def test_classify_by_subject_expiry():
    text, blocks = classify_and_build_message("Certificate Expiry Warning", CERT_EXPIRY_WARNING_PAYLOAD)
    assert ":warning:" in text
    assert "Certificate Expiry Warning" in blocks[0]["text"]["text"]


def test_classify_by_subject_expiring():
    text, _blocks = classify_and_build_message("Certificate Expiring Soon", CERT_EXPIRY_WARNING_PAYLOAD)
    assert ":warning:" in text


def test_classify_by_subject_issued():
    text, blocks = classify_and_build_message("Certificate Issued", CERT_ISSUED_PAYLOAD)
    assert ":white_check_mark:" in text
    assert "Certificate Issued" in blocks[0]["text"]["text"]


def test_classify_by_subject_case_insensitive():
    _text, blocks = classify_and_build_message("CERTIFICATE REVOKED", CERT_REVOKED_PAYLOAD)
    assert blocks is not None


def test_classify_falls_back_to_payload():
    _text, blocks = classify_and_build_message("Some unknown subject", CERT_REVOKED_PAYLOAD)
    assert blocks is not None
    assert "Certificate Revoked" in blocks[0]["text"]["text"]


def test_classify_unrecognised_returns_none():
    text, blocks = classify_and_build_message("Unknown", {"foo": "bar"})
    assert text is None
    assert blocks is None
