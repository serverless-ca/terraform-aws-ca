from cryptography.hazmat.primitives import serialization
from utils.aws.sns import publish_to_sns
from utils.certs.db import (
    db_list_certificates,
    db_expiry_reminder_already_sent,
    db_record_expiry_reminder,
)
from utils.certs.s3 import s3_download
from cryptography.x509 import load_pem_x509_certificate, load_pem_x509_csr
import base64
import json
import os
from datetime import datetime


def _get_subject_from_csr_match(certificates, csr_public_key_pem, common_name):
    """Find the subject of the certificate matching the CSR public key"""
    for certificate in certificates:
        b64_encoded_certificate = certificate["Certificate"]["B"]
        cert = load_pem_x509_certificate(base64.b64decode(b64_encoded_certificate))
        cert_public_key_pem = (
            cert.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )

        if cert_public_key_pem == csr_public_key_pem:
            subject = cert.subject.rfc4514_string()
            print(f"Found CSR-matching certificate for {common_name} with subject {subject}")
            return subject

    return None


def get_latest_certificate(project, env_name, common_name, csr_public_key_pem):
    """Find the certificate with the latest expiry matching the common name and subject.

    First locates the certificate matching the CSR public key to determine the subject,
    then searches all certificates with the same common name and subject to find the one
    with the latest expiry date.
    """

    certificates = db_list_certificates(project, env_name, common_name)

    if not certificates:
        print(f"No certificates found for {common_name}")
        return None

    subject = _get_subject_from_csr_match(certificates, csr_public_key_pem, common_name)
    if subject is None:
        print(f"No matching certificate found for {common_name} with the provided CSR public key")
        return None

    # find the certificate with the latest expiry date matching common name and subject
    latest_certificate = None
    latest_expiry = None

    for certificate in certificates:
        b64_encoded_certificate = certificate["Certificate"]["B"]
        cert = load_pem_x509_certificate(base64.b64decode(b64_encoded_certificate))

        if cert.subject.rfc4514_string() != subject:
            continue

        expiry_date = datetime.strptime(certificate["Expires"]["S"], "%Y-%m-%d %H:%M:%S")

        if latest_expiry is None or expiry_date > latest_expiry:
            latest_expiry = expiry_date
            latest_certificate = certificate

    serial_number = latest_certificate["SerialNumber"]["S"]
    expiry = latest_certificate["Expires"]["S"]
    print(f"Latest certificate for {common_name} (serial {serial_number}) expires {expiry}")

    return latest_certificate


def build_cert_expiry_details(certificate, common_name, days_remaining):
    """Build SNS message details for certificate expiry warning"""
    b64_encoded_certificate = certificate["Certificate"]["B"]
    cert = load_pem_x509_certificate(base64.b64decode(b64_encoded_certificate))

    return {
        "CertificateInfo": {
            "CommonName": common_name,
            "SerialNumber": certificate["SerialNumber"]["S"],
            "Issued": certificate["Issued"]["S"],
            "Expires": certificate["Expires"]["S"],
        },
        "Base64Certificate": (
            b64_encoded_certificate.decode("utf-8")
            if isinstance(b64_encoded_certificate, bytes)
            else b64_encoded_certificate
        ),
        "Subject": cert.subject.rfc4514_string(),
        "DaysRemaining": days_remaining,
    }


def sns_notify_cert_expiry(cert_details, sns_topic_arn):
    keys_to_publish = ["CertificateInfo", "Base64Certificate", "Subject", "DaysRemaining"]
    response = publish_to_sns(cert_details, "Certificate Expiry Warning", sns_topic_arn, keys_to_publish)

    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    common_name = cert_details["CertificateInfo"]["CommonName"]
    print(f"Expiry warning for {common_name} published to SNS")


def process_gitops_certificate(project, env_name, external_s3_bucket_name, internal_s3_bucket_name, gitops_cert):
    """Download CSR from S3 and return the latest matching certificate, or None"""
    common_name = gitops_cert["common_name"]
    csr_file = gitops_cert["csr_file"]

    csr_response = s3_download(external_s3_bucket_name, internal_s3_bucket_name, f"csrs/{csr_file}")
    if csr_response is None:
        print(f"CSR file csrs/{csr_file} not found, skipping {common_name}")
        return None

    csr = load_pem_x509_csr(csr_response["Body"].read())

    csr_public_key_pem = (
        csr.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )

    return get_latest_certificate(project, env_name, common_name, csr_public_key_pem)


def _process_certificate_expiry(certificate, common_name, expiry_reminders, sns_topic_arn, now):
    """Evaluate whether an expiry reminder should be sent for a certificate"""
    expiry_date = datetime.strptime(certificate["Expires"]["S"], "%Y-%m-%d %H:%M:%S")
    days_remaining = (expiry_date - now).days

    if days_remaining not in expiry_reminders:
        print(f"{common_name} expires in {days_remaining} days, no reminder needed")
        return None

    if db_expiry_reminder_already_sent(certificate):
        print(f"Expiry reminder already sent for {common_name} at {days_remaining} days")
        return None

    cert_details = build_cert_expiry_details(certificate, common_name, days_remaining)
    sns_notify_cert_expiry(cert_details, sns_topic_arn)

    return days_remaining


def lambda_handler(event, context):  # pylint:disable=unused-argument
    project = os.environ["PROJECT"]
    env_name = os.environ["ENVIRONMENT_NAME"]
    external_s3_bucket_name = os.environ["EXTERNAL_S3_BUCKET"]
    internal_s3_bucket_name = os.environ["INTERNAL_S3_BUCKET"]
    sns_topic_arn = os.environ["SNS_TOPIC_ARN"]
    expiry_reminders = json.loads(os.environ["EXPIRY_REMINDERS"])

    response = s3_download(external_s3_bucket_name, internal_s3_bucket_name, "tls.json")
    gitops_certificates = json.loads(response["Body"].read().decode("utf-8"))

    now = datetime.now()

    for gitops_cert in gitops_certificates:
        certificate = process_gitops_certificate(
            project, env_name, external_s3_bucket_name, internal_s3_bucket_name, gitops_cert
        )
        if certificate is None:
            continue

        common_name = gitops_cert["common_name"]
        days_remaining = _process_certificate_expiry(certificate, common_name, expiry_reminders, sns_topic_arn, now)

        if days_remaining is not None:
            db_record_expiry_reminder(
                project, env_name, common_name, certificate["SerialNumber"]["S"], days_remaining
            )
