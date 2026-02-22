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

    # find the certificate matching the CSR public key to determine the subject
    subject = None
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
            break

    if subject is None:
        print(f"No matching certificate found for {common_name} with the provided CSR public key")
        return None

    # find the certificate with the latest expiry date matching common name and subject
    latest_certificate = None
    latest_expiry = None

    for certificate in certificates:
        b64_encoded_certificate = certificate["Certificate"]["B"]
        cert = load_pem_x509_certificate(base64.b64decode(b64_encoded_certificate))
        cert_subject = cert.subject.rfc4514_string()

        if cert_subject != subject:
            continue

        expiry = certificate["Expires"]["S"]
        expiry_date = datetime.strptime(expiry, "%Y-%m-%d %H:%M:%S")

        if latest_expiry is None or expiry_date > latest_expiry:
            latest_expiry = expiry_date
            latest_certificate = certificate

    serial_number = latest_certificate["SerialNumber"]["S"]
    expiry = latest_certificate["Expires"]["S"]
    print(f"Latest certificate for {common_name} (serial {serial_number}) expires {expiry}")

    return latest_certificate


def sns_notify_cert_expiry(cert_details, sns_topic_arn):
    keys_to_publish = ["CertificateInfo", "Base64Certificate", "Subject", "DaysRemaining"]
    response = publish_to_sns(cert_details, "Certificate Expiry Warning", sns_topic_arn, keys_to_publish)

    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    common_name = cert_details["CertificateInfo"]["CommonName"]
    print(f"Expiry warning for {common_name} published to SNS")


def lambda_handler(event, context):  # pylint:disable=unused-argument,too-many-locals
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
        common_name = gitops_cert["common_name"]
        csr_file = gitops_cert["csr_file"]

        # download CSR from S3
        csr_response = s3_download(external_s3_bucket_name, internal_s3_bucket_name, f"csrs/{csr_file}")
        if csr_response is None:
            print(f"CSR file csrs/{csr_file} not found, skipping {common_name}")
            continue

        csr_file_contents = csr_response["Body"].read()
        csr = load_pem_x509_csr(csr_file_contents)

        # extract public key from CSR
        csr_public_key_pem = (
            csr.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )

        # look up latest certificate with matching common name and subject
        certificate = get_latest_certificate(project, env_name, common_name, csr_public_key_pem)
        if certificate is None:
            continue

        expiry = certificate["Expires"]["S"]
        expiry_date = datetime.strptime(expiry, "%Y-%m-%d %H:%M:%S")
        days_remaining = (expiry_date - now).days

        if days_remaining not in expiry_reminders:
            print(f"{common_name} expires in {days_remaining} days, no reminder needed")
            continue

        # check if a reminder has already been sent for this number of days remaining
        if db_expiry_reminder_already_sent(certificate, days_remaining):
            print(f"Expiry reminder already sent for {common_name} at {days_remaining} days")
            continue

        # build SNS message
        serial_number = certificate["SerialNumber"]["S"]
        issued = certificate["Issued"]["S"]
        b64_encoded_certificate = certificate["Certificate"]["B"]
        cert = load_pem_x509_certificate(base64.b64decode(b64_encoded_certificate))

        cert_details = {
            "CertificateInfo": {
                "CommonName": common_name,
                "SerialNumber": serial_number,
                "Issued": issued,
                "Expires": expiry,
            },
            "Base64Certificate": (
                b64_encoded_certificate.decode("utf-8")
                if isinstance(b64_encoded_certificate, bytes)
                else b64_encoded_certificate
            ),
            "Subject": cert.subject.rfc4514_string(),
            "DaysRemaining": days_remaining,
        }

        sns_notify_cert_expiry(cert_details, sns_topic_arn)

        # record that a reminder was sent
        db_record_expiry_reminder(project, env_name, common_name, serial_number, days_remaining)

    return
