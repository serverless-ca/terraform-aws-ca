import boto3
import os
import base64
from datetime import datetime
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization

project = os.environ["PROJECT"]
env_name = os.environ["ENVIRONMENT_NAME"]
base_table_name = "CA"


def db_get_table_name():
    # constructs the DynamoDB table name, e.g. SecureEmailCADev

    capitalised_project = project.replace("-", " ").title().replace(" ", "")
    capitalised_env_name = env_name.title()
    table_name = f"{capitalised_project}{base_table_name}{capitalised_env_name}"

    return table_name


def db_list_certificates(common_name):
    # returns list of certificates for a specified common_name
    client = boto3.client("dynamodb")

    print(f"querying DynamoDB table {db_get_table_name()} for {common_name}")

    response = client.query(
        TableName=db_get_table_name(),
        KeyConditionExpression="CommonName = :CommonName",
        ExpressionAttributeValues={":CommonName": {"S": common_name}},
    )

    return response["Items"]


def db_issue_certificate(common_name, request_public_key_pem):
    """Determines whether certificate should be issued"""

    certificates = db_list_certificates(common_name)

    # if there are no certificates with that name, issue a certificate
    if not certificates:
        return True

    # if this is a request with a private key that's been used before, reject the request
    for certificate in certificates:
        serial_number = certificate["SerialNumber"]["S"]
        b64_encoded_certificate = certificate["Certificate"]["B"]
        cert = load_pem_x509_certificate(base64.b64decode(b64_encoded_certificate))
        public_key = cert.public_key()

        # Convert public key to PEM format
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        if public_key_pem == request_public_key_pem:
            print(f"Private key has been used before for {common_name} certificate serial number {serial_number}")
            print("Certificate request rejected, submit request using new private key")
            return False

    # private key hasn't been used before, approve certificate request
    return True


def db_ca_cert_issued(cert_info, certificate, encrypted_private_key=None):
    # creates a new item in DynamoDB when a CA certificate is issued

    common_name = cert_info["CommonName"]
    issued = cert_info["Issued"]
    expires = cert_info["Expires"]
    serial_number = cert_info["SerialNumber"]

    client = boto3.client("dynamodb")
    print(f"adding {common_name} certificate details to DynamoDB table {db_get_table_name()}")
    if encrypted_private_key is None:
        client.put_item(
            TableName=db_get_table_name(),
            Item={
                "SerialNumber": {"S": serial_number},
                "CommonName": {"S": common_name},
                "Issued": {"S": issued},
                "Expires": {"S": expires},
                "Certificate": {"B": certificate},
                "CRLNumber": {"N": "0"},
            },
        )

        return

    client.put_item(
        TableName=db_get_table_name(),
        Item={
            "SerialNumber": {"S": serial_number},
            "CommonName": {"S": common_name},
            "Issued": {"S": issued},
            "Expires": {"S": expires},
            "Certificate": {"B": certificate},
            "EncryptedPrivateKey": {"B": encrypted_private_key},
            "CRLNumber": {"N": "0"},
        },
    )


def db_tls_cert_issued(cert_info, certificate):
    """creates a new item in DynamoDB when a TLS certificate is issued"""
    # if a passphrase is used, private key must be encrypted

    common_name = cert_info["CommonName"]
    issued = cert_info["Issued"]
    expires = cert_info["Expires"]
    serial_number = cert_info["SerialNumber"]

    client = boto3.client("dynamodb")
    print(f"adding {common_name} certificate details to DynamoDB table {db_get_table_name()}")

    client.put_item(
        TableName=db_get_table_name(),
        Item={
            "SerialNumber": {"S": serial_number},
            "CommonName": {"S": common_name},
            "Issued": {"S": issued},
            "Expires": {"S": expires},
            "Certificate": {"B": certificate},
        },
    )


def db_update_crl_number(common_name, serial_number):
    """increments CRL number by 1 and returns new value as integer"""

    client = boto3.client("dynamodb")

    print(f"updating {common_name} CRL number in DynamoDB")

    response = client.update_item(
        TableName=db_get_table_name(),
        ExpressionAttributeNames={"#N": "CRLNumber"},
        UpdateExpression="SET #N = #N + :n",
        ExpressionAttributeValues={":n": {"N": "1"}},
        Key={"CommonName": {"S": common_name}, "SerialNumber": {"S": serial_number}},
        ReturnValues="UPDATED_NEW",
    )

    return int(response["Attributes"]["CRLNumber"]["N"])


def db_get_certificate(common_name, serial_number):
    """returns certificate with specified serial_number"""
    client = boto3.client("dynamodb")

    print(f"querying DynamoDB table {db_get_table_name()} for {serial_number}")

    response = client.query(
        TableName=db_get_table_name(),
        KeyConditionExpression="CommonName = :CommonName",
        ExpressionAttributeValues={":CommonName": {"S": common_name}},
    )
    items = response["Items"]

    return [i for i in items if i["SerialNumber"]["S"] == serial_number][0]


def db_revocation_date(common_name, serial_number):
    """adds revocation date to existing item in DynamoDB, or returns date already revoked"""
    client = boto3.client("dynamodb")

    certificate = db_get_certificate(common_name, serial_number)

    # if certificate is already revoked, return revocation date
    if certificate.get("Revoked"):
        return datetime.strptime(certificate["Revoked"]["S"], "%Y-%m-%d %H:%M:%S")

    # if certificate hasn't already been revoked, return today's date
    now = datetime.now()
    revoked = now.strftime("%Y-%m-%d %H:%M:%S")

    print(f"revoking certificate {common_name} serial number {serial_number}")

    # write today's date to DynamoDB to record revocation
    client.update_item(
        TableName=db_get_table_name(),
        Key={
            "CommonName": {"S": common_name},
            "SerialNumber": {"S": serial_number},
        },
        UpdateExpression="set Revoked=:r",
        ExpressionAttributeValues={":r": {"S": revoked}},
        ConditionExpression="attribute_not_exists(Revoked)",
    )

    return now
