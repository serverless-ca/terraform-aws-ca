import boto3
import os
from datetime import datetime

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


def db_issue_certificate(common_name, days_before_expiry=30):
    """Determines whether certificate should be issued"""

    certificates = db_list_certificates(common_name)

    # if there are no certificates with that name, issue a certificate
    if not certificates:
        return True

    # check each certificate to see if it is revoked, or within x days of expiry
    number_of_certs = 0
    for certificate in certificates:
        serial_number = certificate["SerialNumber"]["S"]
        expires = datetime.strptime(certificate["Expires"]["S"], "%Y-%m-%d %H:%M:%S")
        now = datetime.utcnow()
        delta = expires - now
        delta_days = delta.days
        if delta_days < days_before_expiry:
            print(f"{common_name} certificate {serial_number} due to expire in {delta_days} days")

        elif certificate.get("Revoked"):
            print(f"{common_name} certificate {serial_number} has been revoked")

        else:
            print(f"{common_name} certificate {serial_number} exists valid for over {days_before_expiry} days")
            number_of_certs = number_of_certs + 1

    # if there's an existing cert valid for over x days, don't issue a new one
    if number_of_certs:
        return False

    # if all certs are due to expire within x days, issue a new one
    print(f"all {common_name} certificates revoked or due to expire in less than {days_before_expiry} days")
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
