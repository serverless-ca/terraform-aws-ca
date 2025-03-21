#!/usr/bin/env python3
import os
import sys
import json
import base64
import argparse
import boto3
from cryptography.hazmat.primitives.serialization import load_der_private_key
from modules.certs.crypto import create_csr_info, crypto_encode_private_key, crypto_tls_cert_signing_request
from modules.certs.kms import kms_generate_key_pair, kms_get_kms_key_id
from modules.aws.lambdas import get_lambda_name

# identify home directory and create certs subdirectory if needed
homedir = os.path.expanduser("~")
base_path = f"{homedir}/certs"
if not os.path.exists(base_path):
    print(f"Creating directory {base_path}")
    os.makedirs(base_path)


def create_session(profile):
    """
    Creates and returns AWS session using profile
    """

    try:
        if profile is not None:
            session = boto3.session.Session(profile_name=profile)
        else:
            session = boto3.session.Session()
    except Exception as e:
        session = {"error": e}
    if isinstance(session, dict):
        print(f"Error: Unable to open session using profile {profile}. {session['error']}")
        sys.exit(1)
    else:
        print(f"AWS session opened using profile: {profile}")
    return session


def parse_arguments():
    """
    Read arguments and return arguments dictonary
    """

    arguments = {}
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default=None, help="AWS profile described in .aws/config file")
    parser.add_argument("--verbose", action="store_true", help="Output of all generated payload data")
    arguments = vars(parser.parse_args())

    return arguments


def main():  # pylint:disable=too-many-locals,too-many-statements
    """
    Create test client certificate for default Serverless CA environment
    """

    args = parse_arguments()

    # create AWS session
    session = create_session(args["profile"])

    # set variables
    lifetime = 90
    common_name = "My Test Certificate"
    country = "GB"
    locality = "London"
    state = "England"
    organization = "Serverless Inc"
    organizational_unit = "Security Operations"
    purposes = ["client_auth"]
    output_path_cert_key = f"{base_path}/client-key.pem"
    output_path_cert_pem = f"{base_path}/ca-bundle.pem"
    output_path_cert_crt = f"{base_path}/client-cert.crt"
    output_path_cert_combined = f"{base_path}/ca-cert-key-bundle.pem"
    key_alias = "serverless-tls-keygen-dev"

    # create key pair using symmetric KMS key to provide entropy
    key_id = kms_get_kms_key_id(key_alias, session=session)
    if isinstance(key_id, dict):
        print(f'Error: {key_id["error"]}')
        sys.exit(1)
    kms_response = kms_generate_key_pair(key_id, session=session)
    private_key = load_der_private_key(kms_response["PrivateKeyPlaintext"], None)

    # create CSR
    csr_info = create_csr_info(common_name, country, locality, organization, organizational_unit, state)
    csr_pem = crypto_tls_cert_signing_request(private_key, csr_info)

    # Construct JSON data to pass to Lambda function
    request_payload = {
        "common_name": common_name,
        "purposes": purposes,
        "lifetime": lifetime,
        "base64_csr_data": base64.b64encode(csr_pem).decode("utf-8"),
        "force_issue": True,
        "cert_bundle": True,
    }

    request_payload_bytes = json.dumps(request_payload)

    # Invoke TLS certificate Lambda function
    lambda_name = get_lambda_name("tls-cert", session=session)
    client = session.client("lambda")
    response = client.invoke(
        FunctionName=lambda_name,
        InvocationType="RequestResponse",
        LogType="None",
        Payload=bytes(request_payload_bytes.encode("utf-8")),
    )

    # Inspect the response which includes the signed certificate
    response_payload = response["Payload"]
    payload_data = json.load(response_payload)
    print(f"Certificate issued for {common_name}")
    if args["verbose"]:
        print(payload_data)

    # Extract certificate and private key from response
    base64_cert_data = payload_data["Base64Certificate"]
    cert_data = base64.b64decode(base64_cert_data)
    key_data = crypto_encode_private_key(private_key)

    # Write certificate and private key to files
    if output_path_cert_key:
        with open(output_path_cert_key, "w", encoding="utf-8") as f:
            f.write(key_data.decode("utf-8"))
            print(f"Private key written to {output_path_cert_key}")

    if output_path_cert_pem:
        with open(output_path_cert_pem, "w", encoding="utf-8") as f:
            f.write(cert_data.decode("utf-8"))
            print(f"Combined client certificate and CA bundle written to {output_path_cert_pem}")

    if output_path_cert_crt:
        with open(output_path_cert_crt, "w", encoding="utf-8") as f:
            f.write(cert_data.decode("utf-8"))
            print(f"Certificate written to {output_path_cert_crt}")

    if output_path_cert_combined:
        with open(output_path_cert_combined, "w", encoding="utf-8") as f:
            f.write(key_data.decode("utf-8"))
            f.write(cert_data.decode("utf-8"))
            print(
                f"Combined issuing and root certificate bundle and private key written to {output_path_cert_combined}"
            )


if __name__ == "__main__":
    main()
