#!/usr/bin/env python3

import json
import base64
import os
import sys
import argparse
import boto3
from cryptography.hazmat.primitives.serialization import load_der_private_key
from modules.certs.crypto import create_csr_info, crypto_encode_private_key, crypto_tls_cert_signing_request
from modules.certs.kms import kms_generate_key_pair, kms_get_kms_key_id
from modules.aws.lambdas import get_lambda_name

# identify home directory and create certs subdirectory if needed
homedir = os.path.expanduser("~")
dir_path = os.path.dirname(os.path.realpath(__file__))
default_vardir = f"{dir_path}/variables"
default_varfile = "certificate_variables.json"
default_base_path = f"{homedir}/ca/certificates"
default_key_pair_spec = "ECC_NIST_P256"


def parse_variables(input_file):
    """
    Parse variables file to obtain variables
    """

    if os.path.isfile(input_file):
        try:
            with open(input_file, encoding="utf-8") as json_file:
                data = json.load(json_file)
        except Exception as e:
            data = {"error": f"Unable to parse JSON. {e}"}
    else:
        data = {"error": "No file"}
    return data


def get_session(aws_profile):
    """
    Open boto3 connection using profile
    """

    try:
        aws_session = boto3.session.Session(profile_name=aws_profile)
    except Exception as e:
        aws_session = {"error": e}
    return aws_session


def parse_arguments():
    """
    Read arguments and return arguments dictonary
    """

    arguments = {}
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", action="store_true", help="The role for which the certificate is being generated")
    parser.add_argument("--profile", default="default", help="AWS profile described in .aws/config file")
    parser.add_argument("--vardir", default=default_vardir, help="Directory with JSON files with variables")
    parser.add_argument("--varfile", default=default_varfile, help="JSON variables file")
    parser.add_argument("--keyalgo", default=default_key_pair_spec, help="Key algorithm")
    parser.add_argument("--destination", default=default_base_path, help="Destination directory for generated keys")
    parser.add_argument("--keygenalias", default=None, help="Alias for KMS key")
    parser.add_argument("--verbose", action="store_true", help="Output of all generated payload data")
    arguments = vars(parser.parse_args())

    return arguments


def create_session(profile):
    """
    Creates and returns AWS session using profile
    """

    session = get_session(profile)
    if isinstance(session, dict):
        print(f"Error: Unable to open session using profile {profile}. {session['error']}")
        sys.exit(1)
    else:
        print(f"AWS session opened using profile: {profile}")

    return session


def get_first_certificate(data):
    """
    Leave only the first certificate
    """

    certs = data.split("-----END CERTIFICATE-----")
    certs = [cert.strip() + "\n-----END CERTIFICATE-----" for cert in certs if cert.strip()]
    if certs:
        return certs[0]
    return None


def main():  # pylint:disable=too-many-locals,too-many-branches,too-many-statements
    """
    Create certificate for default Serverless CA environment
    """

    args = parse_arguments()

    varfile = f"{args['vardir']}/{args['varfile']}"
    is_server = args["server"]
    if is_server:
        role = "server"
        print("Generating SERVER certificate")
    else:
        role = "client"
        print("Generating CLIENT certificate")
    base_path = args["destination"]
    if not os.path.exists(base_path):
        print(f"Creating directory {base_path}")
        os.makedirs(base_path)

    session = create_session(args["profile"])

    # set variables
    variables = parse_variables(varfile)
    if "error" in variables:
        print(f'Error: Unable to read variables. {variables["error"]}')
    else:
        print(f"Variables are obtained from file {varfile}")

    lifetime = variables["lifetime"]
    common_name = variables["common_name"]
    country = variables["country"]
    locality = variables["locality"]
    state = variables["state"]
    organization = variables["organization"]
    organizational_unit = variables["organizational_unit"]
    purposes = variables["purposes"]
    if args["keygenalias"] is None:
        key_alias = variables["key_alias"]
    else:
        key_alias = args["keygenalias"]
    if is_server:
        try:
            sans = variables["sans"]
        except KeyError:
            print("Server role requires sans variable to be set, but it is not obtained")
            sys.exit(3)

    # create key pair using symmetric KMS key to provide entropy
    key_id = kms_get_kms_key_id(key_alias, session=session)
    if isinstance(key_id, dict):
        print(f'Error: {key_id["error"]}')
        sys.exit(1)
    kms_response = kms_generate_key_pair(key_id, key_pair_spec=args["keyalgo"], session=session)
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
    if is_server:
        request_payload["sans"] = sans

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

    # Creating per certificate directory
    clean_common_name = common_name.split(".")[0]
    certificate_dir = f"{base_path}/{clean_common_name}"
    if not os.path.exists(certificate_dir):
        print(f"Creating per certificate directory {clean_common_name}")
        os.makedirs(certificate_dir)

    # Set outputs destination
    output_path_cert_key = f"{certificate_dir}/{role}-key.pem"  # private key
    output_path_cert_crt = f"{certificate_dir}/{role}-cert.crt"  # certificate
    output_path_cert_pem = f"{certificate_dir}/ca.pem"  # cert + issuing CA + root CA PEM bundle

    # Get the first certificate from cert_data
    first_cert = get_first_certificate(cert_data.decode("utf-8"))
    if first_cert is None:
        cert = cert_data.decode("utf-8")
    else:
        cert = first_cert

    # Write certificate and private key to files
    if output_path_cert_key:
        with open(output_path_cert_key, "w", encoding="utf-8") as f:
            f.write(key_data.decode("utf-8"))
            print(f"Private key written to {output_path_cert_key}")

    if output_path_cert_pem:
        with open(output_path_cert_pem, "w", encoding="utf-8") as f:
            f.write(cert_data.decode("utf-8"))
            print(f"Intermediate CA pem bundle written to {output_path_cert_pem}")

    if output_path_cert_crt:
        with open(output_path_cert_crt, "w", encoding="utf-8") as f:
            f.write(cert)
            print(f"Certificate written to {output_path_cert_crt}")


if __name__ == "__main__":
    main()
