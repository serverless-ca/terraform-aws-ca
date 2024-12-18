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
default_varfile = "client.json"
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


def create_session(profile):
    """
    Creates and returns AWS session using profile
    """

    try:
        session = boto3.session.Session(profile_name=profile)
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

    parser = argparse.ArgumentParser()
    parser.add_argument("--server", action="store_true", help="The role for which the certificate is being generated")
    parser.add_argument("--profile", default="default", help="AWS profile described in .aws/config file")
    parser.add_argument("--vardir", default=default_vardir, help="Directory with JSON files with variables")
    parser.add_argument("--varfile", default=default_varfile, help="JSON variables file")
    parser.add_argument("--keyalgo", default=default_key_pair_spec, help="Key algorithm")
    parser.add_argument("--destination", default=default_base_path, help="Destination directory for generated keys")
    parser.add_argument("--keygenalias", default=None, help="Alias for KMS key")
    parser.add_argument("--verbose", action="store_true", help="Output of all generated payload data")

    return vars(parser.parse_args())


def get_first_certificate(data):
    """
    Leave only the first certificate
    """

    certs = data.split("-----END CERTIFICATE-----")
    certs = [cert.strip() + "\n-----END CERTIFICATE-----" for cert in certs if cert.strip()]
    if certs:
        return certs[0]
    return None


def prepare_certificate_variables(variables, args, is_server):
    """
    Prepare certificate-related variables from the parsed JSON
    """

    lifetime = variables["lifetime"]
    common_name = variables["common_name"]
    country = variables["country"]
    locality = variables["locality"]
    state = variables["state"]
    organization = variables["organization"]
    organizational_unit = variables["organizational_unit"]
    purposes = variables["purposes"]
    key_alias = variables["key_alias"] if args["keygenalias"] is None else args["keygenalias"]
    sans = variables.get("sans", None) if is_server else None

    return lifetime, common_name, country, locality, state, organization, organizational_unit, purposes, key_alias, sans


def generate_key_pair(key_alias, session, key_algo):
    """
    Generate key pair using symmetric KMS key
    """

    key_id = kms_get_kms_key_id(key_alias, session=session)
    if isinstance(key_id, dict):
        print(f'Error: {key_id["error"]}')
        sys.exit(1)

    kms_response = kms_generate_key_pair(key_id, key_pair_spec=key_algo, session=session)
    private_key = load_der_private_key(kms_response["PrivateKeyPlaintext"], None)

    return private_key


def create_csr(private_key, csr_data, state):
    """
    Create CSR
    """

    common_name = csr_data["common_name"]
    country = csr_data["country"]
    locality = csr_data["locality"]
    organization = csr_data["organization"]
    organizational_unit = csr_data["organizational_unit"]
    state = csr_data["state"]
    csr_info = create_csr_info(common_name, country, locality, organization, organizational_unit, state)

    return crypto_tls_cert_signing_request(private_key, csr_info)


def prepare_request_payload(csr_pem, common_name, purposes, lifetime, sans):
    """
    Prepare the request payload for Lambda
    """

    request_payload = {
        "common_name": common_name,
        "purposes": purposes,
        "lifetime": lifetime,
        "base64_csr_data": base64.b64encode(csr_pem).decode("utf-8"),
        "force_issue": True,
        "cert_bundle": True,
    }
    if sans is not None:
        request_payload["sans"] = sans

    return json.dumps(request_payload)


def invoke_lambda(session, request_payload_bytes):
    """
    Invoke the TLS certificate Lambda function
    """

    lambda_name = get_lambda_name("tls-cert", session=session)
    client = session.client("lambda")
    response = client.invoke(
        FunctionName=lambda_name,
        InvocationType="RequestResponse",
        LogType="None",
        Payload=bytes(request_payload_bytes.encode("utf-8")),
    )
    response_payload = response["Payload"]

    return json.load(response_payload)


def write_certificate_files(cert_data, key_data, common_name, base_path, is_server):
    """
    Write certificate and private key to files
    """

    clean_common_name = common_name.split(".")[0]
    certificate_dir = f"{base_path}/{clean_common_name}"
    os.makedirs(certificate_dir, exist_ok=True)

    role = "server" if is_server else "client"

    # Set output file paths
    output_path_cert_key = f"{certificate_dir}/{role}-key.pem"  # private key
    output_path_cert_crt = f"{certificate_dir}/{role}-cert.crt"  # certificate
    output_path_cert_pem = f"{certificate_dir}/ca.pem"  # cert + issuing CA + root CA PEM bundle

    # Write certificate and private key to files
    with open(output_path_cert_key, "w", encoding="utf-8") as f:
        f.write(key_data.decode("utf-8"))
        print(f"Private key written to {output_path_cert_key}")

    with open(output_path_cert_pem, "w", encoding="utf-8") as f:
        f.write(cert_data.decode("utf-8"))
        print(f"Certificate chain written to {output_path_cert_pem}")

    cert = get_first_certificate(cert_data.decode("utf-8")) or cert_data.decode("utf-8")
    with open(output_path_cert_crt, "w", encoding="utf-8") as f:
        f.write(cert)
        print(f"Certificate written to {output_path_cert_crt}")


def main():  # pylint:disable=too-many-locals
    """
    Create certificate for default Serverless CA environment
    """

    args = parse_arguments()

    varfile = f"{args['vardir']}/{args['varfile']}"
    is_server = args["server"]

    if is_server:
        print("Generating SERVER certificate")
    else:
        print("Generating CLIENT certificate")

    # set variables
    variables = parse_variables(varfile)
    if "error" in variables:
        print(f'Error: Unable to read variables. {variables["error"]}')
        sys.exit(1)
    else:
        print(f"Variables are obtained from file {varfile}")

    lifetime, common_name, country, locality, state, organization, organizational_unit, purposes, key_alias, sans = (
        prepare_certificate_variables(variables, args, is_server)
    )

    # Create AWS session
    session = create_session(args["profile"])

    # Generate key pair
    private_key = generate_key_pair(key_alias, session, args["keyalgo"])

    # Create CSR
    csr_org_data = {
        "common_name": common_name,
        "country": country,
        "locality": locality,
        "organization": organization,
        "organizational_unit": organizational_unit,
        "state": state,
    }
    csr_pem = create_csr(private_key, csr_org_data, state)

    # Prepare request payload for Lambda
    request_payload_bytes = prepare_request_payload(csr_pem, common_name, purposes, lifetime, sans)

    # Invoke Lambda function
    payload_data = invoke_lambda(session, request_payload_bytes)
    print(f"Certificate issued for {common_name}")

    if args["verbose"]:
        print(payload_data)

    # Extract certificate and private key
    base64_cert_data = payload_data["Base64Certificate"]
    cert_data = base64.b64decode(base64_cert_data)
    key_data = crypto_encode_private_key(private_key)

    # Write certificate and private key to files
    write_certificate_files(cert_data, key_data, common_name, args["destination"], is_server)


if __name__ == "__main__":
    main()
