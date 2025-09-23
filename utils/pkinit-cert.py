#!/usr/bin/env python3
"""
PKINIT Certificate Generator

This script generates PKINIT certificates using the serverless CA with
appropriate profiles for Kerberos authentication.
"""

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
    Read arguments and return arguments dictionary
    """
    parser = argparse.ArgumentParser(description="Generate PKINIT certificates using serverless CA")
    parser.add_argument("--profile", default=None, help="AWS profile described in .aws/config file")
    parser.add_argument("--verbose", action="store_true", help="Output of all generated payload data")
    parser.add_argument("--type", choices=["kdc", "client"], required=True, 
                       help="Type of PKINIT certificate to generate")
    parser.add_argument("--principal", required=True, 
                       help="Kerberos principal name (e.g., krbtgt/EXAMPLE.COM@EXAMPLE.COM or user@EXAMPLE.COM)")
    parser.add_argument("--organization", default="Example Corp", 
                       help="Organization name")
    parser.add_argument("--organizational-unit", default="IT Department", 
                       help="Organizational unit name")
    parser.add_argument("--country", default="US", 
                       help="Country code")
    parser.add_argument("--state", default="California", 
                       help="State or province")
    parser.add_argument("--locality", default="San Francisco", 
                       help="Locality or city")
    parser.add_argument("--lifetime", type=int, default=365, 
                       help="Certificate lifetime in days (default: 365 for client, 3650 for KDC)")
    parser.add_argument("--output-prefix", default="pkinit", 
                       help="Output file prefix")
    
    return vars(parser.parse_args())


def validate_principal(principal, cert_type):
    """
    Validate Kerberos principal format
    """
    if cert_type == "kdc":
        if not principal.startswith("krbtgt/") or "@" not in principal:
            print("Error: KDC principal must be in format 'krbtgt/REALM@REALM'")
            sys.exit(1)
    elif cert_type == "client":
        if "@" not in principal:
            print("Error: Client principal must be in format 'user@REALM' or 'service@REALM'")
            sys.exit(1)


def main():
    """
    Generate PKINIT certificate for specified type and principal
    """
    args = parse_arguments()
    
    # Validate principal format
    validate_principal(args["principal"], args["type"])
    
    # Set default lifetime for KDC certificates
    if args["type"] == "kdc" and args["lifetime"] == 365:
        args["lifetime"] = 3650
    
    # create AWS session
    session = create_session(args["profile"])
    
    # Set variables based on certificate type
    if args["type"] == "kdc":
        profile_name = "pkinit_kdc"
        purposes = ["client_auth", "server_auth"]
        output_suffix = "kdc"
    else:  # client
        profile_name = "pkinit_client"
        purposes = ["client_auth"]
        output_suffix = "client"
    
    # Output file paths
    output_path_cert_key = f"{base_path}/{args['output_prefix']}-{output_suffix}-key.pem"
    output_path_cert_pem = f"{base_path}/{args['output_prefix']}-{output_suffix}-cert.pem"
    output_path_cert_crt = f"{base_path}/{args['output_prefix']}-{output_suffix}-cert.crt"
    output_path_cert_combined = f"{base_path}/{args['output_prefix']}-{output_suffix}-combined.pem"
    
    # KMS key alias (adjust based on your environment)
    key_alias = "serverless-tls-keygen-dev"
    
    # create key pair using symmetric KMS key to provide entropy
    key_id = kms_get_kms_key_id(key_alias, session=session)
    if isinstance(key_id, dict):
        print(f'Error: {key_id["error"]}')
        sys.exit(1)
    kms_response = kms_generate_key_pair(key_id, session=session)
    private_key = load_der_private_key(kms_response["PrivateKeyPlaintext"], None)
    
    # create CSR
    csr_info = create_csr_info(
        args["principal"], 
        args["country"], 
        args["locality"], 
        args["organization"], 
        args["organizational_unit"], 
        args["state"]
    )
    csr_pem = crypto_tls_cert_signing_request(private_key, csr_info)
    
    # Construct JSON data to pass to Lambda function
    request_payload = {
        "common_name": args["principal"],
        "purposes": purposes,
        "lifetime": args["lifetime"],
        "base64_csr_data": base64.b64encode(csr_pem).decode("utf-8"),
        "force_issue": True,
        "cert_bundle": True,
        "profile": profile_name,
        "organization": args["organization"],
        "organizational_unit": args["organizational_unit"],
        "country": args["country"],
        "state": args["state"],
        "locality": args["locality"]
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
    print(f"PKINIT {args['type']} certificate issued for {args['principal']}")
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
            print(f"PKINIT {args['type']} certificate and CA bundle written to {output_path_cert_pem}")
    
    if output_path_cert_crt:
        with open(output_path_cert_crt, "w", encoding="utf-8") as f:
            f.write(cert_data.decode("utf-8"))
            print(f"Certificate written to {output_path_cert_crt}")
    
    if output_path_cert_combined:
        with open(output_path_cert_combined, "w", encoding="utf-8") as f:
            f.write(key_data.decode("utf-8"))
            f.write(cert_data.decode("utf-8"))
            print(f"Combined private key and certificate written to {output_path_cert_combined}")
    
    print(f"\nPKINIT {args['type']} certificate generation completed!")
    print(f"Principal: {args['principal']}")
    print(f"Profile: {profile_name}")
    print(f"Lifetime: {args['lifetime']} days")
    print(f"Files created in: {base_path}")


if __name__ == "__main__":
    main()
