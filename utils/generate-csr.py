#!/usr/bin/env python3
import os
import json
import argparse
from modules.certs.crypto import (
    create_csr_info,
    crypto_encode_private_key,
    crypto_tls_cert_signing_request,
    generate_key,
    write_key_to_disk,
)


def load_variables_from_file(file_path):
    """
    Load the variables from a JSON file.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_arguments():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description="Generate CSR and private key")
    parser.add_argument("--server", action="store_true", help="Generate server certificate (default is client)")
    parser.add_argument("--varfile", type=str, help="Path to JSON file containing CSR variables")
    parser.add_argument(
        "--destination",
        type=str,
        default=os.path.expanduser("~") + "/certs",
        help="Path to destination directory for output files (default: ~/.certs)",
    )
    return parser.parse_args()


def main():
    """
    Create test client or server Certificate Signing Request (CSR) for default Serverless CA environment
    """

    # parse arguments
    args = parse_arguments()

    # set variables
    if args.varfile:
        variables = load_variables_from_file(args.varfile)
    else:
        # default values
        variables = {
            "common_name": "Cloud Engineer",
            "country": "GB",
            "locality": "London",
            "state": "England",
            "organization": "Serverless Inc",
            "organizational_unit": "Security Operations",
        }

    if args.server:
        variables["common_name"] = "server.example.com"

    common_name = variables["common_name"]
    country = variables["country"]
    locality = variables["locality"]
    state = variables["state"]
    organization = variables["organization"]
    organizational_unit = variables["organizational_unit"]

    if not os.path.exists(args.destination):
        print(f"Creating directory {args.destination}")
        os.makedirs(args.destination)

    if args.server:
        output_path_cert_key = f"{args.destination}/server-cert-request-key.pem"
        output_path_csr = f"{args.destination}/server-cert-request.csr"
    else:
        output_path_cert_key = f"{args.destination}/client-cert-request-key.pem"
        output_path_csr = f"{args.destination}/client-cert-request.csr"

    # create private key
    private_key = generate_key()
    write_key_to_disk(private_key, output_path_cert_key)

    # create CSR
    csr_info = create_csr_info(common_name, country, locality, organization, organizational_unit, state)
    csr_pem = crypto_tls_cert_signing_request(private_key, csr_info)

    # write CSR to file
    print(f"Certificate requested for {common_name}")

    if output_path_csr:
        with open(output_path_csr, "w", encoding="utf-8") as f:
            f.write(csr_pem.decode("utf-8"))
            print(f"Certificate request written to {output_path_csr}")

    # write private key to file
    key_data = crypto_encode_private_key(private_key)
    if output_path_cert_key:
        with open(output_path_cert_key, "w", encoding="utf-8") as f:
            f.write(key_data.decode("utf-8"))
            print(f"Private key written to {output_path_cert_key}")


if __name__ == "__main__":
    main()
