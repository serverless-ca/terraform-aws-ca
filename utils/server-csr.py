#!/usr/bin/env python3
import os
from modules.certs.crypto import (
    create_csr_info,
    crypto_encode_private_key,
    crypto_tls_cert_signing_request,
    generate_key,
    write_key_to_disk,
)


# identify home directory and create certs subdirectory if needed
homedir = os.path.expanduser("~")
base_path = f"{homedir}/certs"
if not os.path.exists(base_path):
    print(f"Creating directory {base_path}")
    os.makedirs(base_path)


def main():
    """
    Create test server Certificate Signing Request (CSR) for default Serverless CA environment
    """

    # set variables
    common_name = "server.example.com"
    country = "GB"
    locality = "London"
    state = "England"
    organization = "Serverless Inc"
    organizational_unit = "Security Operations"
    output_path_cert_key = f"{base_path}/server-cert-request-key.pem"
    output_path_csr = f"{base_path}/server-cert-request.csr"

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
