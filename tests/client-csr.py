#!/usr/bin/env python3
import os
from cryptography.hazmat.primitives.serialization import load_der_private_key
from utils_tests.certs.crypto import create_csr_info, crypto_encode_private_key, crypto_tls_cert_signing_request
from utils_tests.certs.kms import kms_generate_key_pair, kms_get_kms_key_id


# identify home directory and create certs subdirectory if needed
homedir = os.path.expanduser("~")
base_path = f"{homedir}/certs"
if not os.path.exists(base_path):
    print(f"Creating directory {base_path}")
    os.makedirs(base_path)


def main():  # pylint:disable=too-many-locals
    """
    Create test client Certificate Signing Request (CSR) for default Serverless CA environment
    """

    # set variables
    common_name = "Cloud Engineer"
    country = "GB"
    locality = "London"
    state = "England"
    organization = "Serverless Inc"
    organizational_unit = "Security Operations"
    output_path_cert_key = f"{base_path}/client-cert-request-key.pem"
    output_path_csr = f"{base_path}/client-cert-request.csr"
    key_alias = "serverless-tls-keygen-dev"

    # create key pair using symmetric KMS key to provide entropy
    key_id = kms_get_kms_key_id(key_alias)
    kms_response = kms_generate_key_pair(key_id)
    private_key = load_der_private_key(kms_response["PrivateKeyPlaintext"], None)

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
