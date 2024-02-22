#!/usr/bin/env python3
from cryptography.hazmat.primitives.serialization import load_der_private_key
from utils_tests.certs.crypto import create_csr_info, crypto_encode_private_key, crypto_tls_cert_signing_request
from utils_tests.certs.kms import kms_generate_key_pair, kms_get_kms_key_id


def main():  # pylint:disable=too-many-locals
    """
    Create test Certificate Signing Request (CSR) for default Serverless CA environment
    /tmp location of csr and keys is for test purposes only
    In production, change location to e.g. /certs with locked down permissions
    """

    # set variables
    common_name = "Cloud Engineer"
    country = "GB"
    locality = "London"
    state = "England"
    organization = "Serverless Inc"
    organizational_unit = "Security Operations"
    output_path_cert_key = "/tmp/cert-request-key.pem"
    output_path_csr = "/tmp/cert-request.csr"
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
            print(f"Private key written to {output_path_cert_key}, this should now be moved to a safe location")


if __name__ == "__main__":
    main()
