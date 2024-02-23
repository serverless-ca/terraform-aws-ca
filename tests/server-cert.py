#!/usr/bin/env python3
import json
import base64
import boto3
import os
from cryptography.hazmat.primitives.serialization import load_der_private_key
from utils_tests.certs.crypto import create_csr_info, crypto_encode_private_key, crypto_tls_cert_signing_request
from utils_tests.certs.kms import kms_generate_key_pair, kms_get_kms_key_id
from utils_tests.aws.lambdas import get_lambda_name

homedir = os.path.expanduser("~")


def main():  # pylint:disable=too-many-locals
    """
    Create test server certificate for default Serverless CA environment
    Before using, create a subdirectory `certs` within your home directory
    """

    # set variables
    lifetime = 90
    common_name = "test.example.com"
    sans = ["test.example.com", "test2.example.com"]
    country = "GB"
    locality = "London"
    state = "England"
    organization = "Serverless Inc"
    organizational_unit = "Security Operations"
    output_path_cert_key = f"{homedir}/certs/server-key.pem"
    output_path_cert_pem = f"{homedir}/certs/server-cert.pem"
    output_path_cert_crt = f"{homedir}/certs/server-cert.crt"
    output_path_cert_combined = f"{homedir}/certs/server-cert-key.pem"
    key_alias = "serverless-tls-keygen-dev"

    # create key pair using symmetric KMS key to provide entropy
    key_id = kms_get_kms_key_id(key_alias)
    kms_response = kms_generate_key_pair(key_id)
    private_key = load_der_private_key(kms_response["PrivateKeyPlaintext"], None)

    # create CSR
    csr_info = create_csr_info(common_name, country, locality, organization, organizational_unit, state)
    csr_pem = crypto_tls_cert_signing_request(private_key, csr_info)

    # Construct JSON data to pass to Lambda function
    request_payload = {
        "common_name": common_name,
        "sans": sans,
        "lifetime": lifetime,
        "base64_csr_data": base64.b64encode(csr_pem).decode("utf-8"),
        "force_issue": True,
        "cert_bundle": True,
    }

    request_payload_bytes = json.dumps(request_payload)

    # Invoke TLS certificate Lambda function
    lambda_name = get_lambda_name("tls-cert")
    client = boto3.client("lambda")
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
            print(f"Certificate written to {output_path_cert_pem}")

    if output_path_cert_crt:
        with open(output_path_cert_crt, "w", encoding="utf-8") as f:
            f.write(cert_data.decode("utf-8"))
            print(f"Certificate written to {output_path_cert_crt}")

    if output_path_cert_combined:
        with open(output_path_cert_combined, "w", encoding="utf-8") as f:
            f.write(key_data.decode("utf-8"))
            f.write(cert_data.decode("utf-8"))

    print(f"Certificate and key written to {output_path_cert_combined}")


if __name__ == "__main__":
    main()
