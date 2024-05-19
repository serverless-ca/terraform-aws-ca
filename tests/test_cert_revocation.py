from assertpy import assert_that
import base64
import json
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.x509 import load_der_x509_crl
from utils.modules.certs.crypto import crypto_tls_cert_signing_request, create_csr_info
from utils.modules.certs.kms import kms_generate_key_pair
from utils.modules.aws.kms import get_kms_details
from utils.modules.aws.lambdas import get_lambda_name, invoke_lambda
from utils.modules.aws.s3 import delete_s3_object, get_s3_bucket, get_s3_object, list_s3_object_keys, put_s3_object


def test_certificate_revoked():
    """
    Test certificate revoked by CA
    """
    common_name = "pipeline-test-certificate-revoked"

    # Get KMS details for key generation KMS key
    key_alias, kms_arn = get_kms_details("-tls-keygen")
    print(f"Generating key pair using KMS key {key_alias}")

    # Generate key pair using KMS key to ensure randomness
    private_key = load_der_private_key(kms_generate_key_pair(kms_arn)["PrivateKeyPlaintext"], None)

    # Generate Certificate Signing Request
    csr_info = create_csr_info(common_name)
    csr = crypto_tls_cert_signing_request(private_key, csr_info)

    # Construct JSON data to pass to Lambda function
    base64_csr_data = base64.b64encode(csr).decode("utf-8")
    json_data = {
        "common_name": common_name,
        "base64_csr_data": base64_csr_data,
        "passphrase": False,
        "lifetime": 1,
        "force_issue": True,
        "cert_bundle": True,
    }

    # Identify TLS certificate Lambda function
    function_name = get_lambda_name("-tls")
    print(f"Invoking Lambda function {function_name}")

    # Invoke TLS certificate Lambda function
    response = invoke_lambda(function_name, json_data)

    # Inspect the response which includes the signed certificate
    serial_number = response["CertificateInfo"]["SerialNumber"]
    print(f"Certificate serial number {serial_number} issued for {common_name}")

    # Identify S3 buckets
    external_bucket_name = get_s3_bucket("external")
    internal_bucket_name = get_s3_bucket()

    # Get CRL before revocation
    objects = list_s3_object_keys(external_bucket_name)
    crl_file_name = [o for o in objects if "issuing-ca" in o and o.endswith(".crl")][0]
    crl_data = get_s3_object(external_bucket_name, crl_file_name)
    crl = load_der_x509_crl(crl_data)
    print(f"Retrieved CRL {crl_file_name} with {len(crl)} revoked certificates")

    # Get revoked certificate JSON data
    if "revoked.json" in list_s3_object_keys(internal_bucket_name):
        gitops = True
        revoked_json = json.loads(get_s3_object(internal_bucket_name, "revoked.json"))
        print(f"Downloaded revoked.json from {internal_bucket_name} with {len(revoked_json)} revoked certificates")

    else:
        print("No revoked.json found in S3 bucket")
        gitops = False
        revoked_json = []

    # Add certificate to revoked list
    revoked_json.append(
        {
            "common_name": common_name,
            "serial_number": serial_number,
        }
    )

    # Upload revoked list to S3 bucket
    revoked = json.dumps(revoked_json)
    print(f"Uploading revocation data to S3 bucket {internal_bucket_name}")
    put_s3_object(internal_bucket_name, kms_arn, "revoked.json", revoked)

    # Revoke certificate
    function_name = get_lambda_name("issuing-ca-crl")
    print(f"Invoking Lambda function {function_name}")

    # Invoke Issuing CA CRL Lambda function
    response = invoke_lambda(function_name, {})

    # Get CRL after revocation
    crl_data = get_s3_object(external_bucket_name, crl_file_name)
    crl = load_der_x509_crl(crl_data)
    print(f"Retrieved CRL {crl_file_name} with {len(crl)} revoked certificates")

    # Delete revoked.json S3 object if GitOps is not enabled
    if not gitops:
        print(f"Deleting revoked.json from S3 bucket {internal_bucket_name}")
        delete_s3_object(internal_bucket_name, "revoked.json")

    # Check that certificate has been revoked
    assert_that(crl.get_revoked_certificate_by_serial_number(int(serial_number)).serial_number).is_equal_to(
        int(serial_number)
    )
