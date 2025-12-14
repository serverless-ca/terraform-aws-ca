from assertpy import assert_that
import base64
import json
import structlog
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.x509 import load_der_x509_crl
from utils.modules.certs.crypto import crypto_tls_cert_signing_request, create_csr_info
from utils.modules.certs.kms import kms_generate_key_pair
from utils.modules.aws.kms import get_kms_details
from utils.modules.aws.lambdas import get_lambda_name, invoke_lambda
from utils.modules.aws.s3 import delete_s3_object, get_s3_bucket, get_s3_object, list_s3_object_keys, put_s3_object

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

log = structlog.get_logger()

common_name = "pipeline-test-certificate-revoked"


def test_certificate_revoked():
    """
    Test certificate revoked by CA
    """
    # Get KMS details for key generation KMS key
    key_alias, kms_arn = get_kms_details("-tls-keygen")
    log.info("generating key pair using KMS key", kms_key_alias=key_alias, kms_key_arn=kms_arn)

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
    log.info("invoking lambda function", function_name=function_name)
    # Invoke TLS certificate Lambda function
    response = invoke_lambda(function_name, json_data)

    # Inspect the response which includes the signed certificate
    serial_number = response["CertificateInfo"]["SerialNumber"]
    log.info("certificate serial number issued", serial_number=serial_number, common_name=common_name)

    # Identify S3 buckets
    external_bucket_name = get_s3_bucket("external")
    internal_bucket_name = get_s3_bucket()

    # Get CRL before revocation
    objects = list_s3_object_keys(external_bucket_name)
    crl_file_name = [o for o in objects if "issuing-ca" in o and o.endswith(".crl")][0]
    crl_data = get_s3_object(external_bucket_name, crl_file_name)
    crl = load_der_x509_crl(crl_data)
    log.info(
        "retrieved CRL (pre-revocation)",
        bucket=external_bucket_name,
        key=crl_file_name,
        revoked_certificate_count=len(crl),
    )

    # Get revoked certificate JSON data
    gitops_revocation_config_file_name = "revoked.json"
    if gitops_revocation_config_file_name in list_s3_object_keys(internal_bucket_name):
        gitops = True
        revoked_json = json.loads(get_s3_object(internal_bucket_name, gitops_revocation_config_file_name))
        log.info(
            "loaded git managed revocation file",
            bucket=internal_bucket_name,
            key=gitops_revocation_config_file_name,
            revoked_certificate_count=len(revoked_json),
        )
    else:
        log.info(
            "git managed revocation file not found", bucket=internal_bucket_name, key=gitops_revocation_config_file_name
        )
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
    log.info(
        "uploading revocation data to s3 bucket",
        bucket_name=internal_bucket_name,
        key=gitops_revocation_config_file_name,
        kms_arn=kms_arn,
        revoked_certificate_count=len(revoked),
    )
    put_s3_object(internal_bucket_name, kms_arn, gitops_revocation_config_file_name, revoked)

    # Revoke certificate
    function_name = get_lambda_name("issuing-ca-crl")
    log.info("invoking lambda function", function_name=function_name)

    # Invoke Issuing CA CRL Lambda function
    response = invoke_lambda(function_name, {})

    # Get CRL after revocation
    crl_data = get_s3_object(external_bucket_name, crl_file_name)
    crl = load_der_x509_crl(crl_data)
    log.info(
        "retrieved CRL (post-revocation)",
        bucket=external_bucket_name,
        key=crl_file_name,
        revoked_certificate_count=len(crl),
    )

    # Delete revoked.json S3 object if GitOps is not enabled
    if not gitops:
        log.info(
            "deleting revocation data from s3 bucket",
            bucket=internal_bucket_name,
            key=gitops_revocation_config_file_name,
        )
        delete_s3_object(internal_bucket_name, gitops_revocation_config_file_name)

    # Check that certificate has been revoked
    assert_that(crl.get_revoked_certificate_by_serial_number(int(serial_number)).serial_number).is_equal_to(
        int(serial_number)
    )


def test_crl_includes_revoked_certs_from_db():
    """
    Test CRL includes revoked certificates from database
    """

    # Identify S3 buckets
    external_bucket_name = get_s3_bucket("external")

    # Get current CRL after revocation from previous test, not listed in revoked.json
    objects = list_s3_object_keys(external_bucket_name)
    crl_file_name = [o for o in objects if "issuing-ca" in o and o.endswith(".crl")][0]
    crl_data = get_s3_object(external_bucket_name, crl_file_name)
    crl = load_der_x509_crl(crl_data)
    log.info(
        "retrieved CRL (pre-revocation)",
        bucket=external_bucket_name,
        key=crl_file_name,
        revoked_certificate_count=len(crl),
    )
    number_of_revoked_certificates_before = len(crl)

    # Invoke Issuing CA CRL Lambda function
    function_name = get_lambda_name("issuing-ca-crl")
    log.info("invoking lambda function", function_name=function_name)
    response = invoke_lambda(function_name, {})

    # Get CRL after revocation
    crl_data = get_s3_object(external_bucket_name, crl_file_name)
    crl = load_der_x509_crl(crl_data)
    log.info(
        "retrieved CRL (post-revocation)",
        bucket=external_bucket_name,
        key=crl_file_name,
        revoked_certificate_count=len(crl),
    )
    number_of_revoked_certificates_after = len(crl)

    assert_that(number_of_revoked_certificates_after).is_equal_to(number_of_revoked_certificates_before)
