import os
import boto3
from .kms import kms_get_kms_key_id

project = os.environ["PROJECT"]
env_name = os.environ["ENVIRONMENT_NAME"]


def kms_ca_generate_key_pair(key_pair_spec="RSA_2048"):
    client = boto3.client(service_name="kms")

    if env_name in ["prd", "prod"]:
        tls_keygen_kms_arn = kms_get_kms_key_id(f"{project}-tls-keygen")

    else:
        tls_keygen_kms_arn = kms_get_kms_key_id(f"{project}-tls-keygen-{env_name}")

    return client.generate_data_key_pair(
        KeyId=tls_keygen_kms_arn,
        KeyPairSpec=key_pair_spec,
    )
