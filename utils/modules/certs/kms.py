import boto3


def kms_generate_key_pair(key_id, key_pair_spec="ECC_NIST_P256", session=None):
    """Generate KMS key pair"""

    if session is None:
        client = boto3.client(service_name="kms")
    else:
        client = session.client(service_name="kms")

    return client.generate_data_key_pair(
        KeyId=key_id,
        KeyPairSpec=key_pair_spec,
    )


def kms_get_kms_key_id(alias, session=None):
    """returns the KMS Key ID for a specified alias"""

    if session is None:
        client = boto3.client(service_name="kms")
    else:
        client = session.client(service_name="kms")

    alias_name = f"alias/{alias}"
    try:
        response = client.describe_key(KeyId=alias_name)
        return response["KeyMetadata"]["KeyId"]
    except Exception as e:
        return {"error": f"Failed to get KMS key ID. {e}"}
