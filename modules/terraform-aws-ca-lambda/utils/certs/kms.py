import boto3


def kms_generate_key_pair(key_id, key_pair_spec="ECC_NIST_P256"):
    client = boto3.client(service_name="kms")

    return client.generate_data_key_pair(
        KeyId=key_id,
        KeyPairSpec=key_pair_spec,
    )


def kms_get_kms_key_id(alias):
    """returns the KMS Key ARN for a specified alias"""
    client = boto3.client(service_name="kms")
    aliases = client.list_aliases(Limit=100)["Aliases"]

    return [a for a in aliases if a["AliasName"] == f"alias/{alias}"][0]["TargetKeyId"]


def kms_describe_key(kms_key_id):
    """returns details of a KMS key"""
    client = boto3.client(service_name="kms")

    return client.describe_key(KeyId=kms_key_id)["KeyMetadata"]


def kms_get_public_key(kms_key_id):
    """returns cipher and public key of an asymmetric KMS key"""
    client = boto3.client(service_name="kms")

    response = client.get_public_key(KeyId=kms_key_id)

    return response["PublicKey"]


def kms_sign(kms_key_id, message, signing_algorithm="RSASSA_PSS_SHA_256"):
    """returns digital signature"""
    client = boto3.client(service_name="kms")
    response = client.sign(KeyId=kms_key_id, SigningAlgorithm=signing_algorithm, Message=message)

    return response["Signature"]
