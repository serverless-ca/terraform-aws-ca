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
