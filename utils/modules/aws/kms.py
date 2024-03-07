import boto3


def get_kms_details(key_purpose):
    """
    Get the KMS ARN based on the key purpose
    """

    kms_client = boto3.client("kms")

    key_aliases = kms_client.list_aliases()["Aliases"]
    key_aliases = [k for k in key_aliases if key_purpose in k["AliasName"]]

    key_alias = key_aliases[0]["AliasName"]

    return key_alias, kms_client.describe_key(KeyId=key_alias)["KeyMetadata"]["Arn"]
