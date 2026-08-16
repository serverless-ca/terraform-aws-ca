import boto3
import os


def get_kms_details(key_purpose, session=None):
    """
    Get the KMS ARN based on the key purpose
    """
    if session is None:
        kms_client = boto3.client("kms")
    else:
        kms_client = session.client("kms")

    key_aliases = kms_client.list_aliases()["Aliases"]
    # optional CA_PROJECT filter to target one of several CA deployments in the same account
    project = os.environ.get("CA_PROJECT")
    if project:
        key_aliases = [k for k in key_aliases if k["AliasName"].startswith(f"alias/{project}-")]
    key_aliases = [k for k in key_aliases if key_purpose in k["AliasName"]]

    key_alias = key_aliases[0]["AliasName"]

    return key_alias, kms_client.describe_key(KeyId=key_alias)["KeyMetadata"]["Arn"]
