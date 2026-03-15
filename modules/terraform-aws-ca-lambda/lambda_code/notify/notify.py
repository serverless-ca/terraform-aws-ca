import json
import logging
import os

import boto3
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

slack_secret_arn = os.environ["SLACK_SECRET_ARN"]
slack_channels = os.environ["SLACK_CHANNELS"]
slack_bad_emoji = os.environ["SLACK_BAD_EMOJI"]
slack_good_emoji = os.environ["SLACK_GOOD_EMOJI"]
slack_username = os.environ["SLACK_USERNAME"]
slack_warning_emoji = os.environ["SLACK_WARNING_EMOJI"]
project = os.environ.get("PROJECT", "Serverless CA")


def get_slack_token():
    """Get Slack OAuth token from AWS Secrets Manager"""
    client = boto3.client("secretsmanager")
    return client.get_secret_value(SecretId=slack_secret_arn)["SecretString"]


def get_account_alias():
    """Get AWS account alias for display in messages"""
    try:
        iam = boto3.client("iam")
        aliases = iam.list_account_aliases()["AccountAliases"]
        return aliases[0] if aliases else None
    except Exception:
        logger.exception("Failed to get account alias")
        return None


def build_section_block(text):
    """Build a Slack Block Kit section block with mrkdwn text"""
    return {"type": "section", "text": {"type": "mrkdwn", "text": text}}


def build_header_block(text):
    """Build a Slack Block Kit header block"""
    return {"type": "header", "text": {"type": "plain_text", "text": text, "emoji": True}}


def build_divider_block():
    return {"type": "divider"}


def build_fields_block(fields):
    """Build a Slack Block Kit section block with multiple fields"""
    return {
        "type": "section",
        "fields": [{"type": "mrkdwn", "text": f} for f in fields],
    }


def format_cert_info_fields(cert_info):
    """Format CertificateInfo dict into Slack fields"""
    fields = []
    if "CommonName" in cert_info:
        fields.append(f"*Common Name:*\n{cert_info['CommonName']}")
    if "SerialNumber" in cert_info:
        fields.append(f"*Serial Number:*\n`{cert_info['SerialNumber']}`")
    if "Issued" in cert_info:
        fields.append(f"*Issued:*\n{cert_info['Issued']}")
    if "Expires" in cert_info:
        fields.append(f"*Expires:*\n{cert_info['Expires']}")
    return fields


def cert_expired_message(json_data):
    """Certificate Expired - certificate has expired without replacement"""
    try:
        cert_info = json_data["CertificateInfo"]
        days = json_data["DaysRemaining"]
    except KeyError:
        return None

    blocks = [build_header_block(f"{slack_bad_emoji} Certificate Expired")]

    if "Subject" in json_data:
        blocks.append(build_section_block(f"*Subject:* `{json_data['Subject']}`"))

    fields = format_cert_info_fields(cert_info)
    if fields:
        blocks.append(build_fields_block(fields))

    blocks.append(build_section_block(f"*Days Remaining:* {days}"))

    return blocks


def cert_expiry_warning_message(json_data):
    """Certificate Expiry Warning - certificate approaching expiry"""
    try:
        cert_info = json_data["CertificateInfo"]
        days = json_data["DaysRemaining"]
    except KeyError:
        return None

    if days <= 0:
        return None

    blocks = [build_header_block(f"{slack_warning_emoji} Certificate Expiry Warning")]

    if "Subject" in json_data:
        blocks.append(build_section_block(f"*Subject:* `{json_data['Subject']}`"))

    fields = format_cert_info_fields(cert_info)
    if fields:
        blocks.append(build_fields_block(fields))

    blocks.append(build_section_block(f"*Days Remaining:* {days}"))

    return blocks


def cert_issued_message(json_data):
    try:
        cert_info = json_data["CertificateInfo"]
    except KeyError:
        return None

    if "DaysRemaining" in json_data:
        return None

    blocks = [build_header_block(f"{slack_good_emoji} Certificate Issued")]

    if "Subject" in json_data:
        blocks.append(build_section_block(f"*Subject:* `{json_data['Subject']}`"))

    fields = format_cert_info_fields(cert_info)
    if fields:
        blocks.append(build_fields_block(fields))

    return blocks


def cert_request_rejected_message(json_data):
    try:
        csr_info = json_data["CSRInfo"]
        reason = json_data["Reason"]
    except KeyError:
        return None

    blocks = [build_header_block(f"{slack_bad_emoji} Certificate Request Rejected")]
    blocks.append(build_section_block(f"*Reason:* {reason}"))

    if "Subject" in json_data:
        blocks.append(build_section_block(f"*Subject:* `{json_data['Subject']}`"))

    fields = []
    if "CommonName" in csr_info:
        fields.append(f"*Common Name:*\n{csr_info['CommonName']}")
    if "Lifetime" in csr_info:
        fields.append(f"*Lifetime (days):*\n{csr_info['Lifetime']}")
    if "Purposes" in csr_info:
        fields.append(f"*Purposes:*\n{', '.join(csr_info['Purposes'])}")
    if "SANs" in csr_info and csr_info["SANs"]:
        san_values = [s["value"] if isinstance(s, dict) else str(s) for s in csr_info["SANs"]]
        fields.append(f"*SANs:*\n{', '.join(san_values)}")
    if fields:
        blocks.append(build_fields_block(fields))

    return blocks


def cert_revoked_message(json_data):
    try:
        common_name = json_data["CommonName"]
        serial = json_data["SerialNumber"]
        revoked = json_data["Revoked"].split(".")[0]
    except KeyError:
        return None

    blocks = [build_header_block(f"{slack_bad_emoji} Certificate Revoked")]

    if "Subject" in json_data:
        blocks.append(build_section_block(f"*Subject:* `{json_data['Subject']}`"))

    blocks.append(
        build_fields_block(
            [
                f"*Common Name:*\n{common_name}",
                f"*Serial Number:*\n`{serial}`",
                f"*Revoked:*\n{revoked}",
            ]
        )
    )

    return blocks


# pylint:disable=too-many-branches
def classify_and_build_message(subject, json_data):
    """Classify the SNS message and return (text, blocks).

    Classification uses the SNS subject line as the primary indicator, with
    JSON payload structure as a fallback for disambiguation.
    """
    subject_lower = subject.lower() if subject else ""

    # Try subject-based classification first
    if "revoked" in subject_lower:
        blocks = cert_revoked_message(json_data)
        if blocks:
            return f"{slack_bad_emoji} {subject}", blocks

    if "rejected" in subject_lower:
        blocks = cert_request_rejected_message(json_data)
        if blocks:
            return f"{slack_bad_emoji} {subject}", blocks

    if "expired" in subject_lower:
        blocks = cert_expired_message(json_data)
        if blocks:
            return f"{slack_bad_emoji} {subject}", blocks

    if "expiry" in subject_lower or "expiring" in subject_lower:
        blocks = cert_expiry_warning_message(json_data)
        if blocks:
            return f"{slack_warning_emoji} {subject}", blocks

    if "issued" in subject_lower:
        blocks = cert_issued_message(json_data)
        if blocks:
            return f"{slack_good_emoji} {subject}", blocks

    # Fallback: use JSON payload structure for classification
    if "Reason" in json_data and "CSRInfo" in json_data:
        blocks = cert_request_rejected_message(json_data)
        if blocks:
            return f"{slack_bad_emoji} {subject}", blocks

    if "Revoked" in json_data and "SerialNumber" in json_data:
        blocks = cert_revoked_message(json_data)
        if blocks:
            return f"{slack_bad_emoji} {subject}", blocks

    if "DaysRemaining" in json_data and "CertificateInfo" in json_data:
        days = json_data.get("DaysRemaining", -1)
        if days <= 0:
            blocks = cert_expired_message(json_data)
            emoji = slack_bad_emoji
        else:
            blocks = cert_expiry_warning_message(json_data)
            emoji = slack_warning_emoji
        if blocks:
            return f"{emoji} {subject}", blocks

    if "CertificateInfo" in json_data:
        blocks = cert_issued_message(json_data)
        if blocks:
            return f"{slack_good_emoji} {subject}", blocks

    return None, None


def lambda_handler(event, context):  # pylint:disable=unused-argument
    subject = event["Records"][0]["Sns"]["Subject"]
    message = event["Records"][0]["Sns"]["Message"]
    json_data = json.loads(message)

    text, blocks = classify_and_build_message(subject, json_data)

    if blocks is None:
        logger.warning("Unrecognised notification type, forwarding raw subject: %s", subject)
        text = subject
        blocks = [build_section_block(f"```{json.dumps(json_data, indent=2)[:2900]}```")]

    account_alias = get_account_alias()
    context_parts = [f"*Project:* {project}"]
    if account_alias:
        context_parts.append(f"*Account:* {account_alias}")
    blocks.append(build_divider_block())
    blocks.append(
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": " | ".join(context_parts)}],
        }
    )

    client = WebClient(token=get_slack_token())
    channel_list = slack_channels.split(",")

    for channel in channel_list:
        channel = channel.strip()
        try:
            response = client.chat_postMessage(
                channel=channel,
                text=text,
                username=slack_username,
                blocks=blocks,
            )
            if response["ok"]:
                logger.info("Message sent to %s", channel)
            else:
                logger.error("Failed to send to %s: %s", channel, response.get("error"))
        except SlackApiError as e:
            logger.error("Slack API error for %s: %s", channel, e.response["error"])
        except Exception:
            logger.exception("Error sending to %s", channel)
