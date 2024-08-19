import boto3
import json


def publish_to_sns(json_data, subject, sns_topic_arn, keys_to_publish="All"):
    # Filter out unwanted keys
    if keys_to_publish == "All":
        keys_to_publish = json_data.keys()

    filtered_json_data = {key: json_data[key] for key in keys_to_publish if key in json_data}

    client = boto3.client("sns")

    response = client.publish(
        TargetArn=sns_topic_arn,
        Subject=subject,
        Message=json.dumps({"default": json.dumps(filtered_json_data)}),
        MessageStructure="json",
    )

    return response
