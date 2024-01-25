from boto3 import client


def get_dynamo_db_table():
    """
    ARN and name of DynamoDB table
    """

    dynamodb_client = client("dynamodb")

    tables = dynamodb_client.list_tables()["TableNames"]
    table = [t for t in tables if "CA" in t]

    return table[0]


def delete_dynamo_db_table_items(table):
    """
    Delete all items from DynamoDB table
    """

    dynamodb_client = client("dynamodb")

    items = dynamodb_client.scan(TableName=table, Limit=500, Select="ALL_ATTRIBUTES")["Items"]

    for item in items:
        serial_number = item["SerialNumber"]["S"]  # sort key
        common_name = item["CommonName"]["S"]  # partition key
        print(f"Deleting DynamoDB item certificate serial number {serial_number}")
        composite_key_json = {"SerialNumber": {"S": serial_number}, "CommonName": {"S": common_name}}
        dynamodb_client.delete_item(TableName=table, Key=composite_key_json)


if __name__ == "__main__":
    table = get_dynamo_db_table()
    print(f"Deleting items from {table}...")
    delete_dynamo_db_table_items(table)
    print(f"Items from {table} deleted successfully")
