{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "KMSforEncryptedResources",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
      ],
      "Resource": "${kms_arn_resource}"
    },
    {
      "Sid": "DynamoDBReader",
      "Effect": "Allow",
      "Action": [
        "dynamodb:DescribeTable",
        "dynamodb:GetItem",
        "dynamodb:Query",
        "dynamodb:Scan"
      ],
      "Resource": [
        "${ddb_table_arn}"
      ]
    }
  ]
}