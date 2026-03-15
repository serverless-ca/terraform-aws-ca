{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "WriteToCloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": [
        "arn:aws:logs:${region}:${account_id}:log-group:/aws/lambda/${project}-${lambda_function_name}-${env}:*"
      ]
    },
    {
      "Sid": "KMSDecryptSecret",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
      ],
      "Resource": "${kms_arn_resource}"
    },
    {
      "Sid": "SlackOAuthSecret",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "${secret_arn}"
    },
    {
      "Sid": "GetAccountName",
      "Effect": "Allow",
      "Action": [
        "iam:ListAccountAliases"
      ],
      "Resource": "*"
    }
  ]
}
