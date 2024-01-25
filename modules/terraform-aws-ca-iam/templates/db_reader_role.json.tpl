{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "AWS": ${jsonencode(aws_principals)}
      },
      "Effect": "Allow",
      "Sid": "AssumeRoleFromAWSPrincipals"
    }
  ]
}