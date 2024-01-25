{
  "Id": "secure-transport-${bucket_name}",
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSSLRequestsOnly",
      "Action": "s3:*",
      "Effect": "Deny",
      "Resource": [
        "arn:aws:s3:::${bucket_name}",
        "arn:aws:s3:::${bucket_name}/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      },
      "Principal": "*"
    },
    {
      "Sid": "Object access from app environment",
      "Effect": "Allow",
      "Principal": {
         "AWS": ${jsonencode(app_aws_principals)}
      },
      "Action": [
         "s3:GetObject",
         "s3:GetObjectAcl",
         "s3:GetObjectAttributes",
         "s3:GetObjectRetention",
         "s3:GetObjectTagging",
         "s3:GetObjectVersion",
         "s3:GetObjectVersionTagging"
      ],
      "Resource": "arn:aws:s3:::${bucket_name}/*"
    },
    {
      "Sid": "Bucket level access from app environment",
      "Effect": "Allow",
      "Principal": {
         "AWS": ${jsonencode(app_aws_principals)}
      },
      "Action": [
         "s3:GetEncryptionConfiguration",
         "s3:GetBucketWebsite",
         "s3:GetBucketLocation",
         "s3:GetBucketObjectLockConfiguration",
         "s3:ListBucket"
      ],
         "Resource": "arn:aws:s3:::${bucket_name}"
    }
  ]
}