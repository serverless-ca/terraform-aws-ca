{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowCloudFront",
            "Effect": "Allow",
            "Principal": {
                "AWS": "${oai_arn}"
            },
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::${bucket_name}/*"
        }
    ]
}