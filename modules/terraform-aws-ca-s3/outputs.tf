output "s3_bucket_name" {
  value = aws_s3_bucket.bucket.id
}
output "s3_bucket_arn" {
  value = aws_s3_bucket.bucket.arn
}

output "s3_bucket_domain_name" {
  value = aws_s3_bucket.bucket.bucket_domain_name
}

output "s3_bucket_regional_domain_name" {
  value = aws_s3_bucket.bucket.bucket_regional_domain_name
}
