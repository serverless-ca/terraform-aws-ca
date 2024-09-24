terraform {
  backend "s3" {
    # Replace this with your bucket name!
    bucket         = "YOUR S3 BUCKET STATE"
    key            = "global/s3/terraform.tfstate"
    region         = "YOUR S3 BUCKET REGION"

    # Replace this with your DynamoDB table name!
    dynamodb_table = "my-running-locks"
    encrypt        = true
  }
}
