provider "aws" {
  region = "eu-west-1"
}

provider "aws" {
  region = "us-east-1"
  alias = "us-east-1"
}

provider "aws" {
  alias      = "eu-west-1"
  region     = "eu-west-1"
  sts_region = "eu-west-1"
}
