{
  "Comment": "Certificate Authority operations",
  "StartAt": "Create Root CA",
  "States": {
    "Create Root CA": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "Payload.$": "$",
        "FunctionName": "arn:aws:lambda:${region}:${account_id}:function:${project}-create-root-ca-${env}:$LATEST"
      },
      "Retry": [
        {
          "ErrorEquals": [
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException",
            "Lambda.SdkClientException",
            "Lambda.TooManyRequestsException"
          ],
          "IntervalSeconds": 2,
          "MaxAttempts": 6,
          "BackoffRate": 2
        }
      ],
      "Next": "Root CA CRL"
    },
    "Root CA CRL": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "InputPath": "$",
      "Parameters": {
        "Payload.$": "$",
        "FunctionName": "arn:aws:lambda:${region}:${account_id}:function:${project}-root-ca-crl-${env}:$LATEST"
      },
      "Retry": [
        {
          "ErrorEquals": [
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException",
            "Lambda.SdkClientException",
            "Lambda.TooManyRequestsException"
          ],
          "IntervalSeconds": 2,
          "MaxAttempts": 6,
          "BackoffRate": 2
        }
      ],
      "Next": "Create Issuing CA"
    },
    "Create Issuing CA": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "InputPath": "$",
      "Parameters": {
        "Payload.$": "$",
        "FunctionName": "arn:aws:lambda:${region}:${account_id}:function:${project}-create-issuing-ca-${env}:$LATEST"
      },
      "Retry": [
        {
          "ErrorEquals": [
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException",
            "Lambda.SdkClientException",
            "Lambda.TooManyRequestsException"
          ],
          "IntervalSeconds": 2,
          "MaxAttempts": 6,
          "BackoffRate": 2
        }
      ],
      "Next": "Issuing CA CRL"
    },
    "Issuing CA CRL": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "InputPath": "$",
      "Parameters": {
        "Payload.$": "$",
        "FunctionName": "arn:aws:lambda:${region}:${account_id}:function:${project}-issuing-ca-crl-${env}:$LATEST"
      },
      "Retry": [
        {
          "ErrorEquals": [
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException",
            "Lambda.SdkClientException",
            "Lambda.TooManyRequestsException"
          ],
          "IntervalSeconds": 2,
          "MaxAttempts": 6,
          "BackoffRate": 2
        }
      ],
      "Next": "File Analysis"
    },
    "File Analysis": {
      "Type": "Map",
      "ItemProcessor": {
        "ProcessorConfig": {
          "Mode": "DISTRIBUTED",
          "ExecutionType": "STANDARD"
        },
        "StartAt": "TLS Certificate",
        "States": {
          "TLS Certificate": {
            "Type": "Task",
            "Resource": "arn:aws:states:::lambda:invoke",
            "OutputPath": "$.Payload",
            "Parameters": {
              "Payload.$": "$",
              "FunctionName": "arn:aws:lambda:${region}:${account_id}:function:${project}-tls-cert-${env}:$LATEST"
            },
            "Retry": [
              {
                "ErrorEquals": [
                  "Lambda.ServiceException",
                  "Lambda.AWSLambdaException",
                  "Lambda.SdkClientException",
                  "Lambda.TooManyRequestsException"
                ],
                "IntervalSeconds": 2,
                "MaxAttempts": 6,
                "BackoffRate": 2
              }
            ],
            "End": true
          }
        }
      },
      "ItemReader": {
        "Resource": "arn:aws:states:::s3:getObject",
        "ReaderConfig": {
          "InputType": "JSON"
        },
        "Parameters": {
          "Bucket": "${internal_s3_bucket}",
          "Key": "tls.json"
        }
      },
      "MaxConcurrency": 1000,
      "Label": "FileAnalysis",
      "End": true
    }
  }
}
