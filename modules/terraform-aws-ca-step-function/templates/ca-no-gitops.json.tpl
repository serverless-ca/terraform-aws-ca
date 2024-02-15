{
  "Comment": "Certificate Authority operations GitOps disabled",
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
      "End": true
    }
  }
}
