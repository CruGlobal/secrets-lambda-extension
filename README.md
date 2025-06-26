# secrets-lambda-extension
This is an internal lambda extension used to modify the lambda runtime process by adding environment variables (`secrets`)
defined in AWS SSM Parameter Store to the node environment.

This extension requires the Lambda be defined with the [aws/lambda/app](https://github.com/CruGlobal/cru-terraform-modules/tree/main/aws/lambda/app) Terraform Module. This will ensure the
correct permissions and ENV variables to retrieve the secrets. All secrets with `RUNTIME` or `ALL` visibility will be
added to the execution environment of the Lambda function.

## Usage
Add to the Lambda Dockerfile using Multi-Stage build:
```dockerfile
# Download and extract the secrets-lambda-extension
FROM alpine:latest AS extension
RUN mkdir -p /opt/secrets-lambda-extension && \
    wget https://github.com/CruGlobal/secrets-lambda-extension/releases/download/v1.0.0/secrets-lambda-extension-linux-amd64.tar.gz -q -O - |tar -xzC /opt/secrets-lambda-extension/

# Copy the secrets-lambda-extension from the extension stage
COPY --from=extension /opt/secrets-lambda-extension /opt/secrets-lambda-extension
ENV AWS_LAMBDA_EXEC_WRAPPER=/opt/secrets-lambda-extension/secrets-wrapper
```

### Reference
- [AWS Lambda Wrappers](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-modify.html)