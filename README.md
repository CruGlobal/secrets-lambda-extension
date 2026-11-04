# secrets-lambda-extension
This is an internal lambda extension used to modify the lambda runtime process by adding environment variables (`secrets`)
defined in AWS SSM Parameter Store to the function's environment.

This extension requires the Lambda be defined with the [aws/lambda/app](https://github.com/CruGlobal/cru-terraform-modules/tree/main/aws/lambda/app) Terraform Module. This will ensure the
correct permissions and ENV variables to retrieve the secrets. All secrets with `RUNTIME` or `ALL` visibility will be
added to the execution environment of the Lambda function.

## Usage
Add to the Lambda Dockerfile using Multi-Stage build:
```dockerfile
# Download and extract the secrets-lambda-extension
FROM public.ecr.aws/docker/library/alpine:latest AS extension
# Deliberately tracks the LATEST extension release (pinned versions rotted in
# Dockerfiles fleet-wide; under build-once the artifact itself is the pin and a
# bad release is caught on the release-candidate surface). Resolve `latest`
# once, record what was baked, then fetch that exact version.
RUN apk add --no-cache curl && \
    mkdir -p /opt/secrets-lambda-extension && \
    version=$(curl -fsIL -o /dev/null -w '%{url_effective}' https://github.com/CruGlobal/secrets-lambda-extension/releases/latest | sed 's|.*/tag/||') && \
    echo "secrets-lambda-extension: ${version}" && \
    echo "${version}" > /opt/secrets-lambda-extension/VERSION && \
    wget "https://github.com/CruGlobal/secrets-lambda-extension/releases/download/${version}/secrets-lambda-extension-linux-amd64.tar.gz" -q -O - |tar -xzC /opt/secrets-lambda-extension/

# Copy the secrets-lambda-extension from the extension stage
COPY --from=extension /opt/secrets-lambda-extension /opt/secrets-lambda-extension
ENV AWS_LAMBDA_EXEC_WRAPPER=/opt/secrets-lambda-extension/secrets-wrapper
```

This is the same block the Lambda stacks in [cru-app-template](https://github.com/CruGlobal/cru-app-template) use, so new apps
already get it. `/opt/secrets-lambda-extension/VERSION` records which release an image carries.

If you pin a version instead, use v1.0.3 or later. v1.0.0 and v1.0.1 exit at startup when `BUILD_NUMBER` is not set,
which pipeline v2 images don't set, and v1.0.2 can print a secret into the logs when a parameter name is not a valid
shell identifier (fixed in v1.0.3).

### Reference
- [AWS Lambda Wrappers](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-modify.html)