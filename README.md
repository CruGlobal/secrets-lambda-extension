# secrets-lambda-extension
This is an internal lambda extension used to modify the lambda runtime process by adding environment variables (`secrets`)
defined in AWS SSM Parameter Store to the function's environment.

This extension requires the Lambda be defined with the [aws/lambda/app](https://github.com/CruGlobal/cru-terraform-modules/tree/main/aws/lambda/app) Terraform Module. This will ensure the
correct permissions and ENV variables to retrieve the secrets.

## Which parameters it loads

By default it loads **every** parameter under `/ecs/<PROJECT_NAME>/<env>/`, where `<env>` is `prod` for
`ENVIRONMENT=production`, `stage` for `staging`, and `lab` for anything else. It adds each one to the function's
environment, named by the part of the parameter name after that path. A name that isn't a valid shell variable name is
skipped. To load only some of them, set `SECRETS_PARAMETERS` (below).

### Loading only named parameters: `SECRETS_PARAMETERS`

Set `SECRETS_PARAMETERS` to a comma-separated list of parameter names, the part after `/ecs/<PROJECT_NAME>/<env>/`:

```
SECRETS_PARAMETERS=DATABASE_URL,API_KEY
```

It is meant for a function with its own IAM role that may call `ssm:GetParameters` on only its listed parameters and
can't read the whole path. When it is set, the extension:

- fetches exactly `/ecs/<PROJECT_NAME>/<env>/<NAME>` for each name with `GetParameters`, 10 names per call, and never
  reads by path;
- trims spaces around each name and ignores empty entries and repeats;
- loads nothing when the value is `none` or empty. A function that has its own role but no parameters uses `none`, so it
  still never reads by path;
- refuses to start when a name isn't a valid shell variable name, when a listed parameter doesn't exist, or when the
  role can't read one (AccessDenied). The error names the parameters, never their values, and shows in the function's
  log as `Failed to retrieve secrets: ...`, the same as any other SSM error.

Each parameter it loads lands in the environment under the same name, and is cached the same way, as in the default
mode. Leave `SECRETS_PARAMETERS` unset to keep loading every parameter under the path.

It does **not** read a parameter's `param_type` tag (`RUNTIME`, `BUILD` or `ALL`). It used to, but that took one
`ListTagsForResource` call per parameter on every cold start, and busy functions hit the API's rate limit and failed to
start (changed in v1.0.1, #7). So a parameter tagged `BUILD` is loaded too. Under pipeline v2 that path holds runtime
values only: build-time secrets are repository secrets named `BUILD_<NAME>`, not parameters.

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