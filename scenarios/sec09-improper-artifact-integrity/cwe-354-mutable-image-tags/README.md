# Improper Validation of Integrity Check Value

## OWASP CI/CD Category

CICD-SEC-09: Improper Artifact Integrity Validation

## CWE

CWE-354: Improper Validation of Integrity Check Value

## Why It Maps To The CWE

The vulnerable files reference images with `:latest`, which is mutable and does not validate an immutable integrity value such as a SHA-256 image digest. This maps to CWE-354 because the pipeline accepts the artifact reference without properly validating an integrity check value.

## Affected Vulnerable Files

- `vulnerable/Dockerfile`
- `vulnerable/docker-compose.yml`

## Fixed Files

- `fixed/Dockerfile`
- `fixed/docker-compose.yml`

## Safe Reproduction Steps

Inspect the image references. Pulling or running the images is not required.

## Expected Insecure Behavior

The same tag may point to different image content over time.

## Secure Remediation

Use immutable image digests such as `image@sha256:<digest>`.

## Limitations Of The Scenario

The fixed digest is a realistic placeholder for demonstration and may not resolve to a real image.
