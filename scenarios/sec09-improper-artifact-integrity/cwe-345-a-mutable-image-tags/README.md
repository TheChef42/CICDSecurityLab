# Mutable Image Tags

## OWASP CI/CD Category

CICD-SEC-09: Improper Artifact Integrity Validation

## CWE

CWE-345: Insufficient Verification of Data Authenticity

## Why It Maps To The CWE

The vulnerable files reference images with `:latest`, which is mutable and does not identify a specific artifact. CWE-345 is broad, but it fits because the pipeline accepts image identity without sufficient authenticity verification.

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
