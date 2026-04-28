# Insecure Container Default

## OWASP CI/CD Category

CICD-SEC-07: Insecure System Configuration

## CWE

CWE-16: Configuration

## Why It Maps To The CWE

The Dockerfile omits a `USER` directive, so the container defaults to root. CWE-16 is broad, but it is suitable here because the weakness is an insecure configuration default rather than a language-specific coding flaw.

## Affected Vulnerable Files

- `vulnerable/Dockerfile`

## Fixed Files

- `fixed/Dockerfile`

## Safe Reproduction Steps

Inspect the Dockerfiles. Building the images is optional.

## Expected Insecure Behavior

The vulnerable container runs processes as root by default.

## Secure Remediation

Create a non-root account and set `USER` before runtime commands execute.

## Limitations Of The Scenario

The example does not run privileged containers or interact with the host.
