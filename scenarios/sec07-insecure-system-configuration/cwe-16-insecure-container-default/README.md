# Insecure Container Default

## OWASP CI/CD Category

CICD-SEC-07: Insecure System Configuration

## CWE

CWE-250: Execution with Unnecessary Privileges

## Why It Maps To The CWE

The Dockerfile omits a `USER` directive, so the container defaults to root. This maps to CWE-250 because the build container executes with privileges that are not required for the demonstrated CI task.

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
