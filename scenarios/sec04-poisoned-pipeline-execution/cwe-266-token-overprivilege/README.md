# Incorrect Privilege Assignment

## OWASP CI/CD Category

CICD-SEC-04: Poisoned Pipeline Execution

## CWE

CWE-266: Incorrect Privilege Assignment

## Why It Maps To The CWE

The vulnerable workflow grants `permissions: write-all`, assigning the CI token broader privileges than the build job needs. This maps to CWE-266 because the weakness is an incorrect assignment of privilege in the workflow configuration.

## Affected Vulnerable Files

- `vulnerable/build.yml`

## Fixed Files

- `fixed/build.yml`

## Safe Reproduction Steps

Inspect the workflow permissions. The workflow contains only harmless build commands.

## Expected Insecure Behavior

If abused, the workflow token would have unnecessary write permissions.

## Secure Remediation

Set explicit least-privilege permissions, for example `contents: read`.

## Limitations Of The Scenario

The lab does not run a GitHub workflow or perform write operations.
