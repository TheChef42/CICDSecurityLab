# Token Over-privilege

## OWASP CI/CD Category

CICD-SEC-04: Poisoned Pipeline Execution

## CWE

CWE-269: Improper Privilege Management

## Why It Maps To The CWE

The vulnerable workflow grants `permissions: write-all`, giving the CI token broad write access when the build job only needs read access.

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
