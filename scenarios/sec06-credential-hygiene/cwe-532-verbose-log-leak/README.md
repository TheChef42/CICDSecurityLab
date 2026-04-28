# Verbose Log Leak

## OWASP CI/CD Category

CICD-SEC-06: Insufficient Credential Hygiene

## CWE

CWE-532: Insertion of Sensitive Information into Log File

## Why It Maps To The CWE

The vulnerable workflow enables shell tracing and dumps environment variables. In real CI logs, this can expose secret values.

## Affected Vulnerable Files

- `vulnerable/debug-workflow.yml`

## Fixed Files

- `fixed/debug-workflow.yml`

## Safe Reproduction Steps

Inspect the workflow. The secret-like value is fake test data only.

## Expected Insecure Behavior

Debug logs could include sensitive environment values.

## Secure Remediation

Avoid `set -x`, `env`, and `printenv` around secrets. Mask sensitive values and log only required non-sensitive fields.

## Limitations Of The Scenario

The workflow is not executed by the lab, and the exposed value is fake.
