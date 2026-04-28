# Hardcoded Secret

## OWASP CI/CD Category

CICD-SEC-06: Insufficient Credential Hygiene

## CWE

CWE-798: Use of Hard-coded Credentials

## Why It Maps To The CWE

The vulnerable files contain fake test credentials directly in source-controlled scripts and configuration.

## Affected Vulnerable Files

- `vulnerable/deploy.sh`
- `vulnerable/app.env`

## Fixed Files

- `fixed/deploy.sh`
- `fixed/app.env.example`

## Safe Reproduction Steps

Inspect the fake values. They are intentionally invalid examples and are labeled as fake test credentials.

## Expected Insecure Behavior

Committed credential-looking values can be discovered by anyone with repository access and may leak through tooling.

## Secure Remediation

Read secrets from environment variables, GitHub Secrets, or a dedicated secret manager.

## Limitations Of The Scenario

No real credentials are included. The values are fake and must not be used for authentication.
