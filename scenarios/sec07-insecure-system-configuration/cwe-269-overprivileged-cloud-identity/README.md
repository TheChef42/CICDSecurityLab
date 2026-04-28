# Overprivileged Cloud Identity

## OWASP CI/CD Category

CICD-SEC-07: Insecure System Configuration

## CWE

CWE-269: Improper Privilege Management

## Why It Maps To The CWE

The vulnerable Terraform assigns an administrator policy to a CI/CD role, granting more privilege than the pipeline requires.

## Affected Vulnerable Files

- `vulnerable/main.tf`

## Fixed Files

- `fixed/main.tf`

## Safe Reproduction Steps

Inspect the Terraform files only. Do not run `terraform apply`; no cloud credentials are needed.

## Expected Insecure Behavior

A CI/CD identity would receive administrative cloud access.

## Secure Remediation

Use narrowly scoped IAM policies that allow only the required actions and resources.

## Limitations Of The Scenario

The Terraform is local demonstration code and is not applied to a real cloud account.
