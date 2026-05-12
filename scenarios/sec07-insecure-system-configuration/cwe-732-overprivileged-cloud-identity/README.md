# Incorrect Permission Assignment for Critical Resource

## OWASP CI/CD Category

CICD-SEC-07: Insecure System Configuration

## CWE

CWE-732: Incorrect Permission Assignment for Critical Resource

## Why It Maps To The CWE

The vulnerable Terraform assigns an administrator policy to a CI/CD role. This maps to CWE-732 because a critical pipeline resource receives broader permissions than it needs.

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
