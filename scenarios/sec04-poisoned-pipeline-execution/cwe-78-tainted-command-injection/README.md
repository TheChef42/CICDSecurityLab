# Tainted Command Injection

## OWASP CI/CD Category

CICD-SEC-04: Poisoned Pipeline Execution

## CWE

CWE-78: Improper Neutralization of Special Elements used in an OS Command

## Why It Maps To The CWE

The vulnerable workflow places an untrusted GitHub issue title directly into a shell command. In a real pipeline, attacker-controlled text could alter command behavior.

## Affected Vulnerable Files

- `vulnerable/issue-title-search.yml`

## Fixed Files

- `fixed/issue-title-search.yml`

## Safe Reproduction Steps

Inspect the workflow YAML. The demonstrated commands use harmless `echo` and `grep` examples only.

## Expected Insecure Behavior

The shell receives untrusted event text as part of the command body.

## Secure Remediation

Pass untrusted values through environment variables, validate allowed characters, quote arguments, and prefer commands that avoid shell evaluation.

## Limitations Of The Scenario

The workflow is not executed by the lab and does not perform dangerous operations.
