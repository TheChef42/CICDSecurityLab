# Integrity Omission

## OWASP CI/CD Category

CICD-SEC-03: Dependency Chain Abuse

## CWE

CWE-494: Download of Code Without Integrity Check

## Why It Maps To The CWE

The vulnerable example shows the `curl | sh` style of pipeline bootstrap where code is executed without first validating a checksum, digest, or signature. The local script is harmless, but the pattern represents execution of downloaded code without authenticity or integrity verification.

## Affected Vulnerable Files

- `vulnerable/install-unverified.sh`
- `vulnerable/remote-install-example.sh`

## Fixed Files

- `fixed/install-verified.sh`
- `fixed/trusted-install.sh`
- `fixed/trusted-install.sh.sha256`

## Safe Reproduction Steps

Review or run `vulnerable/install-unverified.sh`. It executes only the local mock installer in this folder and does not contact a network endpoint.

## Expected Insecure Behavior

The vulnerable flow executes a script without proving that the script is the expected artifact.

## Secure Remediation

Verify a SHA-256 checksum, signature, or digest before execution. Fail closed if verification fails.

## Limitations Of The Scenario

The unsafe download is shown as a commented pattern and simulated with a local script so the lab never executes remote code.
