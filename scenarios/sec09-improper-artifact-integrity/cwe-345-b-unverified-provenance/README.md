# Unverified Provenance

## OWASP CI/CD Category

CICD-SEC-09: Improper Artifact Integrity Validation

## CWE

CWE-345: Insufficient Verification of Data Authenticity

## Why It Maps To The CWE

The vulnerable deployment script accepts a local artifact without requiring a provenance file, signature, attestation, or trusted builder identity. CWE-345 is appropriate because the artifact's authenticity is not sufficiently verified.

## Affected Vulnerable Files

- `vulnerable/deploy-artifact.sh`
- `vulnerable/artifact.txt`

## Fixed Files

- `fixed/deploy-artifact.sh`
- `fixed/artifact.txt`
- `fixed/provenance.json`

## Safe Reproduction Steps

Run the scripts only against the local mock artifact if desired. No external service or signing infrastructure is used.

## Expected Insecure Behavior

The vulnerable script deploys the artifact even when provenance is missing.

## Secure Remediation

Require provenance metadata, verify the artifact digest, check the trusted builder identity, and fail closed.

## Limitations Of The Scenario

The fixed example uses a local mock provenance file instead of real Sigstore, SLSA, or GPG verification.
