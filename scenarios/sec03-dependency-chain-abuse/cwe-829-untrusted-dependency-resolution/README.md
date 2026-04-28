# Untrusted Dependency Resolution

## OWASP CI/CD Category

CICD-SEC-03: Dependency Chain Abuse

## CWE

CWE-829: Inclusion of Functionality from Untrusted Control Sphere

## Why It Maps To The CWE

The vulnerable package manifest omits a lockfile. Absence of a lockfile is not dependency confusion by itself, but it allows CI runners to resolve package versions from a registry without deterministic integrity protection.

## Affected Vulnerable Files

- `vulnerable/package.json`
- `vulnerable/install-dependencies.sh`

## Fixed Files

- `fixed/package.json`
- `fixed/package-lock.json`
- `fixed/install-dependencies.sh`

## Safe Reproduction Steps

Inspect the vulnerable folder and note that `package.json` exists without `package-lock.json`. No package installation is required.

## Expected Insecure Behavior

The CI install step uses `npm install`, allowing dependency resolution to change over time.

## Secure Remediation

Commit a lockfile, pin dependency versions, and use `npm ci` in CI.

## Limitations Of The Scenario

The example demonstrates the enabling condition for untrusted dependency resolution. It does not publish or install a malicious package.
