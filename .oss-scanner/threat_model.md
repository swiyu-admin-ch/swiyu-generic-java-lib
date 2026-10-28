# Threat model: swiyu-generic-java-lib

## What the project is
A set of Java libraries (Maven multi-module, Java 25) for the Swiss SWIYU trust infrastructure: SD-JWT
(build/validate/verify), JWT/JWS/JWE utilities, DPoP, DID resolution, Token Status List and claims path pointers.
They are libraries, not services: there is no network listener in this repository.

## Where untrusted input enters
- JWT / SD-JWT / JWE / DPoP proof strings (including disclosures and key-binding JWTs)
- DID documents and DID log entries fetched by the resolver adapter
- Token Status List tokens (compressed bit lists)
- Claims path pointer expressions

## Ecosystem context (derived from the swiyu e-ID trust infrastructure threat model)
This library is used by the Issuer (https://github.com/swiyu-admin-ch/swiyu-issuer), the Verifier
(https://github.com/swiyu-admin-ch/swiyu-verifier) and Registry-facing components of the swiyu Trust Infrastructure
(STRIDE-based threat model, https://swiyu-admin-ch.github.io/threat-model/). Relevant assumptions and attack-tree branches:
- Attackers are computationally bounded and cannot break cryptographic primitives; TLS 1.3, the TEE, the OS and
  the device are assumed trustworthy. Findings that require breaking these assumptions are out of scope.
- **Circumvent verification (3.1):** a wallet must not be able to make an invalid VP appear valid. This is the
  central goal for the SD-JWT / JWT / DPoP validation and verification modules.
- **Change sent VC / credential request (3.3, 3.4):** tampering with a credential or credential request
  (e.g. removing the holder-binding requirement) must be detected.
- **Spoof communication partner / impersonate issuer or holder (2.4, 3.2.2, 3.2.3):** issuer identity (DID resolution,
  key lookup) and holder binding (key-binding JWT, DPoP) must be validated strictly.
- **Malicious requests (2.2.2):** crashes, out-of-memory or CPU loops caused by crafted input (e.g. JWE decompression,
  status list expansion, deeply nested JSON) are denial-of-service findings.
- **Design/implementation flaws and insecure use of libraries (2.2, 2.2.5):** wrong defaults or easy-to-misuse APIs count.
- **Unallowed change of swiyu managed content (2.3):** manipulated registry/DID/status list content must not be
  accepted without integrity and authenticity checks.
- **Supply chain (2.2.1):** vulnerable or malicious dependencies matter only when reachable from this library.
- **Privacy (4.x):** the library should not leak or log holder data and should not introduce tracking identifiers
  (e.g. stable status list index/URI exposure beyond what the specification requires).

## Security goals / what we care about (draft, to be confirmed by security)
- Signature, issuer, holder-binding and DPoP validation must not be bypassable (algorithm confusion, `none`, missing checks).
- Resource exhaustion from small inputs (e.g. decompression bombs in JWE / status lists, unbounded recursion).
- Cryptographic misuse (weak algorithms, insecure randomness, key handling).
- Parser flaws (JSON/Base64 handling, path expression parsing).
- Privacy: no leakage of holder data via logs, errors or tracking identifiers.

## Severity guidance (draft, to be confirmed by security)
- Critical: validation bypass accepting a forged or tampered credential/token/proof.
- High: memory/CPU exhaustion from a small attacker-controlled input; leakage of key material.
- Medium: incorrect rejection/acceptance in non-security-critical validation steps; DoS requiring unusual inputs.
- Low: hardening issues without a demonstrated exploit.

## Out of scope
- Test code, build scripts and CI configuration.
- Vulnerabilities in third-party dependencies without a reachable path from this library.
- Misconfiguration by the embedding application.
- Availability of external services (registries, DNS, attestation services), wallet/device security, social engineering,
  and organisational topics (support, backups, recovery, internal leaks) from the ecosystem threat model.
