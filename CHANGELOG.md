# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.7.0] – 2026-07-08
- Separate header from body claims in trust-statement so that header claims and body claims can be distinguished and validated independently
- JWKSet no longer used for signature checks for jwt via DidDocument, instead use the JWK from keys directly.

## [1.6.2] – 2026-06-03
- Bump didresolver to 2.8.0 for security updates.

---

## [1.6.1] – 2026-05-18

### Fixed
- `swiyu-did-resolver-adapter`: bump tomcat version to 11.0.22 for security updates.

---

## [1.6.0] – 2026-05-15

### Fixed
- `swiyu-dpop-util`: Enhance htu validation to handle reverse proxy path stripping (#971).

---

## [1.5.0] – 2026-05-06

### Added

- **`swiyu-jwt-validator`** (new library): Centralized, framework-agnostic JWT validation for the swiyu ecosystem. Enforces absolute `kid`, ignores `iss` claim, validates Base Registry allowlist, and checks `exp`/`nbf` with configurable clock skew tolerance (#872).
- **`swiyu-sdjwt-validator`** (new library): SD-JWT VC validation per Swiss Profile (RFC 9901). Enforces `typ: dc+sd-jwt`, `_sd_alg: sha-256`, and prohibits registered claims in Disclosures (#872).
- `swiyu-claims-path-pointer-util`: Manifest info with version added to built JARs (#896).

### Changed

- Updated Bouncy Castle to `1.84`.
- Updated Spring Boot version due to CVE.
- Updated aggregator `swiyu-generic-java-all` to include all current libraries.

### Fixed

- `swiyu-dpop-util`: Allow more flexibility in path for `htu` comparison (#941).
- `swiyu-claims-path-pointer-util`: Sanitize requested values before validating against claims (#847).
- `swiyu-ts-builder`: Changed protected methods to public in `AbstractTrustStatementBuilder`.

### Removed

- Removed `swiyu-client-attestation-validator` library (#956).

---

## 1.4.0

### Added
- `swiyu-claims-path-pointer-util`: Utility for validating and flattening claims paths (EIDOMNI-847).
- Manifest info with version added to built JARs (EIDOMNI-896).

### Changed
- Updated Bouncy Castle to `1.84`.
- Updated `commons-lang3` to `3.20.0`.

### Fixed
- Sanitize requested values before validating against claims (EIDOMNI-847).
- Rename `validateRequestedClaim` to `validateRequestedClaims` and enhance number validation.

