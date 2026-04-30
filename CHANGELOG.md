# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## next – [1.5.0]

### Added

#### `swiyu-jwt-validator` (new library)

A new centralized, framework-agnostic Java library for DID-based JWT validation in the swiyu
ecosystem (#872). Implements PARENT-ADR-027 and PARENT-ADR-035.

**Core components:**

- **`DidJwtValidator`** – Main facade orchestrating the full validation flow.
  Supports two usage patterns:
  - *Flow B (two-step)*: `getAndValidateResolutionUrl()` returns the validated DID URL for the
    caller to fetch; `validateJwt(jwt, DidDoc)` verifies the signature against the pre-fetched
    DID Document.
  - *Flow A (JWK set)*: `validateJwt(jwt, JWKSet)` for use-cases where the JWK set is already
    available (e.g. Trust Statements).
  - `getDidString(jwt)` – convenience method to extract the DID string from the JWT `kid`
    header, avoiding redundant re-parsing when calling `resolveDid()` after
    `getAndValidateResolutionUrl()`.

  **Security rules enforced unconditionally:**
  - JWTs without an absolute `kid` header are rejected.
  - The `iss` claim is never validated – trust is established exclusively via the `kid`.
  - The resolved DID URL must match the configured Base Registry allowlist.

- **`UrlRestriction`** – Enforces a host allowlist (Base Registry whitelist) to prevent
  CSRF and "phone home" attacks. Validates DID URLs and Status List URLs before any
  network call. Throws `IllegalArgumentException` on construction if the allowlist is
  `null` or empty to prevent silent misconfigurations.

- **`DidKidParser`** – Parses the `kid` from the JWT header and extracts the DID string
  via the `didresolver` native library (`ch.admin.swiyu:didresolver`) – without any
  network calls and without manual `#`-splitting in application code.

- **`JwtValidatorException`** – Unified unchecked runtime exception wrapping all
  underlying technical errors (`ParseException`, `JOSEException`, `DidResolverException`,
  etc.) for simplified error handling in consuming components.

**Dependencies:** `swiyu-did-resolver-adapter`, `swiyu-jwt-util`, `didresolver`

---

#### `swiyu-sdjwt-validator` (new library)

A new library for SD-JWT VC validation according to the Swiss Profile VC specification
(RFC 9901 / #872). Builds on top of `swiyu-jwt-validator`.

**Core components:**

- **`SdJwtVcValidator`** – Validates SD-JWT VC tokens with Swiss Profile specific rules:
  - `typ` JOSE header must be `dc+sd-jwt` (configurable for migration phase via constructor
    accepting a `Set<String>` of accepted values, e.g. also `vc+sd-jwt`).
  - `_sd_alg` claim must be `sha-256`.
  - Registered claims (`iss`, `nbf`, `exp`, `iat`, `cnf`, `vct`, `vct#integrity`, `status`,
    `vct_metadata_uri`, `vct_metadata_uri#integrity`, `_sd`, `_sd_alg`) MUST NOT appear in
    any Disclosure (RFC 9901 §3.2.2.2).
  - Signature verification delegated to `DidJwtValidator`.
  - Exposes the same two-step Flow B via `getAndValidateResolutionUrl()` for consistent
    HTTP-fetch separation.

- **`SdJwtParser`** – Utility for splitting the SD-JWT compound string into its components
  (Issuer-Signed JWT, Disclosures, optional Key Binding JWT) and Base64url-decoding
  individual Disclosures.

**Dependencies:** `swiyu-jwt-validator`

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

