# swiyu-sdjwt-verifier (draft)

**This library is not yet production-ready and is still under development. Therefore, this library should not be used anywhere yet.**

Validates SD-JWT VC tokens according to the **Swiss Profile VC specification** (RFC 9901).

Delegates DID-based signature verification to [`swiyu-jwt-validator`](../swiyu-jwt-validator).
Companion library to [`swiyu-sdjwt-builder`](../swiyu-sdjwt-builder), which creates the tokens
validated here. Shared constants live in [`swiyu-sdjwt-util`](../swiyu-sdjwt-util).

## Features

| Rule | Enforced by |
|---|---|
| `typ` header must be one of `dc+sd-jwt` / `vc+sd-jwt` (migration phase) | `SdJwtParser` |
| `_sd_alg` = `sha-256` | `SdJwtVcValidator` |
| Registered claims NOT in Disclosures (`iss`, `nbf`, `exp`, `iat`, `cnf`, `vct`, `vct#integrity`, `status`, `vct_metadata_uri`, `vct_metadata_uri#integrity`, `_sd`, `_sd_alg`) | `SdJwtParser` |
| Key Binding JWT freshness & audience check (RFC 9901 §7.3) | `SdJwtVcValidator` |
| DID-based signature verification | delegated to `swiyu-jwt-validator` |

## Installation

```xml
<dependency>
    <groupId>ch.admin.swiyu</groupId>
    <artifactId>swiyu-sdjwt-verifier</artifactId>
    <version>3.0.0</version>
</dependency>
```

## Usage

```java
private Map<String, Object> verifySdJwt(String serializedSdJwt, JWK issuerJwk) throws SdJwtParseException, SdJwtVerificationException {
    // Must have a DidJwtValidator configured with an accepted Base Registry allowlist
    SdJwtVcValidator validator = new SdJwtVcValidator(didJwtValidator);

    SdJwt sdJwt = SdJwtParser.parseSdJwt(serializedSdJwt);
    // Required for the header to become available on sdJwt
    validator.validateHeader(sdJwt);

    // issuerJwk is resolved by the caller, e.g. via the DID Document for sdJwt.getHeader().getKeyID()
    validator.validateJwt(sdJwt, issuerJwk);

    if (sdJwt.hasKeyBinding()) {
        validator.validateKeyBinding(sdJwt, audience, nonce, acceptableProofTimeWindowSeconds);
    }
    // If necessary, validate Token Status List or Trust Statements here, using sdJwt.getClaims()

    // Resolves the Disclosures and returns the plain claim map (issuer- and holder-provided claims combined)
    return validator.processDisclosures(sdJwt);
}
```

See [`SdJwtUsageTest`](src/test/java/ch/admin/bj/swiyu/sdjwtverifier/SdJwtUsageTest.java) for a complete, runnable round-trip example (creation via `swiyu-sdjwt-builder`, Key Binding, verification).

## Dependency Graph

```
swiyu-sdjwt-verifier
  ├── swiyu-sdjwt-util
  └── swiyu-jwt-validator
        ├── swiyu-jwt-util
        └── didresolver (native)
```

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.
