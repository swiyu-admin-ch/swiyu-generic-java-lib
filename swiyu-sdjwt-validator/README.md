# swiyu-sdjwt-validator (draft)

**This library is not yet production-ready and is still under development. Therefore, this library should not be used anywhere yet.**

Creates and validates SD-JWT VC tokens according to the **Swiss Profile VC specification** (RFC 9901).

Delegates DID-based signature verification to [`swiyu-jwt-validator`](../swiyu-jwt-validator).

## Features

| Rule | Enforced by |
|---|---|
| `typ` header must be one of `dc+sd-jwt` / `vc+sd-jwt` (migration phase) | `SdJwtParser` |
| `_sd_alg` = `sha-256` | `SdJwtVcValidator` (verification) |
| Registered claims NOT in Disclosures (`iss`, `nbf`, `exp`, `iat`, `cnf`, `vct`, `vct#integrity`, `status`, `vct_metadata_uri`, `vct_metadata_uri#integrity`, `_sd`, `_sd_alg`) | `SdJwtParser` (verification) / `RecursiveDisclosureUtil` (creation) |
| Key Binding JWT freshness & audience check (RFC 9901 §7.3) | `SdJwtVcValidator` |
| DID-based signature verification | delegated to `swiyu-jwt-validator` |

## Installation

```xml
<dependency>
    <groupId>ch.admin.swiyu</groupId>
    <artifactId>swiyu-sdjwt-validator</artifactId>
    <version>2.1.0-SNAPSHOT</version>
</dependency>
```

## Usage

### Creation

```java
Map<SdJwtVcClaim, Object> vcClaims = Map.of(
    SdJwtVcClaim.ISSUER, "did:webvh:scid:example.com",
    SdJwtVcClaim.VCT, "ch.swiyu.test");
Map<String, Object> credentialSubjectClaims = Map.of("name", "Bob", "surname", "Builder");

TimeConfiguration timeConfig = TimeConfiguration.builder()
    .expiry(Optional.of(Instant.now().plus(1, ChronoUnit.DAYS)))
    .build();

SdJwtVcBuilder builder = SdJwtVcBuilder.createBuilder(
    "did:webvh:scid:example.com#key-1", vcClaims, credentialSubjectClaims, timeConfig, myNimbusJWSSigner);

CreatedSdJwtVc signed = builder.createSignedSdJwtVc(
    Optional.of(new TokenStatusListReferenceData(1, "https://www.example.com/status/1")),
    Optional.of(holderPublicJwk)); // omit if no Key Binding is required

String serialized = signed.serializedSdJwt();
```

### Verification

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

See [`SdJwtUsageTest`](src/test/java/ch/admin/bj/swiyu/sdjwtvalidator/SdJwtUsageTest.java) for a complete, runnable round-trip example (creation, Key Binding, verification).

## Dependency Graph

```
swiyu-sdjwt-validator
  └── swiyu-jwt-validator
        ├── swiyu-jwt-util
        └── didresolver (native)
```

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.


