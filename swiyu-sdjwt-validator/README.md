# swiyu-sdjwt-validator (draft)

**This library is not yet production-ready and is still under development. Therefore, this library should not be used anywhere yet.**

Validates SD-JWT VC tokens according to the **Swiss Profile VC specification** (RFC 9901).

Delegates DID-based signature verification to [`swiyu-jwt-validator`](../swiyu-jwt-validator).

## Features

| Rule | Enforced by |
|---|---|
| `typ` header = `dc+sd-jwt` (configurable for migration) | `SdJwtVcValidator` |
| `_sd_alg` = `sha-256` | `SdJwtVcValidator` |
| Registered claims NOT in Disclosures (`iss`, `nbf`, `exp`, `iat`, `cnf`, `vct`, `vct#integrity`, `status`, `vct_metadata_uri`, `vct_metadata_uri#integrity`, `_sd`, `_sd_alg`) | `SdJwtVcValidator` |
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
    TimeConfiguration timeConfig = TimeConfiguration.Builder().expiry(Instant.now().plus(1, ChronoUnit.DAYS)).build();
    SdJwtVcBuilder builder = SdJwtVcBuilder.createBuilder("did:webvh:scid:example.com#key-1", vcClaims, credentialSubjectClaims, timeConfig, myNimbusJWSSigner);
    CreatedSdJwtVc signed builder.createSignedSdJwtVc(Optional.of(new TokenStatusListReferenceData(1, "https://www.example.com/status/1")), Optional.of(signatureData.holderKey));
    signed.serializedSdJwt();
```

### Verification

```java
private Map<String, Object> verifySdJwt(String serializedSdJwt) {
    SdJwtValidator sdJwtValidator = new SdJwtValidator(didJwtValidator); // Must have a did jwt validator configured with accepted URLs
    SdJwt sdJwt = SdJwtParser.parseSdJwt(serializedSdJwt);
    // Required for header to be present in sdJwt
    sdJwtValidator.validateHeader(sdJwt);
    String kid = sdJwt.getHeader().getKeyId();
    JWK issuerJwk = didKeyResolver.resolve(kid); // DID Resolver not part of library
    sdJwtValidator.validateJwt(sdJwt, issuerJwk);
    JWTClaimsSet claims = sdJwt.getClaims();
    if (sdJwt.hasKeyBinding) {
        SdJwtValidator.validateKeyBinding(sdJwt, audience, nonce, acceptableProofTimeWindow);
    }
    // If necessary valdiate Token Status List or Trust here

    Map<String, Object> verifiedClaims = sdJwtValidator.processDisclosures(sdJwt);
    return verifiedVlaims
    
}
```

## Dependency Graph

```
swiyu-sdjwt-validator
  └── swiyu-jwt-validator
        ├── swiyu-did-resolver-adapter
        ├── swiyu-jwt-util
        └── didresolver (native)
```

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.

