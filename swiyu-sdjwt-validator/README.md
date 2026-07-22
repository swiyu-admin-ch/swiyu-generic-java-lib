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
    <version>1.8.3</version>
</dependency>
```

## Usage

### Flow B – Two-Step (recommended)

```java
// Initialise once
DidJwtValidator didJwtValidator = new DidJwtValidator(
    new UrlRestriction(Set.of("identifier.admin.ch"))
);
SdJwtVcValidator validator = new SdJwtVcValidator(didJwtValidator);

// Step 1 – pre-flight: validate typ and get DID resolution URL
String didUrl    = validator.getAndValidateResolutionUrl(sdJwt);
String didString = didJwtValidator.getDidString(sdJwt);

// Step 2 – caller fetches the DID Document (HTTP GET to didUrl), then:
String didLog = httpClient.fetch(didUrl);
DidDoc didDoc = did.resolveAll(didString, didLog).getDidDoc();
validator.validateSdJwtVc(sdJwt, didDoc);
```

### Migration Phase (accepting both `vc+sd-jwt` and `dc+sd-jwt`)

```java
SdJwtVcValidator validator = new SdJwtVcValidator(didJwtValidator,
    Set.of(SdJwtVcValidator.TYP_DC_SD_JWT, SdJwtVcValidator.TYP_VC_SD_JWT));
```

### Flow A – Direct JWK Set validation

```java
validator.validateSdJwtVc(sdJwt, jwkSet);
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

