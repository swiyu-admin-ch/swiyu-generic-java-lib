# swiyu-sdjwt-builder (draft)

**This library is not yet production-ready and is still under development. Therefore, this library should not be used anywhere yet.**

Creates SD-JWT VC tokens according to the **Swiss Profile VC specification** (RFC 9901).

Companion library to [`swiyu-sdjwt-verifier`](../swiyu-sdjwt-verifier), which validates the
tokens created here. Shared constants live in [`swiyu-sdjwt-util`](../swiyu-sdjwt-util).

## Features

| Rule | Enforced by |
|---|---|
| `typ` header = `dc+sd-jwt` | `SdJwtVcBuilder` |
| Required VC claims present (e.g. `vct`) | `SdJwtVcBuilder` |
| Time claims (`exp`, `nbf`, `iat`) must not be set via `vcClaims` | `SdJwtVcBuilder` |
| Protected claims (`iss`, `nbf`, `exp`, `iat`, `cnf`, `vct`, `vct#integrity`, `status`, `vct_metadata_uri`, `vct_metadata_uri#integrity`, `_sd`, `_sd_alg`) MUST NOT be overridden via selectively disclosable claims | `RecursiveDisclosureUtil` |
| Token Status List reference / Key Binding confirmation key (`cnf`) | `SdJwtVcBuilder` |

## Installation

```xml
<dependency>
    <groupId>ch.admin.swiyu</groupId>
    <artifactId>swiyu-sdjwt-builder</artifactId>
    <version>2.1.0-SNAPSHOT</version>
</dependency>
```

## Usage

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

## Dependency Graph

```
swiyu-sdjwt-builder
  ├── swiyu-sdjwt-util
  └── swiyu-jwt-util
```

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.
