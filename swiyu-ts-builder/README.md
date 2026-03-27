# Trust Statement Builder (swiyu-ts-builder)

A pure Java library for building unsigned Trust Statement JWTs for the Swiss trust infrastructure (swiyu).
It provides a type-safe, fluent builder API for all Trust Statement types defined in the swiyu specification.

## Features

- **Type-safe Fluent API**: CRTP-based builder hierarchy prevents type errors when chaining calls across inheritance boundaries
- **All swiyu Trust Statement types**: Ready-to-use builders for `idTS`, `vqPS`, `pvaTS`, `piaTS`, `piTLS`, and `ncTLS`
- **Validation**: Built-in constraint enforcement (UUID v4, RFC 3339 timestamps, max-length checks, non-empty list guards)
- **Signing agnostic**: Produces an unsigned `TrustStatementJwt` payload – signing is delegated to a `JWSSigner` of your choice (e.g. HSM, software key)
- **No framework dependency**: Pure Java 21, no Spring Boot required

## Installation

### Maven

```xml
<dependency>
    <groupId>ch.admin.swiyu</groupId>
    <artifactId>swiyu-ts-builder</artifactId>
    <version>1.3.0</version>
</dependency>
```

**Note:** Requires Java 21+.

## Usage

### Identity Trust Statement (idTS)

```java
TrustStatementJwt jwt = new IdTsBuilder()
        .withKid("did:tdw:example.ch:issuer-1#assert-key-01")
        .withIssuer("did:tdw:example.ch:issuer-1")
        .withSubject("did:tdw:example.ch:issuer-1")
        .withValidity(Instant.now(), Instant.now().plus(365, ChronoUnit.DAYS))
        .withStatus(42, "https://status.example.ch/list/1")
        .addEntityName("Smithery AG")                          // default (no locale)
        .addEntityName("de-CH", "Bundesamt für Justiz")        // localized
        .addEntityName("fr-CH", "Office fédéral de la justice")
        .withIsStateActor(true)
        .addRegistryId("UID", "CHE-123.456.789")
        .build();

// Hand off to a JWSSigner of your choice
String signedJws = mySigner.sign(jwt.getPayloadToSign());
```

### Verification Query Public Statement (vqPS)

```java
TrustStatementJwt jwt = new VqPsBuilder()
        .withKid("did:tdw:example.ch:verifier-1#assert-key-01")
        .withIssuer("did:tdw:example.ch:verifier-1")
        .withSubject("did:tdw:example.ch:verifier-1")
        .withValidity(Instant.now(), Instant.now().plus(365, ChronoUnit.DAYS))
        .withJti("550e8400-e29b-41d4-a716-446655440000")
        .addPurposeName("Age verification")                    // default
        .addPurposeName("de-CH", "Altersnachweis")             // localized
        .addPurposeDesc("Checks whether the requesting person is of legal age.")
        .addPurposeDesc("de-CH", "Prüfung ob die anfragende Person volljährig ist.")
        .withRequest("age_verification", "{ ... dcql query ... }")
        .build();
```

### Protected Verification Authorization Trust Statement (pvaTS)

```java
TrustStatementJwt jwt = new PvaTsBuilder()
        .withKid("did:tdw:example.ch:verifier-1#assert-key-01")
        .withIssuer("did:tdw:example.ch:verifier-1")
        .withSubject("did:tdw:example.ch:verifier-1")
        .withValidity(Instant.now(), Instant.now().plus(365, ChronoUnit.DAYS))
        .withStatus(7, "https://status.example.ch/list/1")
        .withJti("550e8400-e29b-41d4-a716-446655440000")
        .withAuthorizedFields(List.of("personal_administrative_number"))
        .build();
```

### Protected Issuance Authorization Trust Statement (piaTS)

```java
TrustStatementJwt jwt = new PiaTsBuilder()
        .withKid("did:tdw:example.ch:issuer-2#assert-key-01")
        .withIssuer("did:tdw:example.ch:issuer-2")
        .withSubject("did:tdw:example.ch:issuer-2")
        .withValidity(Instant.now(), Instant.now().plus(365, ChronoUnit.DAYS))
        .withStatus(3, "https://status.example.ch/list/1")
        .addCanIssue(
                "urn:ch.admin.fedpol.eid",
                "de-CH", "E-ID",
                "Akkreditiert gemäss E-ID-Gesetz")
        .build();
```

### Protected Issuance Trust List Statement (piTLS)

```java
TrustStatementJwt jwt = new PiTlsBuilder()
        .withKid("did:tdw:example.ch:registry#assert-key-01")
        .withIssuer("did:tdw:example.ch:registry")
        .withValidity(Instant.now(), Instant.now().plus(365, ChronoUnit.DAYS))
        .withStatus(99, "https://status.example.ch/list/1")
        .withJti("550e8400-e29b-41d4-a716-446655440000")
        .withVctValues(List.of(
                "urn:ch.admin.fedpol.eid",
                "urn:ch.admin.asa.driving-licence"))
        .build();
```

### Non-Compliance Trust List Statement (ncTLS)

```java
TrustStatementJwt jwt = new NcTlsBuilder()
        .withKid("did:tdw:example.ch:registry#assert-key-01")
        .withIssuer("did:tdw:example.ch:registry")
        .withValidity(Instant.now(), Instant.now().plus(1, ChronoUnit.DAYS))
        .withStatus(5, "https://status.example.ch/list/1")
        .addNonCompliantActor(
                "did:tdw:example.ch:bad-actor",
                "2026-02-25T07:07:35Z",
                "en", "Revoked due to policy violation")
        .build();
```

### Signing the payload

All builders return an unsigned `TrustStatementJwt`. Pass the payload to a `JWSSigner` implementation to obtain the final compact JWS serialization:

```java
TrustStatementJwt jwt = new IdTsBuilder()
        .withKid("did:tdw:example.ch:issuer-1#assert-key-01")
        .withIssuer("did:tdw:example.ch:issuer-1")
        .withSubject("did:tdw:example.ch:issuer-1")
        .withValidity(Instant.now(), Instant.now().plus(365, ChronoUnit.DAYS))
        .withStatus(0, "https://status.example.ch/list/1")
        .build();

// JWSSigner is a single-method interface – implement it against your HSM or software key
String compactJws = mySigner.sign(jwt.getPayloadToSign());
```

## Builder overview

All builders inherit `withKid`, `withIssuer`, `withSubject`, `withValidity` and `withStatus` from `AbstractTrustStatementBuilder`.

| Builder | Statement type | `typ` header | Type-specific claims |
|---|---|---|---|
| `IdTsBuilder` | `idTS` | `swiyu-identity-trust-statement+jwt` | `entity_name`, `is_state_actor`, `registry_ids` |
| `VqPsBuilder` | `vqPS` | `swiyu-verification-query-public-statement+jwt` | `jti`, `purpose_name`, `purpose_description`, `request` |
| `PvaTsBuilder` | `pvaTS` | `swiyu-protected-verification-authorization-trust-statement+jwt` | `jti`, `authorized_fields` |
| `PiaTsBuilder` | `piaTS` | `swiyu-protected-issuance-authorization-trust-statement+jwt` | `can_issue` |
| `PiTlsBuilder` | `piTLS` | `swiyu-protected-issuance-trust-list-statement+jwt` | `jti`, `vct_values` |
| `NcTlsBuilder` | `ncTLS` | `swiyu-non-compliance-trust-list-statement+jwt` | `non_compliant_actors` |

## Error Handling

All `build()` methods throw `TrustStatementException` (unchecked) when required claims are missing or constraints are violated:

```java
try {
    TrustStatementJwt jwt = new IdTsBuilder().build(); // missing sub → exception
} catch (TrustStatementException e) {
    log.error("Trust statement validation failed: {}", e.getMessage());
}
```

## Dependencies

- **Nimbus JOSE JWT 10.6**: JWT/JWS data structures and serialization
- **Jackson 2.19.2**: JSON payload assembly
- **Java 21+**: Core runtime

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.

---

For feedback and contributions, see [CONTRIBUTING.md](/CONTRIBUTING.md).
