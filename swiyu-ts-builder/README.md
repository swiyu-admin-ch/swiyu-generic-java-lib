# Trust Statement Builder (swiyu-ts-builder)

A pure Java library for building unsigned Trust Statement JWTs for the Swiss trust infrastructure (swiyu).
It provides a type-safe, fluent builder API for all Trust Statement types defined in the Swiss Trust Protocol 2.0.

## Features

- **Type-safe Fluent API**: CRTP-based builder hierarchy prevents type errors when chaining calls across inheritance boundaries
- **Statement categories**: Builders are categorised as `TrustStatement`, `PublicStatement` or `TrustListStatement` via marker interfaces
- **All swiyu Trust Statement types**: Ready-to-use builders for `idTS`, `vqPS`, `pvaTS`, `piaTS`, `piTLS`, and `ncTLS`
- **Validation**: Built-in constraint enforcement (UUID v4, RFC 3339 timestamps, max-length checks, non-empty list guards) – fail-fast in setters, complete validation before object construction
- **Signing agnostic**: Produces an unsigned Nimbus `SignedJWT` (header + claims) – signing is delegated to a `JWSSigner` of your choice (e.g. HSM, software key)
- **No framework dependency**: Pure Java 21, no Spring Boot required

## Installation

### Maven

```xml
<dependency>
    <groupId>ch.admin.swiyu</groupId>
    <artifactId>swiyu-ts-builder</artifactId>
    <version>1.5.0</version>
</dependency>
```

**Note:** Requires Java 21+.

## Statement categories

| Category | Marker interface | Description |
|---|---|---|
| Trust Statement | `TrustStatement` | Attests **verified** information about a subject. Issued only after formal human review and approval. `sub` and `status` are required. |
| Public Statement | `PublicStatement` | Attests that self-declared information has been recorded in a public register. Content is **not reviewed**. `sub` and `jti` are required. |
| Trust List Statement | `TrustListStatement` | Provides exhaustive information about the swiyu ecosystem. Absence from the list is semantically meaningful. `sub` is **not supported**. |

## Usage

### Signing the result

All builders return an unsigned Nimbus [`SignedJWT`](https://www.javadoc.io/doc/com.nimbusds/nimbus-jose-jwt/latest/com/nimbusds/jwt/SignedJWT.html)
in `UNSIGNED` state. Sign it with a `JWSSigner` of your choice:

```java
SignedJWT ts = new IdTsBuilder()
        // ... configure ...
        .build();

ts.sign(mySigner); // JWSSigner – HSM, software key, etc.
String compactJws = ts.serialize();
```

---

### Identity Trust Statement (idTS)

```java
SignedJWT ts = new IdTsBuilder()
        .withKid("did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch:api:v1:did#assert-key-01")
        .withSubject("did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRBB1:identifier.admin.ch:api:v1:did")
        .withValidity(Instant.now(), Instant.now().plus(365, ChronoUnit.DAYS))
        .withStatus(42, "https://status.example.ch/list/1")
        .addEntityName("Smithery AG")                           // default (no locale)
        .addEntityName("de-CH", "Bundesamt für Justiz")         // localized
        .addEntityName("fr-CH", "Office fédéral de la justice")
        .withIsStateActor(true)
        .addRegistryId("UID", "CHE-123.456.789")
        .build();
```

### Verification Query Public Statement (vqPS)

```java
Map<String, Object> dcqlQuery = Map.of("credentials", List.of(
        Map.of(
                "id", "my_credential",
                "format", "dc+sd-jwt",
                "meta", Map.of("vct_values", List.of("urn:ch.admin.fedpol.eid")),
                "claims", List.of(Map.of("path", List.of("last_name")))
        )
));

SignedJWT ts = new VqPsBuilder()
        .withKid("did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch:api:v1:did#assert-key-01")
        .withSubject("did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRBB1:identifier.admin.ch:api:v1:did")
        .withValidity(Instant.now(), Instant.now().plus(365, ChronoUnit.DAYS))
        .withJti("550e8400-e29b-41d4-a716-446655440000")
        .addPurposeName("Age verification")                     // default
        .addPurposeName("de-CH", "Altersnachweis")              // localized
        .addPurposeDesc("Checks whether the requesting person is of legal age.")
        .addPurposeDesc("de-CH", "Prüfung ob die anfragende Person volljährig ist.")
        .withRequest("age_verification", dcqlQuery)
        .build();
```

### Protected Verification Authorization Trust Statement (pvaTS)

```java
SignedJWT ts = new PvaTsBuilder()
        .withKid("did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch:api:v1:did#assert-key-01")
        .withSubject("did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRBB1:identifier.admin.ch:api:v1:did")
        .withValidity(Instant.now(), Instant.now().plus(365, ChronoUnit.DAYS))
        .withStatus(7, "https://status.example.ch/list/1")
        .withJti("550e8400-e29b-41d4-a716-446655440000")
        .withAuthorizedFields(List.of("personal_administrative_number"))
        .build();
```

### Protected Issuance Authorization Trust Statement (piaTS)

```java
SignedJWT ts = new PiaTsBuilder()
        .withKid("did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch:api:v1:did#assert-key-01")
        .withSubject("did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRBB1:identifier.admin.ch:api:v1:did")
        .withValidity(Instant.now(), Instant.now().plus(365, ChronoUnit.DAYS))
        .withStatus(3, "https://status.example.ch/list/1")
        .withCanIssue(
                "urn:ch.admin.fedpol.eid",
                "de-CH", "E-ID",
                "Akkreditiert gemäss E-ID-Gesetz")
        .build();
```

### Protected Issuance Trust List Statement (piTLS)

```java
SignedJWT ts = new PiTlsBuilder()
        .withKid("did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch:api:v1:did#assert-key-01")
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
SignedJWT ts = new NcTlsBuilder()
        .withKid("did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch:api:v1:did#assert-key-01")
        .withValidity(Instant.now(), Instant.now().plus(1, ChronoUnit.DAYS))
        .withStatus(5, "https://status.example.ch/list/1")
        .addNonCompliantActor(
                new NcTlsBuilder.NonCompliantActorBuilder(
                        "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRCC1:identifier.admin.ch:api:v1:did",
                        "2026-02-25T07:07:35Z",
                        "Revoked due to policy violation")
                        .addReason("de", "Widerrufen wegen Richtlinienverstoß")
                        .addReason("fr-CH", "Révoqué en raison d'une violation de politique")
                        .build())
        .build();
```

## Builder overview

`withKid`, `withSubject`, `withValidity`, `withStatus` and `withJti` are inherited from `AbstractTrustStatementBuilder`.
`sub` is not supported for `TrustListStatement` builders (`NcTlsBuilder`, `PiTlsBuilder`) and will throw immediately if called.

| Builder | Category | `typ` header | Type-specific claims |
|---|---|---|---|
| `IdTsBuilder` | `TrustStatement` | `swiyu-identity-trust-statement+jwt` | `entity_name`, `is_state_actor`, `registry_ids` |
| `VqPsBuilder` | `PublicStatement` | `swiyu-verification-query-public-statement+jwt` | `purpose_name`, `purpose_description`, `request` |
| `PvaTsBuilder` | `TrustStatement` | `swiyu-protected-verification-authorization-trust-statement+jwt` | `authorized_fields` |
| `PiaTsBuilder` | `TrustStatement` | `swiyu-protected-issuance-authorization-trust-statement+jwt` | `can_issue` |
| `PiTlsBuilder` | `TrustListStatement` | `swiyu-protected-issuance-trust-list-statement+jwt` | `vct_values` |
| `NcTlsBuilder` | `TrustListStatement` | `swiyu-non-compliance-trust-list-statement+jwt` | `non_compliant_actors` |

## Error Handling

All validation is unchecked and thrown as `TrustStatementValidationException`. Errors are thrown fail-fast
in setters where possible, and at the latest during `build()` before the `SignedJWT` is constructed:

```java
try {
    SignedJWT ts = new IdTsBuilder().build(); // missing kid, validity, ... → exception
} catch (TrustStatementValidationException e) {
    log.error("Trust statement validation failed: {}", e.getMessage());
}
```

Builder instances are **single-use** – calling `build()` a second time on the same instance throws.

## Dependencies

- **Nimbus JOSE JWT 10.6**: JWT/JWS data structures and serialization
- **Java 21+**: Core runtime

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.

---

For feedback and contributions, see [CONTRIBUTING.md](/CONTRIBUTING.md).
