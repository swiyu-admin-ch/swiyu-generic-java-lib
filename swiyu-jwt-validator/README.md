# swiyu-jwt-validator

A pure, framework-agnostic Java library for JWT validation in the swiyu ecosystem.
It orchestrates DID resolution, URL allowlist enforcement and cryptographic signature verification –
without making any HTTP calls itself (Flow B).

## Features

- **Flow B (two-step):** `getAndValidateResolutionUrl()` extracts and validates the DID URL; the caller fetches the DID Document; `validateJwt(jwtString, didDocument)` verifies the signature.
- **Flow A (direct):** `validateJwt(jwtString, jwkSet)` verifies the signature against a pre-built JWK set (e.g. for Trust Statements).
- **Absolute `kid` enforcement:** JWTs without a fully-qualified `kid` (DID URL with `#` fragment) are rejected immediately.
- **Base Registry allowlist:** DID URLs are validated against a configurable set of allowed hosts to prevent CSRF and "phone home" attacks.
- **`iss` claim ignored:** Trust is established exclusively via the `kid`; the `iss` claim is never validated.
- **Time claim validation:** `exp` and `nbf` are validated when present, with a configurable clock skew tolerance (default: 60 s).
- **No Spring Framework:** Pure Java, injectable via constructor into any framework.

## Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>ch.admin.swiyu</groupId>
    <artifactId>swiyu-jwt-validator</artifactId>
    <version>1.9.0-SNAPSHOT</version>
</dependency>
```

## Usage

### Flow B – Two-Step (recommended for DID-based JWTs)

```java
// Initialise once (inject allowedHosts from your configuration)
DidJwtValidator validator = new DidJwtValidator(
    new UrlRestriction(Set.of("identifier.admin.ch"))
);

// Step 1 – pre-flight: get the DID resolution URL and DID string (no HTTP call made by the library)
String didUrl    = validator.getAndValidateResolutionUrl(jwtString);
String didString = validator.getDidString(jwtString);

// Step 2 – caller fetches the DID Document (HTTP GET to didUrl), then resolves and validates:
String didLog = httpClient.fetch(didUrl);
DidDoc didDoc = did.resolveAll(didString, didLog).getDidDoc();
validator.validateJwt(jwtString, didDoc);
// → exp/nbf are checked automatically; iss is ignored
```

### Flow A – Direct JWK Set validation (e.g. Trust Statements)

```java
validator.validateJwt(jwtString, jwkSet);
// → exp/nbf are checked automatically; iss is ignored
```

### Custom Clock Skew

```java
// Allow up to 120 seconds of clock difference between issuer and verifier
DidJwtValidator validator = new DidJwtValidator(
    new UrlRestriction(Set.of("identifier.admin.ch")),
    120
);
```

## Dependency Graph

```
swiyu-jwt-validator
  ├── swiyu-did-resolver-adapter  (HTTP-based DID log retrieval)
  ├── swiyu-jwt-util              (cryptographic JWT signature verification)
  └── didresolver (native)        (DID URL resolution and DID Document parsing)
```

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.