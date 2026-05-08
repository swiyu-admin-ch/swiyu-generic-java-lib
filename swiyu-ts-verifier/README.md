# Trust Statement Verifier (`swiyu-ts-verifier`)

A Java library for verifying signed Trust Statements (JWTs) conforming to the Swiss Trust Protocol 2.0 (swiyu ecosystem). This module provides a high-level facade to validate the cryptographic integrity, lifecycle status, and business rules of all 6 Trust Statement types: `idTS`, `vqPS`, `pvaTS`, `piaTS`, `piTLS`, and `ncTLS`.

## Features

- **Cryptographic Verification**: Ensures trust statements have not been tampered with using Nimbus JOSE and the `swiyu-jwt-validator`.
- **Validity & Lifecycle Verification**: Validates statements against Token Status Lists (`swiyu-token-status-list`) to ensure they are neither revoked nor suspended.
- **Trust Mark Generation**: Automatically evaluates business rules to derive Trust Marks (e.g., Identity Trust Marker, Compliant Actor Trust Marker), providing an easy overview of an actor's trustworthiness.

## Dependencies

- `swiyu-token-status-list`: Verification of Trust Statement Status.
- `swiyu-jwt-validator`: Verification of Trust Statement signatures.
- **Jackson**: JSON processing.
- **Nimbus JOSE + JWT**: Cryptographic operations.

---

### Basic Usage

The primary entry point for this library is the `TrustStatementVerifier` facade. The verification process is split into three phases: Initialization, Fetching Dependencies, and Verification.

### 1. Initialization
Instantiate the verifier by passing the raw, serialized Trust Statement JWTs and a URL restriction (to prevent resolving DIDs from untrusted hosts).

```java
import ch.admin.bj.swiyu.jwtvalidator.UrlRestriction;
import ch.admin.bj.swiyu.tsverifier.TrustStatementVerifier;
import java.util.List;
import java.util.Set;

// 1. Define allowed Trust Registry hosts
UrlRestriction urlRestriction = new UrlRestriction(Set.of("trust-reg.trust-infra.swiyu.admin.ch"));

// 2. Initialize the Verifier with the incoming JWT strings
List<String> rawJwts = List.of(idTsJwt, piaTsJwt, piTlsJwt);
TrustStatementVerifier verifier = new TrustStatementVerifier(rawJwts, urlRestriction);
```

### 2. Resolving Dependencies (Keys & Status Lists)
Before verifying, the host application must fetch the required public keys (DID Documents) and Token Status Lists based on the provided statements. The facade tells you exactly what it needs:

```java

// Extract the required Key IDs (DIDs + Fragments) to fetch the corresponding public keys
Set<String> requiredKIDs = verifier.getRequiredKeyIds();

// Extract the required Status List URIs to fetch the revocation data
Set<String> requiredStatusLists = verifier.getRequiredStatusLists();

// -> TODO for the Host App: Fetch JWKSet and StatusList DTOs based on these sets.
```

### 3. Verification & Trust Evaluation
Once the host application has fetched the required keys (JWKSet) and status lists (List<TokenStatusListTokenDto>), you can execute the final trust evaluation.

Scenario A: Verifying an Issuer (e.g., inside a Wallet)

```java

TrustVerificationResult result = verifier.verifyIssuanceStatements(
    "did:tdw:trust-registry-root", // The ecosystem's root anchor DID
    "did:tdw:issuer-actor",        // The DID of the issuer being evaluated
    "urn:ch.admin.fedpol.betaid",  // The VCT (Credential Type) being requested
    fetchedPublicKeys,             // JWKSet containing the resolved keys
    fetchedStatusLists             // List of verified Token Status Lists
);

// Check if the issuer is fully trusted for this specific credential
boolean isTrusted = result.markers().isTrustedIssuer();
Scenario B: Verifying a Verifier (e.g., during Presentation)

Java

TrustVerificationResult result = verifier.verifyVerifierStatements(
    "did:tdw:trust-registry-root", // The ecosystem's root anchor DID
    "did:tdw:verification-issuer", // The DID that issued the vqPS
    "did:tdw:verifier-actor",      // The DID of the verifier being evaluated
    fetchedPublicKeys, 
    fetchedStatusLists
);

// Check if the verifier is fully trusted to request the specified claims
boolean isTrusted = result.markers().isTrustedVerifier();
```

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.

---

For feedback and contributions, see [CONTRIBUTING.md](/CONTRIBUTING.md).