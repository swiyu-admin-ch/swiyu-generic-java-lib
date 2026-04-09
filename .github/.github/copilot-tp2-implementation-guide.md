# Implementation Guide: swiyu-ts-generator (Trust Protocol 2.0)

## 1. Project Scope and Architecture
You are tasked with implementing a Java library (`swiyu-ts-generator`) that generates JSON Web Tokens (JWTs) representing Trust Statements for the Swiss "swiyu" Trust Infrastructure.

**Design Pattern:**
Implement a strict **Builder Pattern** with a Fail-Fast validation approach.
*   Use an `AbstractTrustStatementBuilder` for common headers and payload claims.
*   Provide 6 concrete builder classes, one for each specific Trust Statement type.
*   Throw a domain-specific `TrustStatementValidationException` immediately if length limits, formats, or required fields are violated during the `with...()` or `add...()` setter calls.
*   Rely on Information Hiding for localization (e.g., `addEntityName("de-CH", "Name")` translates to `"entity_name#de-CH": "Name"` in the JSON output).

---

## 2. JWT Header Requirements (JWS)
Every generated Trust Statement MUST be a JWS (Compact Serialization) and MUST include the following protected headers:
1.  **`alg`**: MUST be exactly `"ES256"`.
2.  **`kid`**: MUST be an absolute DID with a key reference (e.g., `"did:tdw:Qm...#key-1"`).
3.  **`profile_version`**: MUST be exactly `"swiss-profile-trust:1.0.0"`.
4.  **`typ`**: MUST be set automatically by the concrete builder based on the statement type (see section 4).

---

## 3. Common Payload Claims
The `AbstractTrustStatementBuilder` MUST handle and validate the following standard JWT claims:
*   **`iss`** (Issuer) & **`sub`** (Subject): MUST be formatted as DIDs (e.g., starting with `did:`).
*   **`iat`**, **`nbf`**, **`exp`**: Epoch timestamps (NumericDate as per RFC 7519). Ensure `nbf <= exp`.
*   **`status`**: A revocation object. If required by the statement type, it MUST be structured exactly like this:
    ```json
    "status": {
      "status_list": {
        "idx": <integer>,
        "uri": "<string URL>"
      }
    }
    ```

---

## 4. Specific Trust Statement Types

Implement 6 concrete builders with the following strict payload rules, required fields, and `typ` headers.

### 4.1. Identity Trust Statement (`idTS`)
*   **Header `typ`**: `"swiyu-identity-trust-statement+jwt"`
*   **Required Claims**: `sub`, `iat`, `exp`, `status`, `entity_name`, `is_state_actor`, `registry_ids`.
*   **Fields**:
    *   `entity_name` (String): Human-readable name. Supports localization.
    *   `is_state_actor` (Boolean).
    *   `registry_ids` (Array of Objects): Each object MUST contain `type` (String, e.g., "UID") and `value` (String, e.g., "CHE-000.000.000").

### 4.2. Verification Query Public Statement (`vqPS`)
*   **Header `typ`**: `"swiyu-verification-query-public-statement+jwt"`
*   **Required Claims**: `jti`, `sub`, `iat`, `exp`, `purpose_name`, `purpose_description`, `request`.
*   **Fields**:
    *   `jti` (String): MUST be a valid UUIDv4 (RFC 9562).
    *   `purpose_name` (String): MAX 50 characters. Supports localization.
    *   `purpose_description` (String): MAX 500 characters. Supports localization.
    *   `request` (Object): MUST contain:
        *   `type`: Exactly `"DCQL"`.
        *   `scope`: String matching the OpenID4VP scope.
        *   `query`: A DCQL JSON object containing a `meta` object with a non-empty `vct_values` array for each credential query.

### 4.3. Protected Verification Authorization Trust Statement (`pvaTS`)
*   **Header `typ`**: `"swiyu-protected-verification-authorization-trust-statement+jwt"`
*   **Required Claims**: `jti`, `sub`, `iat`, `exp`, `status`, `authorized_fields`.
*   **Fields**:
    *   `jti` (String): MUST be a valid UUIDv4.
    *   `authorized_fields` (Array of Strings): MUST be a non-empty array of field names (e.g., `["personal_administrative_number"]`).

### 4.4. Protected Issuance Authorization Trust Statement (`piaTS`)
*   **Header `typ`**: `"swiyu-protected-issuance-authorization-trust-statement+jwt"`
*   **Required Claims**: `sub`, `iat`, `nbf`, `exp`, `status`, `can_issue`.
*   **Fields**:
    *   `can_issue` (Object): The Protected Issuance Authorization Object MUST contain:
        *   `vct` (String): The Verifiable Credential Type identifier.
        *   `vct_name` (String): MAX 500 characters. Supports localization.
        *   `description` / `reason` (String, Optional): MAX 50 characters. Supports localization.

### 4.5. Protected Issuance Trust List Statement (`piTLS`)
*   **Header `typ`**: `"swiyu-protected-issuance-trust-list-statement+jwt"`
*   **Required Claims**: `jti`, `iss`, `iat`, `nbf`, `exp`, `status`, `vct_values`.
*   **Fields**:
    *   `jti` (String): MUST be a valid UUIDv4.
    *   `vct_values` (Array of Strings): MUST be a non-empty array of valid VCT identifiers (e.g., `["urn:ch.admin.fedpol.eid"]`).

### 4.6. Non-Compliance Trust List Statement (`ncTLS`)
*   **Header `typ`**: `"swiyu-non-compliance-trust-list-statement+jwt"`
*   **Required Claims**: `iat`, `exp`, `status`, `non_compliant_actors`.
*   **Fields**:
    *   `non_compliant_actors` (Array of Objects): MUST be a non-empty array. Each object MUST contain:
        *   `actor` (String): The DID of the bad actor.
        *   `flagged_at` (String): MUST be a valid RFC 3339 timestamp string (e.g., `"2026-02-25T07:07:35Z"`).
        *   `reason` (String): Human-readable reason. Supports localization.

---

## 5. Localization Helper (I18n)
For fields marked as "Supports localization" (e.g., `entity_name`, `purpose_name`, `purpose_description`, `vct_name`, `reason`), the builder MUST provide methods to easily add language tags conforming to **BCP 47 / RFC 5646**.

**Implementation rule:**
If the developer calls `addPurposeName("de-CH", "Beispiel")`, the library MUST internally serialize this into the JSON claim `"purpose_name#de-CH": "Beispiel"`.
If called without a locale (or default locale), output the base claim name without the `#` suffix (e.g., `"purpose_name": "Example"`).

---

## 6. Target Developer Experience (Code Example)
Your generated Java classes should enable the following fluent API usage:

```java
String jwt = IdentityTrustStatementBuilder.create()
    .withKid("did:tdw:QmZytP...#assert-key-01")
    .withIssuer("did:tdw:QmZytP...")
    .withSubject("did:example:actor")
    .withValidity(Instant.now(), Instant.now().plus(365, ChronoUnit.DAYS)) // Sets iat, nbf, exp
    .withStatus(0, "https://example.com/statuslists/1")
    .withIsStateActor(false)
    .addEntityName("John Smith's Smithery")         // default
    .addEntityName("de-CH", "John Smith's Schmiderei") // localized
    .addRegistryId("UID", "CHE-000.000.000")
    .addRegistryId("LEI", "0A1B2C3D4E5F6G7H8J9I")
    .buildAndSign(privateKey); // Builds JSON, applies ES256 signature, returns JWS string