
# Copilot Instructions: Swiss Trust Protocol 2.0 (TP2)

## 1. Context and Core Principles
When generating code, architecture designs, or answering questions related to the "Trust Protocol 2.0" (TP2) for the Swiss `swiyu` ecosystem, adhere to the following core principles:
*   **Zero-Trust Architecture:** No actor trusts another blindly. All actors MUST validate the received Trust Statements themselves before acting.
    *   **Wallet checks Verifier:** The Wallet protects the user by verifying the Verifier's Trust Statements before sharing data.
    *   **Verifier checks Issuer (Verifier-View):** The Verifier protects itself by validating the Issuer's Trust Statements to ensure the Issuer had state authorization to issue the presented Verifiable Credential (VC).
*   **Privacy by Design:** Verifiers MUST NOT make any requests or notify the Issuer about individual verifications.
*   **Format:** Trust Statements are standard JSON Web Tokens (JWT) using JWS Compact Serialization. They do NOT use Selective Disclosure (SD) or device binding, as all trust data is public.

## 2. Trust Statement Types
There are 6 specific Trust Statements in TP2. Whenever generating a statement, the `typ` header MUST exactly match the statement type:

1.  **Identity Trust Statement (`idTS`)**
    *   *Purpose:* Links real-world identities to their cryptographic DIDs.
    *   *typ:* `swiyu-identity-trust-statement+jwt`
2.  **Verification Query Public Statement (`vqPS`)**
    *   *Purpose:* Public transparency on intended verification scope. Contains the DCQL query.
    *   *typ:* `swiyu-verification-query-public-statement+jwt`
3.  **Protected Verification Authorization Trust Statement (`pvaTS`)**
    *   *Purpose:* Grants a Verifier authorization to request protected claims (e.g., personal administrative numbers).
    *   *typ:* `swiyu-protected-verification-authorization-trust-statement+jwt`
4.  **Protected Issuance Authorization Trust Statement (`piaTS`)**
    *   *Purpose:* Proof of state authorization for an Issuer to issue protected VCs.
    *   *typ:* `swiyu-protected-issuance-authorization-trust-statement+jwt`
5.  **Protected Issuance Trust List Statement (`piTLS`)**
    *   *Purpose:* An exhaustive list of VC types (`vct_values`) whose issuance is protected.
    *   *typ:* `swiyu-protected-issuance-trust-list-statement+jwt`
6.  **Non-Compliance Trust List Statement (`ncTLS`)**
    *   *Purpose:* Warns actors of known bad/non-compliant actors in the ecosystem.
    *   *typ:* `swiyu-non-compliance-trust-list-statement+jwt`

## 3. Cryptographic and Structural Requirements (Structural Integrity)
When implementing statement generators (e.g., `swiyu-ts-generator` Java Library), enforce the following strict rules:
*   **JOSE Headers:**
    *   `alg` MUST be `ES256`.
    *   `kid` MUST be a DID with a key reference (e.g., `did:tdw:...#key-1`).
    *   `profile_version` MUST be `swiss-profile-trust:1.0.0`.
*   **Payload Claims:**
    *   `iss` and `sub` MUST be valid DIDs (typically `did:tdw`).
    *   `iat`, `nbf`, `exp` MUST be valid Epoch timestamps (RFC 7519).
    *   `status` MUST be present and structured as a Token Status List revocation entry (`{"status_list": {"idx": <int>, "uri": "<string>"}}`).
    *   `jti` MUST be a valid UUIDv4 (RFC 9562).
    *   `flagged_at` (in ncTLS) MUST be an RFC 3339 formatted string.
*   **Localization (I18n):**
    *   Human-readable claims (e.g., `entity_name`, `purpose_name`) support BCP-47 localization by appending `#<language_tag>` to the claim name (e.g., `entity_name#de-CH`).
    *   APIs/Builders should use Information Hiding (e.g., `addEntityName(locale, name)`) to abstract string concatenation from the developer.

## 4. Trust Markers (UI Evaluation)
The Wallet evaluates Trust Statements to derive Trust Markers for the UI. Ensure logic accounts for these dependencies:
*   **Verified Identity Trust Mark (viTM):** Valid `idTS` present.
*   **Compliant Actor Trust Mark (caTM):** Actor is not listed in a valid `ncTLS`.
*   **Transparent Verification Trust Mark (tvTM):** Valid `vqPS` present (Verifier only).
*   **Governed use case Trust Mark (gucTM):** The `vct` of the credential is listed in the `piTLS`.
*   **Governed use case authorization Trust Mark (gucaTM):** Requires gucTM + viTM + a valid `piaTS` (for Issuers) or `pvaTS` (for Verifiers) matching the exact credential/field.

## 5. Sidechannel Provisioning
Trust statements are distributed actively by the actors to reduce chattiness with the Trust Registry:
*   **Generic Issuer:** Embeds `idTS` and `piaTS` automatically into the Issuer Metadata (`.well-known/openid-credential-issuer`).
*   **Generic Verifier:** Embeds `idTS`, `vqPS`, and `pvaTS` inside the JWT-Secured Authorization Request (OID4VP Request Object) within the `verifier_info` array. Format: `[{"format": "jwt", "data": "<JWT_STRING>"}]`.

## 6. Implementation Patterns
*   **Fail-Fast Principle:** Builders for Trust Statements must validate formats (UUIDv4, RFC 3339) and lengths (e.g., max 50 chars for `purpose_name`, max 500 chars for `purpose_description`) inside the setter methods. Throw a `TrustStatementException` immediately upon invalid input.
*   **Builder Pattern:** Use abstract base classes to encapsulate fixed headers (`typ`, `profile_version`) and mandatory claims, and specific concrete builders for the payload of the 6 distinct statement types.
