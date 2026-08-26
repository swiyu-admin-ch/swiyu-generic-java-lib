# Copilot Implementation Guide: swiyu-jwt-validator (Task EIDOMNI-872)

## 1. Context & Architectural Principles
You are an expert Java developer. Your task is to implement the `swiyu-jwt-validator` library.
- **No Spring Framework**: This library is a pure, framework-agnostic Java artifact [1, 2]. Do not use `@ConfigurationProperties`, Spring annotations, or `config/` packages.
- **Constructor Injection**: All dependencies (such as the allowed hosts whitelist) MUST be injected via constructor [1, 2].
- **Flow B Architecture (No Internal Network Calls)**: The library does NOT execute HTTP requests. Network calls and caching are handled externally by the integrating component. The library simply prepares the URL and validates the signature [3].
- **Dependencies**: The library orchestrates and consumes the existing `swiyu-did-resolver-adapter` and `swiyu-jwt-util` libraries [4, 5].

## 2. Package Structure
Target package: `ch.admin.bj.swiyu.jwtvalidator` [6]
Required Classes [2, 3, 6]:
- `JwtValidatorException.java`
- `UrlRestriction.java`
- `DidKidParser.java`
- `DidJwtValidator.java` (Main Facade)

## 3. Strict Security & Domain Rules (from EIDARTFE-1729 & EIDARTFE-1727)
You must strictly enforce the following rules during implementation:
- **Absolute `kid` enforcement**: JWTs without a `kid` header or with a non-absolute `kid` MUST be rejected immediately [3, 7].
- **No custom splitting**: All `kid` handling and DID extraction MUST be done using the resolver's `getDidFromAbsoluteKid(kid)` method. Do not implement manual `#` string splitting in this library [3, 8].
- **Ignore `iss` claim**: Any `iss` (Issuer) claim present in the JWT payload MUST be actively ignored during validation. Validation and trust establishment are exclusively based on the `kid` [3, 7, 9].
- **Key Extraction**: Public keys MUST be extracted from the DID Document using the exact library call `getKeyByMethodId(kid)` [3, 8].
- **Base Registry Enforcement**: The resolved DID URL MUST be validated against the whitelist of allowed hosts before the caller makes any network requests [2, 3].

## 4. Class Implementation Details

### 4.1 JwtValidatorException
- Must be a custom unchecked exception extending `RuntimeException` [2].
- Must provide constructors to wrap underlying technical exceptions like `ParseException`, `JOSEException`, and `DidResolverException` [2, 10].

### 4.2 UrlRestriction
- **Constructor**: Accepts `Set<String> allowedHosts` [2, 10].
- **Method**: `boolean validateUrl(String url)` [2, 3].
- **Logic**: Validates if the generated DID URL strictly matches one of the allowed hosts (Base Registry) to prevent CSRF and "phone home" attacks [2, 3, 11].

### 4.3 DidKidParser
- **Methods**: `extractKidFromHeader(String jwtString): String` and `getDidFromAbsoluteKid(String kid): String` [2, 3].
- **Logic**: Parses the JWT header. Throws `JwtValidatorException` if the `kid` is missing or not absolute [3, 7].

### 4.4 DidJwtValidator (Main Facade)
This is the primary entry point, implementing the "2-Step Flow" (Flow B) and "Flow A" for pre-fetched key sets [3].

**Method 1: `String getAndValidateResolutionUrl(String jwtString)`** [3]
*(Step 1 of Flow B: Pre-flight & URL Extraction)*
1. Calls `DidKidParser` to extract the `kid` from the `jwtString`.
2. Calls `DidKidParser` to get the DID from the absolute `kid`.
3. Resolves the DID to its URL using the `DidResolverAdapter`.
4. Calls `UrlRestriction.validateUrl(didUrl)` to enforce the Base Registry whitelist.
5. Returns the validated `didUrl` to the caller. (The caller will then perform the HTTP GET to fetch the `DidDocument`).

**Method 2: `boolean validateJwt(String jwtString, DidDocument didDocument)`** [3]
*(Step 3 of Flow B: Signature Validation)*
1. Extracts the `kid` from the JWT header.
2. Extracts the specific key from the `didDocument` using `getKeyByMethodId(kid)` [3, 8].
3. Converts the extracted key to a `JWKSet`.
4. Calls `swiyu-jwt-util` to perform the pure mathematical signature check.
5. Applies domain rules: Ensure that any `iss` claim in the payload is ignored [3, 7, 9].

**Method 3: `boolean validateJwt(String jwtString, JWKSet jwkSet)`** [3]
*(Flow A: Validation without Base Registry, e.g., for Trust Statements)*
1. Extracts the `kid` from the JWT header.
2. Verifies the signature directly with the provided `jwkSet` using `swiyu-jwt-util`.
3. Applies domain rules: Ensure that any `iss` claim in the payload is ignored [3, 7, 9].