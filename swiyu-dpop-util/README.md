# DPoP Utility Library

A utility library for validating DPoP (Demonstration of Proof-of-Possession) JWTs in the Swiyu ecosystem, compliant with RFC 9449.

## Features

- ✅ **DPoP JWT Validation**: Parses and validates DPoP JWTs according to RFC 9449, including all required claims, headers, and signature checks
- ✅ **Access Token Binding Validation**: Validates that a DPoP proof is correctly bound to an access token and public key
- ✅ **Access Token Hash Validation**: Utilities for validating the 'ath' claim (access token hash)
- ✅ **Constants and Exception Handling**: Centralized constants and custom exception for DPoP validation
- ✅ **Integration Ready**: Designed for secure proof-of-possession in OAuth2/OpenID Connect flows

## Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>ch.admin.swiyu</groupId>
    <artifactId>swiyu-dpop-util</artifactId>
    <version>1.4.0</version>
</dependency>
```

## Usage

### Parse and Validate a DPoP JWT

The main entry point is a method that parses and validates a DPoP JWT according to RFC 9449. It checks all required headers and claims, verifies the signature, and ensures the JWT matches the HTTP request context.

```java
import ch.admin.bj.swiyu.dpop.DpopJwtValidator;
import ch.admin.bj.swiyu.dpop.DpopConstants;
import ch.admin.bj.swiyu.dpop.DpopValidationException;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.JOSEException;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.time.Clock;
import javax.servlet.http.HttpServletRequest;

public SignedJWT parseDpopJwt(String dpop, HttpServletRequest request, ApplicationProperties applicationProperties) {
    try {
        var dpopJwt = SignedJWT.parse(dpop);
        var header = dpopJwt.getHeader();
        var jwtClaims = dpopJwt.getJWTClaimsSet();
        DpopJwtValidator.validateMandatoryClaims(header, jwtClaims);
        DpopJwtValidator.validateTyp(header);
        DpopJwtValidator.validateAlgorithm(header, DpopConstants.SUPPORTED_ALGORITHMS);
        var key = header.getJWK();
        DpopJwtValidator.validateSignature(dpopJwt, key);
        DpopJwtValidator.validatePublicKeyNotPrivate(key);
        DpopJwtValidator.validateHtm(request.getMethod(), jwtClaims);
        DpopJwtValidator.validateHtu(request.getRequestURL(), jwtClaims.getStringClaim("htu"),
                new URI(applicationProperties.getExternalUrl()));
        DpopJwtValidator.validateIssuedAt(jwtClaims, applicationProperties.getAcceptableProofTimeWindowSeconds(), Clock.systemUTC());
        // Optionally: hasValidSelfContainedNonce(jwtClaims);
        return dpopJwt;
    } catch (ParseException | JOSEException | URISyntaxException | NullPointerException e) {
        throw new DemonstratingProofOfPossessionException("Malformed DPoP", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF, e);
    } catch (DpopValidationException e) {
        throw new DemonstratingProofOfPossessionException(e.getMessage(), DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF, e);
    }
}
```

- **Parameters:**
  - `dpop`: The DPoP JWT as a serialized string.
  - `request`: The HTTP request the DPoP was provided with.
  - `applicationProperties`: Configuration (e.g., external URL, time window).
- **Returns:** The parsed and validated `SignedJWT`.
- **Throws:** `DemonstratingProofOfPossessionException` if the DPoP is invalid.

### Validate DPoP Access Token Binding

After parsing and validating the DPoP JWT, you should validate that it is correctly associated with the access token and the public key to which the access token is bound.

```java
import com.nimbusds.jwt.SignedJWT;
import java.util.Map;

/**
 * Validates if the validated DPoP is associated with the access token and public key.
 *
 * @param accessToken    the access token the DPoP is bound to, as used for bearer token
 * @param dpopJwt        Parsed JWT of the DPoP
 * @param boundPublicKey The public key bound to the access token as Json Web Key (JWK)
 * @throws DemonstratingProofOfPossessionException if the DPoP is not correctly associated with the access token or the key.
 * @see #parseDpopJwt(String, HttpServletRequest, ApplicationProperties)
 */
public void validateAccessTokenBinding(String accessToken, SignedJWT dpopJwt, Map<String, Object> boundPublicKey) {
    try {
        // Ensure that the value of the ath claim equals the hash of that access token
        DemonstratingProofOfPossessionUtils.validateAccessTokenHash(accessToken, dpopJwt.getJWTClaimsSet().getStringClaim("ath"));
        // Confirm that the public key to which the access token is bound matches the public key from the DPoP proof
        validateBoundPublicKey(dpopJwt, boundPublicKey);
    } catch (ParseException e) {
        throw new DemonstratingProofOfPossessionException("Malformed DPoP", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF, e);
    }
}
```

- **Parameters:**
  - `accessToken`: The access token value.
  - `dpopJwt`: The parsed DPoP JWT (from `parseDpopJwt`).
  - `boundPublicKey`: The public key (JWK) bound to the access token.
- **Throws:** `DemonstratingProofOfPossessionException` if the DPoP is not correctly associated with the access token or key.


## Dependencies

- **Nimbus JOSE+JWT**: JWT parsing and signature verification
- **Java Base64**: Encoding utilities

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.

---

For feedback and contributions, see [CONTRIBUTING.md](/CONTRIBUTING.md).
