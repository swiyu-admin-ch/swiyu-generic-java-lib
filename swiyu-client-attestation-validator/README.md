# Client Attestation Validator

A Spring Boot auto-configuration library for validating OAuth 2.0 Client Attestation tokens with Proof of Possession (PoP).

## Features

- ✅ **Spring Boot Auto-Configuration**: Automatic bean registration with property-based configuration
- ✅ **JWT Validation**: Complete validation of attestation and PoP tokens
- ✅ **Hash Verification**: Validates request body hashes using JSON Canonicalization (JCS)
- ✅ **Flexible Configuration**: Supports resource paths (classpath, file system) via Spring's Resource abstraction

## Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>io.github.swiyu-admin-ch</groupId>
    <artifactId>swiyu-client-attestation-validator</artifactId>
    <version>0.0.1-snapshot</version>
</dependency>
```

## Configuration

Configure the properties in your `application.yml` or `application.properties`:

```yaml
swiyu:
  attestation:
    enabled: true
    publicKeyPath: classpath:keys/attestation-service-public.pem
    attestationServiceDid: did:example:attestation-service
    didKeySuffix: "#assert-key-01"
```

Or use environment variable substitution with a default:
```yaml
didKeySuffix: ${ATTESTATION_SERVICE_DID_KEY:"#assert-key-01"}
```

### Configuration Properties

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `swiyu.attestation.enabled` | No | `false` | Enable/disable attestation validation. When `false`, all requests are accepted. |
| `swiyu.attestation.publicKeyPath` | Yes* | - | Path to the EC public key PEM file (e.g., `classpath:keys/public.pem` or `file:/etc/keys/public.pem`) |
| `swiyu.attestation.attestationServiceDid` | Yes* | - | The DID (Decentralized Identifier) of the attestation service |
| `swiyu.attestation.didKeySuffix` | Yes* | - | The key suffix for the DID (e.g., `#assert-key-01`) |

\* Required when `enabled=true`

## Usage

### Basic Usage

The `ClientAttestationValidator` bean will be automatically available for dependency injection when `swiyu.attestation.enabled=true`:

```java
import ch.admin.bj.swiyu.clientattestation.ClientAttestationValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@RestController
public class MyController {
    
    @Autowired
    private ClientAttestationValidator clientAttestationValidator;

    public ResponseEntity<Void> reportNonCompliantActor(
            @Parameter(description = "OAuth client attestation token proving device integrity", required = true)
            @RequestHeader("OAuth-Client-Attestation") String clientAttestation,
            @Parameter(description = "OAuth client attestation PoP token binding the attestation to the request", required = true)
            @RequestHeader("OAuth-Client-Attestation-PoP") String clientAttestationPop,
            @Valid @RequestBody MyRequest request,
            HttpServletRequest servletRequest
    ) throws UnsupportedEncodingException {
        // Read the cached body
        String rawBody = new String(((ContentCachingRequestWrapper) servletRequest).getContentAsByteArray(),
                servletRequest.getCharacterEncoding());

        if (!clientAttestationValidator.isAttested(clientAttestation, clientAttestationPop, rawBody)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}
```

### Method Signature

```java
/**
 * Validates client attestation and proof of possession.
 * 
 * @param attestation The attestation JWT token
 * @param pop The proof of possession JWT token
 * @param body The request body (JSON string)
 * @return true if validation passes, false otherwise
 */
public boolean isAttested(String attestation, String pop, String body)
```

### Behavior when Disabled

When `swiyu.attestation.enabled=false`:
- The `ClientAttestationValidator` bean is **not** created
- The auto-configuration is skipped
- No validation occurs


## Testing

In your test classes, use `@TestPropertySource` to configure the properties:

```java
@SpringBootTest
@TestPropertySource(properties = {
    "swiyu.attestation.enabled=true",
    "swiyu.attestation.attestationServiceDid=did:example:attestation-service",
    "swiyu.attestation.didKeySuffix=#key-1",
    "swiyu.attestation.publicKeyPath=classpath:keys/attestation-service-public.pem"
})
class MyTest {
    @Autowired
    private ClientAttestationValidator validator;
    
    @Test
    void testAttestationValidation() {
        String attestation = "eyJhbGciOiJFUzI1NiIsInR5cCI6...";
        String pop = "eyJhbGciOiJFUzI1NiIsInR5cCI6...";
        String body = "{\"data\":\"example\"}";
        
        boolean isValid = validator.isAttested(attestation, pop, body);
        
        assertTrue(isValid);
    }
}
```

Make sure the PEM file exists in your test resources directory (e.g., `src/test/resources/keys/attestation-service-public.pem`).

## Public Key Format

The public key must be an EC (Elliptic Curve) key in PEM format:

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
-----END PUBLIC KEY-----
```

Supported curves: P-256 (secp256r1), P-384, P-521

## Error Handling

The validator handles errors gracefully:

- **Configuration errors**: Throws `IllegalArgumentException` during bean initialization
- **Key loading errors**: Logs error and rejects all requests (returns `false`)
- **Validation errors**: Returns `false` and logs detailed information

The `isAttested()` method never throws exceptions - it returns `false` on any error.

## Logging

The library uses SLF4J for logging. Ensure you have an SLF4J implementation in your Spring Boot application (typically `spring-boot-starter-logging`).

Log levels:
- `INFO`: Validation failures with reasons
- `WARN`: Configuration warnings (e.g., missing public key)
- `ERROR`: Unexpected errors during validation

Example log output:
```
INFO  c.a.b.s.c.ClientAttestationValidator : Wrong issuer did:wrong:service
INFO  c.a.b.s.c.ClientAttestationValidator : PoP req hash validation failed
ERROR c.a.b.s.c.ClientAttestationValidator : Attestation EC verification failed
```

## Dependencies

The library includes:

- **Nimbus JOSE+JWT** (9.37.3): JWT parsing and validation
- **Bouncy Castle** (1.78.1): Cryptographic operations and PEM parsing
- **Jackson** (2.19.2): JSON processing
- **Java JSON Canonicalization** (1.1): JCS implementation for hash verification
- **Spring Boot Starter**: Auto-configuration support

# Contributions and feedback

We welcome any feedback on the code regarding both the implementation and security aspects. Please follow the guidelines for
contributing found in [CONTRIBUTING.md](/CONTRIBUTING.md).

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.

---

