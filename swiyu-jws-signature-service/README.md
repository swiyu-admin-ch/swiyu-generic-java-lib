# JWS Signature Service

A Spring Boot auto-configuration library for creating and managing JSON Web Signatures (JWS) using software keys or Hardware Security Modules (HSMs) such as PKCS#11 and Securosys Primus.

## Features

- ✅ **Spring Boot Auto-Configuration**: Automatic bean registration for JWS signing
- ✅ **Flexible Key Management**: Supports software keys, PKCS#11 HSMs, and Securosys Primus HSMs
- ✅ **Strategy Pattern**: Easily extendable key management strategies
- ✅ **DTO-Based Configuration**: Simple configuration via Java DTOs
- ✅ **Integration Ready**: Designed for secure digital signatures in enterprise applications

## Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>io.github.swiyu-admin-ch</groupId>
    <artifactId>swiyu-jws-signature-service</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Usage

### Basic Usage

Inject the `JwsSignatureService` bean and use it to create JWS signers based on your configuration:

```java
import ch.admin.bj.swiyu.jwssignatureservice.JwsSignatureService;
import ch.admin.bj.swiyu.jwssignatureservice.dto.SignatureConfigurationDto;
import ch.admin.bj.swiyu.jwssignatureservice.dto.HSMPropertiesDto;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.KeyStrategyException;
import com.nimbusds.jose.JWSSigner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class MySigningService {
    
    @Autowired
    private JwsSignatureService jwsSignatureService;

    public JWSSigner createSigner() throws KeyStrategyException {
        SignatureConfigurationDto config = SignatureConfigurationDto.builder()
            .keyManagementMethod("pkcs11")
            .hsm(HSMPropertiesDto.builder()
                .keyId("mySigningKey")
                .userPin("123456")
                .pkcs11Config("/etc/hsm/pkcs11.cfg")
                .build())
            .verificationMethod("did:example:123#key-1")
            .build();
        
        // Create signer without overrides
        return jwsSignatureService.createSigner(config);
        
        // Or with runtime keyId/keyPin overrides:
        // return jwsSignatureService.createSigner(config, "overrideKeyId", "overridePin");
    }
}
```

### Supported Key Management Methods

- `key`: Software EC key (PEM format)
- `pkcs11`: PKCS#11 HSM
- `securosys`: Securosys Primus HSM

## Configuration Reference

### SignatureConfigurationDto

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `keyManagementMethod` | String | ✅ Yes | Method for key management. Valid values: `"key"`, `"pkcs11"`, `"securosys"` |
| `verificationMethod` | String | ✅ Yes | The ID of the verification method in the DID document (e.g., `"did:example:123#key-1"`) |
| `privateKey` | String | ⚠️ For `"key"` only | PEM-encoded EC private key. Required when `keyManagementMethod` is `"key"` |
| `hsm` | HSMPropertiesDto | ⚠️ For HSM methods | HSM configuration. Required when `keyManagementMethod` is `"pkcs11"` or `"securosys"` |

### HSMPropertiesDto

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `keyId` | String | ✅ Yes | The key alias/identifier in the HSM keystore |
| `userPin` | String | ✅ Yes | PIN/password for accessing the key in the HSM (for `pkcs11`: keystore PIN; for `securosys`: key PIN) |
| `pkcs11Config` | String | ⚠️ For `pkcs11` | Path to PKCS#11 configuration file (e.g., `"/etc/hsm/pkcs11.cfg"`). See [Java PKCS#11 Reference Guide](https://docs.oracle.com/en/java/javase/21/security/pkcs11-reference-guide1.html) |
| `host` | String | ⚠️ For `securosys` | Securosys HSM host address |
| `port` | String | ⚠️ For `securosys` | Securosys HSM port |
| `user` | String | ⚠️ For `securosys` | Securosys HSM username |
| `password` | String | ⚠️ For `securosys` | Securosys HSM password |
| `proxyUser` | String | ❌ Optional | Securosys Primus proxy username |
| `proxyPassword` | String | ❌ Optional | Securosys Primus proxy password |
| `keyPin` | String | ❌ Optional | Can be overridden via method parameter in `createSigner()` |

### Configuration Examples

#### Example 1: Software Key (PEM)

```java
SignatureConfigurationDto config = SignatureConfigurationDto.builder()
    .keyManagementMethod("key")
    .privateKey("-----BEGIN EC PRIVATE KEY-----\n" +
                "MHcCAQEEIJKtRr...\n" +
                "-----END EC PRIVATE KEY-----")
    .verificationMethod("did:example:123#key-1")
    .build();

JWSSigner signer = jwsSignatureService.createSigner(config);
```

#### Example 2: PKCS#11 HSM

```java
SignatureConfigurationDto config = SignatureConfigurationDto.builder()
    .keyManagementMethod("pkcs11")
    .hsm(HSMPropertiesDto.builder()
        .keyId("mySigningKey")
        .userPin("123456")
        .pkcs11Config("/etc/hsm/pkcs11.cfg")
        .build())
    .verificationMethod("did:web:example.com#key-1")
    .build();

JWSSigner signer = jwsSignatureService.createSigner(config);
```

#### Example 3: Securosys Primus HSM

```java
SignatureConfigurationDto config = SignatureConfigurationDto.builder()
    .keyManagementMethod("securosys")
    .hsm(HSMPropertiesDto.builder()
        .keyId("securosys-signing-key")
        .userPin("keyPin123")
        .host("hsm.example.com")
        .port("8443")
        .user("hsmUser")
        .password("hsmPassword")
        .proxyUser("proxyUser")      // Optional
        .proxyPassword("proxyPass")  // Optional
        .build())
    .verificationMethod("did:tdw:example.com#key-1")
    .build();

JWSSigner signer = jwsSignatureService.createSigner(config);
```

#### Example 4: Override KeyId and KeyPin

```java
SignatureConfigurationDto config = SignatureConfigurationDto.builder()
    .keyManagementMethod("pkcs11")
    .hsm(HSMPropertiesDto.builder()
        .keyId("defaultKey")
        .userPin("defaultPin")
        .pkcs11Config("/etc/hsm/pkcs11.cfg")
        .build())
    .verificationMethod("did:example:123#key-1")
    .build();

// Override keyId and keyPin at runtime
JWSSigner signer = jwsSignatureService.createSigner(config, "overrideKey", "overridePin");
```

## Important Notes

### PKCS#11 Configuration

The PKCS#11 configuration file specifies the PKCS#11 module (vendor-specific library) and its settings. The format is vendor-specific. Example:

```
name = MyHSM
library = /usr/lib/libpkcs11.so
slot = 0
```

For more details, see the [Java PKCS#11 Reference Guide](https://docs.oracle.com/en/java/javase/21/security/pkcs11-reference-guide1.html).

### Securosys Primus HSM

The Securosys strategy requires:
- The Primus JCE provider to be available at runtime
- A key with an associated self-signed certificate in the HSM
- See [Securosys Certificate Sign Request Documentation](https://docs.securosys.com/primus-tools/Use-Cases/certificate-sign-request)

### Key Requirements

- **Software Keys (`key`)**: Must be PEM-encoded EC private keys (ECDSA)
- **HSM Keys**: Must have an associated certificate in the keystore
- All strategies support EC (Elliptic Curve) keys for ECDSA signatures

### Deep Copy Behavior

The `createSigner()` method creates a deep copy of the `SignatureConfigurationDto` to prevent modification of the original configuration object. This ensures thread-safety when the same configuration is reused.

## Error Handling

- Throws `KeyStrategyException` for key loading or signing errors
- Validates configuration and fails fast on misconfiguration
- All parameters marked as required will cause exceptions if missing or null

## Dependencies

- **Nimbus JOSE+JWT**: JWS/JWT signing and verification
- **Bouncy Castle**: Cryptographic operations
- **Jackson**: JSON processing
- **Spring Boot Starter**: Auto-configuration support

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.

---

For feedback and contributions, see [CONTRIBUTING.md](/CONTRIBUTING.md).
