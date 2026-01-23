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
    <version>0.0.3</version>
</dependency>
```

## Usage

### Basic Usage

Inject the `JwsSignatureService` bean and use it to create JWS signers based on your configuration:

```java
import ch.admin.bj.swiyu.jwssignatureservice.JwsSignatureService;
import ch.admin.bj.swiyu.jwssignatureservice.dto.SignatureConfigurationDto;
import org.springframework.beans.factory.annotation.Autowired;

@Service
public class MyService {
    @Autowired
    private JwsSignatureService jwsSignatureService;

    public void signData() {
        SignatureConfigurationDto config = SignatureConfigurationDto.builder()
            .keyManagementMethod("pkcs11") // or "key" or "securosys"
            .hsm(HSMPropertiesDto.builder()
                .userPin("1234")
                .keyId("myKeyId")
                .pkcs11Config("/etc/hsm/pkcs11.cfg")
                .build())
            .verificationMethod("did:example:123#key-1")
            .build();
        JWSSigner signer = jwsSignatureService.createSigner(config, null, null);
        // Use signer to sign JWTs
    }
}
```

### Supported Key Management Methods

- `key`: Software EC key (PEM format)
- `pkcs11`: PKCS#11 HSM
- `securosys`: Securosys Primus HSM

### DTO Configuration Example

```java
SignatureConfigurationDto config = SignatureConfigurationDto.builder()
    .keyManagementMethod("key")
    .privateKey("-----BEGIN EC PRIVATE KEY-----...-----END EC PRIVATE KEY-----")
    .verificationMethod("did:example:123#key-1")
    .build();
```

## Error Handling

- Throws `KeyStrategyException` for key loading or signing errors
- Validates configuration and fails fast on misconfiguration

## Dependencies

- **Nimbus JOSE+JWT**: JWS/JWT signing and verification
- **Bouncy Castle**: Cryptographic operations
- **Jackson**: JSON processing
- **Spring Boot Starter**: Auto-configuration support

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.

---

For feedback and contributions, see [CONTRIBUTING.md](/CONTRIBUTING.md).
