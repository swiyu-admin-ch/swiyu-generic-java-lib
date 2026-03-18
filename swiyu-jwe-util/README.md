# swiyu-jwe-util

Utility library for JSON Web Encryption (JWE) in the Swiyu ecosystem. Provides static methods for secure payload encryption and decryption, supporting enterprise integration and cryptographic best practices.

## Features
- Static utility methods for JWE encryption and decryption
- Supports EC keys and standard JWE algorithms
- Designed for integration in enterprise Java applications

## Installation
Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>ch.admin.swiyu</groupId>
    <artifactId>swiyu-jwe-util</artifactId>
    <version>1.3.0</version>
</dependency>
```

## Usage Example

```java
import ch.admin.bj.swiyu.jweutil.JweUtil;
import com.nimbusds.jose.jwk.JWK;

String encrypted = JweUtil.encrypt("my payload", recipientPublicKey);
String decrypted = JweUtil.decrypt(encrypted, recipientPrivateKey);
```

## Supported Algorithms
- ECDH-ES with AES-GCM
- EC keys (P-256, P-384, P-521)

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.

---
For feedback and contributions, see [CONTRIBUTING.md](/CONTRIBUTING.md).
