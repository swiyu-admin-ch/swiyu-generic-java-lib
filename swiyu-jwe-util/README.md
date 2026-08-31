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
    <version>3.0.0</version>
</dependency>
```

## Usage Example

```java
import ch.admin.bj.swiyu.jweutil.JweUtil;
import ch.admin.bj.swiyu.jweutil.JweDecryptionLimits;
import com.nimbusds.jose.jwk.JWK;

String encrypted = JweUtil.encrypt("my payload", recipientPublicKey);

String decrypted = JweUtil.decrypt(encrypted, recipientPrivateKey, JweDecryptionLimits.defaults());
```

## Supported Algorithms
- ECDH-ES with AES-GCM
- EC keys (P-256, P-384, P-521)

## Security: JWE Decompression Bomb Protection (EIDOMNI-1117 / EIDSEC-843)

`JweUtil.decrypt(...)` enforces two independent size limits via `JweDecryptionLimits`:
- `maxCompressedCipherTextLength` – limit on the compressed ciphertext (primary defense, checked by Nimbus before decompression).
- `maxDecompressedPayloadLength` – limit on the decompressed payload, checked right after decryption (defense-in-depth).

```java
String decrypted = JweUtil.decrypt(encrypted, recipientPrivateKey, JweDecryptionLimits.defaults());
```

Defaults: 20 MiB decompressed.

**Migration:** Update to `swiyu-jwe-util` 2.1.0+. Old overloads `decrypt(String, JWK)` / `decrypt(String, JWK, Integer)` are `@Deprecated` but still work. Consumers (`swiyu-issuer-service`, `swiyu-verifier-service`) should switch to passing an explicit `JweDecryptionLimits`.

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.

---
For feedback and contributions, see [CONTRIBUTING.md](/CONTRIBUTING.md).
