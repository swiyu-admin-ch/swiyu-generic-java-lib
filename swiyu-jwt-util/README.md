# JWT Utility Library

A utility library for creating, validating, and parsing JSON Web Tokens (JWT) in the Swiyu ecosystem.

## Features

- ✅ **Utility Class**: Static methods for JWT creation, validation, and parsing
- ✅ **Flexible Token Management**: Supports creation, validation, and parsing of JWTs
- ✅ **Integration Ready**: Designed for secure authentication and authorization in enterprise applications

## Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>ch.admin.swiyu</groupId>
    <artifactId>swiyu-jwt-service</artifactId>
    <version>1.2.0</version>
</dependency>
```

## Usage

### Basic Usage

Use the static methods of `JwtUtil` to create, validate, or parse JWTs:

```java
import ch.admin.bj.swiyu.jwtutil.JwtUtil;

public class MyJwtExample {
    public String createToken() {
        // Example: create a JWT with claims
        return JwtUtil.createJwt("payload");
    }

    public boolean validateToken(String jwt) {
        return JwtUtil.validateJwt(jwt);
    }
}
```

## Dependencies

- **Nimbus JOSE+JWT**: JWT signing and verification
- **Bouncy Castle**: Cryptographic operations
- **Jackson**: JSON processing

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.

---

For feedback and contributions, see [CONTRIBUTING.md](/CONTRIBUTING.md).
