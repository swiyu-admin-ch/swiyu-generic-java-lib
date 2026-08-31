# swiyu-sdjwt-util (draft)

Shared constants for the SD-JWT VC Swiss Profile (RFC 9901), used by both
[`swiyu-sdjwt-builder`](../swiyu-sdjwt-builder) (issuance) and
[`swiyu-sdjwt-verifier`](../swiyu-sdjwt-verifier) (verification).

Contains no business logic — only `SdJwtConstants` (claim names, accepted `typ` values,
protected claims, Key Binding `typ`, profile version markers).

## Installation

```xml
<dependency>
    <groupId>ch.admin.swiyu</groupId>
    <artifactId>swiyu-sdjwt-util</artifactId>
    <version>3.0.0</version>
</dependency>
```

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.
