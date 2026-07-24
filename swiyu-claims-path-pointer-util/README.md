# Claims Pointer Utilities (draft)

**This library is not yet production-ready and is still under development. Therefore, this library should not be used anywhere yet.**

Utilities for working with claim pointers / JSON pointers in the Swiyu ecosystem.

## Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>ch.admin.swiyu</groupId>
    <artifactId>swiyu-claims-path-pointer-util</artifactId>
    <version>1.8.4</version>
</dependency>
```

## Usage

```java
import ch.admin.bj.swiyu.claimspathpointerutil.ClaimsPathPointerUtil;

ClaimsPathPointerUtil.validateRequestedClaim(SomeMap, SomeClaimsPathPointerList, SomeRequestedValues);
```

## License

MIT.
