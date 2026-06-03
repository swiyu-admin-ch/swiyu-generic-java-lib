# Claims Pointer Utilities

Utilities for working with claim pointers / JSON pointers in the Swiyu ecosystem.

## Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>ch.admin.swiyu</groupId>
    <artifactId>swiyu-claims-path-pointer-util</artifactId>
    <version>1.6.2</version>
</dependency>
```

## Usage

```java
import ch.admin.bj.swiyu.claimspathpointerutil.ClaimsPathPointerUtil;

ClaimsPathPointerUtil.validateRequestedClaim(SomeMap, SomeClaimsPathPointerList, SomeRequestedValues);
```

## License

MIT.
