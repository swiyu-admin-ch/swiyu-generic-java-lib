# Swiyu Generic Java Library

A collection of reusable Java helper libraries organized as a multi-module Maven project.

## Project Structure

This project follows a multi-module Maven architecture, where each utility library is a separate module with its own POM. This approach allows you to:

- **Use individual modules**: Include only the utilities you need
- **Use the complete library**: Include all modules via the `swiyu-all` aggregator
- **Easy maintenance**: All modules in one repository with centralized dependency management
- **Flexible builds**: Build everything at once or individual modules

## Modules

### **swiyu-client-attestation-validator**
Utilities for validating client attestation tokens and certificates (Android SafetyNet, Apple DeviceCheck, etc.)

```xml
<dependency>
    <groupId>io.github.swiyu-admin-ch</groupId>
    <artifactId>swiyu-client-attestation-validator</artifactId>
    <version>0.0.1</version>
</dependency>
```

### **swiyu-generic-java-all** (Aggregator)
Include all utility modules at once

```xml
<dependency>
    <groupId>io.github.swiyu-admin-ch</groupId>
    <artifactId>swiyu-generic-java-all</artifactId>
    <version>0.0.1</version>
</dependency>
```

## Building the Project

### Build all modules
```bash
mvn clean install
```

### Build a specific module
```bash
cd swiyu-client-attestation-validator
mvn clean install
```

### Run tests
```bash
mvn test
```

### Run tests for a specific module
```bash
mvn test -pl swiyu-client-attestation-validator
```

## Requirements

- Java 21 or higher
- Maven 3.6 or higher

## Usage Examples




### Validation Utils
```java
[TODO]
```


## Adding New Modules

1. Create a new directory for the module
2. Add the module to the parent POM's `<modules>` section
3. Create a `pom.xml` with the parent reference
4. Implement your utility classes
5. Add tests

# Contributions and feedback

We welcome any feedback on the code regarding both the implementation and security aspects. Please follow the guidelines for
contributing found in [CONTRIBUTING.md](/CONTRIBUTING.md).

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.

