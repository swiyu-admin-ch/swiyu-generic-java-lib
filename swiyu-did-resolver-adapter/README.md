# Swiyu DID Resolver Adapter

A Spring Boot Auto-Configuration library for resolving Decentralized Identifiers (DIDs) to DID Documents and public keys.

## Features

- **DID Resolution**: Resolve DIDs to DID Documents (supports did:tdw, did:webvh)
- **Key Resolution**: Extract public keys from DID Documents as JWK
- **Trust Statement Resolution**: Retrieve trust statements from trust registries
- **Spring Boot Auto-Configuration**: Automatic bean configuration for easy integration
- **WebClient-based**: Uses Spring WebFlux WebClient for HTTP communication
- **URL Rewriting**: Flexible URL rewriting for different environments (testing, production)

## Installation

### Maven

```xml
<dependency>
    <groupId>ch.admin.swiyu</groupId>
    <artifactId>swiyu-did-resolver-adapter</artifactId>
    <version>1.4.0</version>
</dependency>
```

**Note:** This library requires Spring Boot 3.3.4+ and Java 21+.

## Usage

### Automatic Spring Boot Integration

The library configures itself automatically as a Spring Boot Auto-Configuration. You only need to add the dependency:

```java
@Service
public class MyVerifierService {
    
    private final DidResolverAdapter didResolverAdapter;
    
    // Automatically injected by Spring
    public MyVerifierService(DidResolverAdapter didResolverAdapter) {
        this.didResolverAdapter = didResolverAdapter;
    }
    
    public void verifyCredential(String issuerDid) throws DidResolverException {
        // Resolve DID to DID Document
        DidDoc didDoc = didResolverAdapter.resolveDid(issuerDid, Map.of());
        
        // Use the DID Document...
    }
    
    public void verifySignature(String keyId) {
        // Resolve public key from DID Document
        JWK publicKey = didResolverAdapter.resolveKey(keyId, Map.of());
        
        // Verify signature with the public key...
    }
    
    public void checkTrustStatement(String trustRegistryUrl, String vct) {
        // Retrieve trust statement from trust registry
        String trustStatement = didResolverAdapter.resolveTrustStatement(
            trustRegistryUrl, 
            vct, 
            Map.of()
        );
        if (trustStatement == null) {
            // HTTP 404 from the trust registry: no statement available
            return;
        }
        // Any non-404 error triggers a DidResolverException
        // Process trust statement...
    }
}
```

### With URL Rewriting

URL rewriting is useful for redirecting production URLs to test environments or local development:

```java
@Service
public class MyVerifierService {
    
    private final DidResolverAdapter didResolverAdapter;
    
    public MyVerifierService(DidResolverAdapter didResolverAdapter) {
        this.didResolverAdapter = didResolverAdapter;
    }
    
    public DidDoc resolveDid(String didId) throws DidResolverException {
        // Define URL mappings
        Map<String, String> urlMappings = Map.of(
            "https://production.example.com", "https://test.example.com",
            "https://api.production.com", "http://localhost:8080"
        );
        
        return didResolverAdapter.resolveDid(didId, urlMappings);
    }
}
```

### Custom WebClient Configuration

You can customize the WebClient by providing your own `WebClient.Builder` bean:

```java
@Configuration
public class WebClientConfig {
    
    @Bean
    public WebClient.Builder webClientBuilder() {
        return WebClient.builder()
                .defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .defaultHeader(HttpHeaders.USER_AGENT, "MyApplication/1.0")
                .codecs(configurer -> configurer
                    .defaultCodecs()
                    .maxInMemorySize(16 * 1024 * 1024)); // 16 MB
    }
}
```


## Auto-Configuration

The library provides Spring Boot Auto-Configuration through:

- **DidResolverWebClientConfiguration**: Configures the WebClient-based HTTP client
- **DidResolverAdapterConfiguration**: Configures the main DID resolver adapter

These are automatically loaded by Spring Boot. No manual configuration is required unless you want to customize the WebClient.

## Dependencies

The library depends on:

- **Spring Boot 3.3.4+**: Core framework
- **Spring WebFlux**: WebClient for HTTP communication
- **didresolver 2.3.0**: DID resolution logic
- **Nimbus JOSE JWT**: JWK parsing and handling
- **Jackson**: JSON serialization
- **JNA**: Java Native Access (required by didresolver)

## Supported DID Methods

The library supports the following DID methods through the underlying `didresolver` library:

- **did:tdw** (Trust DID Web)
- **did:webvh** (Web Verifiable History)

## Testing

For testing purposes, you can use URL rewriting to redirect to mock endpoints:

```java
@SpringBootTest
public class MyVerifierServiceTest {
    
    @Autowired
    private DidResolverAdapter didResolverAdapter;
    
    @Test
    public void testResolveDid() throws DidResolverException {
        Map<String, String> testMappings = Map.of(
            "https://production.example.com", "http://localhost:8080/mock"
        );
        
        DidDoc didDoc = didResolverAdapter.resolveDid(
            "did:tdw:production.example.com:123", 
            testMappings
        );
        
        assertNotNull(didDoc);
    }
}
```

## License

MIT License - see LICENSE file

## Authors

Developed by the Swiyu Team

## Links

- [GitHub Repository](https://github.com/swiyu-admin-ch/swiyu-generic-java-lib)
- [Maven Central](https://central.sonatype.com/artifact/io.github.swiyu-admin-ch/swiyu-did-resolver-adapter)
