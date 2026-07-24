# Token Status List Library

A utility library for reading and setting states in Token Status Lists.

## Features

- Parsing of Token Status List (TLS) Tokens and References
- Serialize and Deserialize Token Status List Data
- Reading and Setting indexes in Token Status List Data

Note: For verifying the Token Status List Token in JWT format, use the JWT Utility Library. 

## Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>ch.admin.swiyu</groupId>
    <artifactId>swiyu-token-status-list</artifactId>
    <version>1.8.4</version>
</dependency>
```

## Usage

### Basic Usage

Note: use an ObjectMapper to parse JWT bodies into the DTOs. 

```java
import ch.admin.bj.swiyu.statuslist.TokenStatusList;
import ch.admin.bj.swiyu.statuslist.TokenStatusListVerifier;
import ch.admin.bj.swiyu.statuslist.dto.TokenStatusListTokenDto;
import ch.admin.bj.swiyu.statuslist.dto.TokenStatusListReferenceDto;

public class MyStatusListExample {

    // Resolves must be writte by the implementing application to get the status list jwt or did
    private VerificationObjectResolver resolver;

    private DidJwtValidator didJwtValidator;
    private TokenStatusListVerifier verifier;
    

    public VerificationResultDto validateTokenStatus(JWTClaimSet vcClaims) {
        TokenStatusListReferenceDto reference = TokenStatusListMapper.toTokenStatusListReference(vcClaims.getClaims())
        String statusListJWT = resolver.resolveStatusList(reference.getReferencedStatusListUri());
        String didUrl = didJwtValidator.getAndValidateResolutionUrl(statusListJWT);
        DidDocument didDocument = resolver.resolveDidDocument(didUrl);
        // Validates Signature & timing constraints
        didJwtValidator.validateJwt(statusListJWT, didDocument);
        SignedJWT tokenStatusListJwt = SignedJWT.parse(statusListJWT);
        if(!verifier.hasValidTokenStatusListTokenHeader(tokenStatusListJWT.getHeader())) {
            throw new IllegalArgumentException("Illegal Token Status List Token!");
        }
        TokenStatusListTokenDto statusList = TokenStatusListMapper.toTokenStatusListToken(tokenStatusListJWT.getJWTClaimsSet().getClaims()
        // If using caching update according to minimum of statusList.getTtl() and statusList.getExp()
)       return verifier.verifyStatus(reference, statusList);
    }

    /**
     * Get Status form a status list
     */
    public String getStatus(TokenStatusListReferenceDto ref, TokenStatusListTokenDto token) {
        var sl = token.getStatusList();
        var statusList = TokenStatusList.loadTokenStatusListToken(sl.getBits(), sl.getStatusListData());
        return statusList.getStatus(ref.getStatus().getStatusList().getIndex());
    }
}
```

## Dependencies

- **Jackson**: JSON processing

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.

---

For feedback and contributions, see [CONTRIBUTING.md](/CONTRIBUTING.md).
