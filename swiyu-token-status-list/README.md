# Token Status List Library

A utility library for reading and setting states in Token Status Lists.

## Features

- Parsing of Token Status List (TLS) Tokens and References
- Serialize and Deserialize Token Status List Data
- Reading and Setting indexes in Token Status List Data

Note: For verifying the Token Status List Token in JWT format, use the JWT Utility Library. 


## Usage

### Basic Usage

Note: use an ObjectMapper to parse JWT bodies into the DTOs. 

```java
import ch.admin.bj.swiyu.statuslist.TokenStatusList;
import ch.admin.bj.swiyu.statuslist.dto.TokenStatusListTokenDto;
import ch.admin.bj.swiyu.statuslist.dto.TokenStatusListReferenceDto;

public class MyStatusListExample {
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
