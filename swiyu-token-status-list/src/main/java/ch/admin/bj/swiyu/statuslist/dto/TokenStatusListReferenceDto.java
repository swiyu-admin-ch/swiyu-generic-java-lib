package ch.admin.bj.swiyu.statuslist.dto;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Extracted Part of a JWT using a Token Status List.
 * Example:
 * {
 *   "_sd": [
 *     "HvrKX6fPV0v9K_yCVFBiLFHsMaxcD_114Em6VT8x1lg"
 *   ],
 *   "iss": "https://example.com/issuer",
 *   "iat": 1683000000,
 *   "exp": 1883000000,
 *   "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
 *   "status": {
 *     "status_list": {
 *       "idx": 0,
 *       "uri": "https://example.com/statuslists/1"
 *     }
 *   },
 *   "_sd_alg": "sha-256"
 * }
 */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class TokenStatusListReferenceDto {
    @JsonProperty("status")
    private TokenStatusListStatus status;

    @Getter
    @Setter
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class TokenStatusListStatus {
        @JsonProperty("status_list")
        private TokenStatusListStatusListReference statusList;
    }

    @Getter
    @Setter
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class TokenStatusListStatusListReference {
        @JsonProperty("idx")
        private int index;
        @JsonProperty("uri")
        private String uri;
    }

    public boolean referencesStatusListToken(TokenStatusListTokenDto token) {
        return this.getStatus().getStatusList().getUri().equals(token.getSub());
    }
}
