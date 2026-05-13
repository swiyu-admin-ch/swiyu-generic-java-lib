package ch.admin.bj.swiyu.statuslist.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Reduced DTO for token status list - The JWT should already have been verified before!
 * Example:
 * <p>
 * {
 *   "alg": "ES256",
 *   "kid": "12",
 *   "typ": "statuslist+jwt"
 * }
 * .
 * {
 *   "exp": 2291720170,
 *   "iat": 1686920170,
 *   "status_list": {
 *     "bits": 1,
 *     "lst": "eNrbuRgAAhcBXQ"
 *   },
 *   "sub": "https://example.com/statuslists/1",
 *   "ttl": 43200
 * }
 * </p>
 */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class TokenStatusListTokenDto {

    @JsonProperty("status_list")
    private TokenStatusListDto statusList;

    /**
     * The sub (subject) claim MUST specify the URI of the Status List Token.
     * The value MUST be equal to that of the uri claim contained in the status_list claim of the Referenced Token
     */
    @JsonProperty("sub")
    private String sub;

    /**
     * The ttl (time to live) claim, if present, MUST specify the maximum amount of time, in seconds,
     * that the Status List Token can be cached by a consumer before a fresh copy SHOULD be retrieved.
     */
    @JsonProperty("ttl")
    private Integer ttl;

    @Getter
    @Setter
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class TokenStatusListDto {
        /**
         * specifying the number of bits per Referenced Token in the compressed byte array (lst).
         * The allowed values for bits are 1, 2, 4, and 8.
         */
        @JsonProperty("bits")
        private int bits;
        /**
         * A base64url-encoded compressed byte array of the statuses
         */
        @JsonProperty("lst")
        private String statusListData;
    }
}
