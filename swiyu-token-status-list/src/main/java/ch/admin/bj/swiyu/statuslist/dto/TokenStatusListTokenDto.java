package ch.admin.bj.swiyu.statuslist.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.JWSHeader;
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

    @Getter
    @Setter
    @JsonProperty(value = "jws_header")
    private JWSHeader jwsHeader;

    @Deprecated(since = "Swiss Profile 1.0")
    @JsonProperty(value = "iss")
    private String issuer;

    @JsonProperty(value = "status_list", required = true)
    private TokenStatusListDto statusList;

    /**
     * The sub (subject) claim MUST specify the URI of the Status List Token.
     * The value MUST be equal to that of the uri claim contained in the status_list claim of the Referenced Token
     */
    @JsonProperty(value = "sub", required = true)
    private String sub;

    @JsonProperty(value = "iat", required = true)
    private Long iat;

    @JsonProperty(value = "exp", required = true)
    private Long exp;
    /**
     * The ttl (time to live) claim, if present, MUST specify the maximum amount of time, in seconds,
     * that the Status List Token can be cached by a consumer before a fresh copy SHOULD be retrieved.
     */
    @JsonProperty(value = "ttl", required = false)
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
        @JsonProperty(value = "bits", required = true)
        private int bits;
        /**
         * A base64url-encoded compressed byte array of the statuses
         */
        @JsonProperty(value = "lst", required = true)
        private String statusListData;

        public boolean hasRequiredClaims() {
            // bits (must be 1,2,4,8)
            if (bits != 1 && bits != 2 && bits != 4 && bits != 8) {
                return false;
            }

            // lst (required, non‑blank)
            return statusListData != null && !statusListData.isBlank();
        }
    }

    /**
     * Checks whether this DTO contains every claim that the Status List
     * specification mandates for a status‑list token.
     *
     * <p>The method performs the following validations:</p>
     * <ul>
     *   <li>{@code sub} must be non‑null and non‑blank.</li>
     *   <li>{@code statusList} must be non‑null.</li>
     *   <li>{@code statusList.bits} must be one of {@code 1, 2, 4, 8}.</li>
     *   <li>{@code statusList.statusListData} must be non‑null and non‑blank.</li>
     *   <li>If {@code ttl} is present, it must be a positive integer.</li>
     * </ul>
     *
     * @return {@code true} if all required fields are present and satisfy the
     *         constraints; {@code false} otherwise.
     */
    public boolean hasRequiredClaims(boolean expiryMustBePresent) {
        if (sub == null || sub.isBlank()) {
            return false;
        }
        if (iat == null) {
            return false;
        }

        if (expiryMustBePresent && exp == null) {
            return false;
        }

        //  ttl (optional, must be positive if present) 
        if (ttl != null && ttl <= 0) {
            return false;
        }

        return statusList != null && statusList.hasRequiredClaims();
    }
}
