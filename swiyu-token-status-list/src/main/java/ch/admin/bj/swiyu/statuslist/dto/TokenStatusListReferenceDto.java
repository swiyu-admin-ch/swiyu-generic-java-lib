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
 * "_sd": [
 * "HvrKX6fPV0v9K_yCVFBiLFHsMaxcD_114Em6VT8x1lg"
 * ],
 * "iss": "https://example.com/issuer",
 * "iat": 1683000000,
 * "exp": 1883000000,
 * "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
 * "status": {
 * "status_list": {
 * "idx": 0,
 * "uri": "https://example.com/statuslists/1"
 * }
 * },
 * "_sd_alg": "sha-256"
 * }
 */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class TokenStatusListReferenceDto {

    @JsonProperty(value = "iss", required = false)
    private String issuer;

    @JsonProperty(value = "status", required = true)
    private TokenStatusListStatus status;

    @Getter
    @Setter
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class TokenStatusListStatus {
        @JsonProperty(value = "status_list", required = true)
        private TokenStatusListStatusListReference statusList;
    }

    @Getter
    @Setter
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class TokenStatusListStatusListReference {
        @JsonProperty(value = "idx", required = true)
        private int index;
        @JsonProperty(value = "uri", required = true)
        private String uri;
    }

    /**
     * Returns the URI that points to the referenced Token Status List.
     *
     * @return the status‑list URI, never {@code null} if {@link #hasRequiredClaims()}
     *         returned {@code true}
     */
    public String getReferencedStatusListUri() {
        return this.status.statusList.uri;
    }

    /**
     * Checks whether this reference DTO points to the supplied
     * {@link TokenStatusListTokenDto}.
     *
     * @param token the status‑list token DTO to compare against
     * @return {@code true} if the {@code uri} stored in this reference equals the
     *         {@code sub} claim of the supplied token DTO
     */
    public boolean referencesStatusListToken(TokenStatusListTokenDto token) {
        return this.getStatus().getStatusList().getUri().equals(token.getSub());
    }

    /**
     * Verifies that the DTO contains every claim that the Status List spec
     * requires for a reference token.
     *
     * @return {@code true} if all mandatory fields are present and valid,
     *         {@code false} otherwise.
     */
    public boolean hasRequiredClaims() {
        if (status == null || status.getStatusList() == null) {
            return false;
        }

        TokenStatusListStatusListReference ref = status.getStatusList();
        if (ref.getUri() == null || ref.getUri().isBlank()) {
            return false;
        }

        // The index must be a non‑negative integer (the spec defines it as a uint)
        return ref.getIndex() >= 0;
    }
}
