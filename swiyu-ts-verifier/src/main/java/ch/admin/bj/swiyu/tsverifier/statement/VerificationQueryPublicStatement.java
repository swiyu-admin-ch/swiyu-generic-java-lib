package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Map;

/**
 * This statement is provided by verifiers to provide public transparency on their intended verification scope.
 */
@Getter
@Setter
@NoArgsConstructor
public class VerificationQueryPublicStatement extends Statement{
    /**
     * a human readable string defining the purpose of this verification
     */
    @JsonProperty("purpose_name")
    private String purposeName;
    /**
     * a human readable string defining the purpose of this verification
     */
    @JsonProperty("purpose_description")
    private String purposeDescription;
    /**
     * The Verification Request which has been published
     */
    @JsonProperty("request")
    private VerificationRequestObject request;

    /**
     * Verification Request Object holding detailed information to the verification. 
     * This object is also used as source for the DCQL query for creating a verification presentation (vp_token).
     */
    @NoArgsConstructor
    @Getter
    @Setter
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class VerificationRequestObject {
        /**
         * Verification Type, for example DCQL
         */
        private String type;
        /**
         * A scope parameter as defined in OID4VP
         */
        private String scope;
        /**
         * Only present in type is DCQL; The DCQL query for the presentation request.
         */
        private Map<String, Object> query;
    }
}
