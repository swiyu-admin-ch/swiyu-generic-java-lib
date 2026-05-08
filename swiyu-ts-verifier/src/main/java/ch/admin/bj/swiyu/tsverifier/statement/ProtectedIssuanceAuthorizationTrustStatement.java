package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * This statement is provided by issuers as proof of state authorization to issue protected VCs .
 */
@Getter
@Setter
@NoArgsConstructor
public class ProtectedIssuanceAuthorizationTrustStatement extends TrustStatement {

    @JsonProperty("can_issue")
    private ProtectedIssuanceAuthorizationObject canIssue;

    /**
     * Defines the scope and descriptive details of the authorization.
     */
    @Getter
    @Setter
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ProtectedIssuanceAuthorizationObject {
        @JsonProperty("vct")
        private String vct;
        @JsonProperty("vct_name")
        private String vctName;
        @JsonProperty("reason")
        private String reason;
    }
}
