package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
public class VerificationQueryPublicStatement extends Statement{
    @JsonProperty("purpose_name")
    private String purposeName;
    @JsonProperty("purpose_description")
    private String purposeDescription;
    @JsonProperty("request")
    private VerificationRequestObject request;

    @NoArgsConstructor
    @Getter
    @Setter
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class VerificationRequestObject {
        private String type;
        private String scope;
        // DCQL query cannot be validated properly here
        private Map<String, Object> query;
    }
}
