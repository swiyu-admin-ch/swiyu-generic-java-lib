package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/**
 * This statement is provided by verifiers to provide authorization to request protected claims in a presentation from the holder
 */
@Getter
@Setter
@NoArgsConstructor
public class ProtectedVerificationAuthorizationTrustStatement extends TrustStatement{
    
    /**
     * MUST be a non-empty array of strings that specify the name of a field which is authorized to be verified.
     */
    @JsonProperty("authorized_fields")
    private List<String> authorizedFields;
}
