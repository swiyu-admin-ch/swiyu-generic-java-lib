package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class ProtectedVerificationAuthorizationTrustStatement extends TrustStatement{
    @JsonProperty("authorized_fields")
    private List<String> authorizedFields;
}
