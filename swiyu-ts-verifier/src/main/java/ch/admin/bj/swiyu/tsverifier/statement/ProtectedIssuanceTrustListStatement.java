package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class ProtectedIssuanceTrustListStatement extends TrustListStatement{
    @JsonProperty("vct_values")
    private List<String> vctValues;

    @JsonIgnore
    public boolean isVctProtected(String vct) {
        return vctValues.contains(vct);
    }
}
