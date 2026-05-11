package ch.admin.bj.swiyu.tsverifier.statement;


import ch.admin.bj.swiyu.statuslist.dto.TokenStatusListReferenceDto;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Generic class for Trust List Statements; These are List which are signed by the trust provider
 */
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public abstract class TrustListStatement extends Statement implements StatefulStatement {
    /**
     * status reference in a format defined by the swiss-profile-vc
     * For example Token Status List Reference
     */
    @JsonProperty("status")
    private TokenStatusListReferenceDto.TokenStatusListStatus status;

    @JsonIgnore
    @Override
    public String getStatusListUri() {
        return getStatus().getStatusList().getUri();
    }

    @JsonIgnore
    @Override
    public int getStatusIndex() {
        return getStatus().getStatusList().getIndex();
    }

}
