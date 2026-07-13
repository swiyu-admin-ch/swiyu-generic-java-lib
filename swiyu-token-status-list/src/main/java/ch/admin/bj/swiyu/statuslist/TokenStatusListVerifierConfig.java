package ch.admin.bj.swiyu.statuslist;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class TokenStatusListVerifierConfig {
    /**
     * Flag controlling if issuers of the Reference Token and the Status List Token MUST match.
     */
    @Builder.Default
    private boolean issuerMustMatch = false;
    
}
