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

    /**
     * Flag controlling if the expiry of the Status List Token MUST be present (which is required by Swiss Profile)
     */
    @Builder.Default
    private boolean expiryMustBePresent = true;
}
