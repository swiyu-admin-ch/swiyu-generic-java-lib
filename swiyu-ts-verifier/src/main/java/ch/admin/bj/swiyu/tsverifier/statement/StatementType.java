package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Arrays;
import java.util.Optional;

@Getter
@RequiredArgsConstructor
public enum StatementType {
    /**
     * idTS
     */
    @JsonProperty("swiyu-identity-trust-statement+jwt")
    IDENTITY_TRUST_STATEMENT("swiyu-identity-trust-statement+jwt", IdentityTrustStatement.class),
    /**
     * vqPS
     */
    @JsonProperty("swiyu-verification-query-public-statement+jwt")
    VERIFICATION_QUERY_PUBLIC_STATEMENT("swiyu-verification-query-public-statement+jwt", VerificationQueryPublicStatement.class),
    /**
     * pvaTS
     */
    @JsonProperty("swiyu-protected-verification-authorization-trust-statement+jwt")
    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT("swiyu-protected-verification-authorization-trust-statement+jwt", ProtectedVerificationAuthorizationTrustStatement.class),
    /**
     * piaTS
     */
    @JsonProperty("swiyu-protected-issuance-authorization-trust-statement+jwt")
    PROTECTED_ISSUANCE_AUTHORIZATION_TRUST_STATEMENT("swiyu-protected-issuance-authorization-trust-statement+jwt", ProtectedIssuanceAuthorizationTrustStatement.class),
    /**
     * piTLS
     */
    @JsonProperty("swiyu-protected-issuance-trust-list-statement+jwt")
    PROTECTED_ISSUANCE_TRUST_LIST_STATEMENT("swiyu-protected-issuance-trust-list-statement+jwt", ProtectedIssuanceTrustListStatement.class),
    /**
     * ncTLS
     */
    @JsonProperty("swiyu-non-compliance-trust-list-statement+jwt")
    NON_COMPLIANCE_TRUST_LIST_STATEMENT("swiyu-non-compliance-trust-list-statement+jwt", NonComplianceTrustListStatement.class);


    private final String type;
    private final Class<? extends Statement> statementClass;

    public static Optional<StatementType> getByType(String type) {
        return Arrays.stream(StatementType.values())
                .filter(statementType -> statementType.type.equalsIgnoreCase(type))
                .findAny();
    }
}
