package ch.admin.bj.swiyu.tsbuilder;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builder for Protected Issuance Authorization Trust Statements (piaTS).
 * <p>
 * A piaTS proves that an issuer has state authorization to issue a specific Verifiable Credential
 * type (VCT) within the Swiss trust infrastructure.
 * </p>
 *
 * <p>Required claims: {@code sub}, {@code iat}, {@code nbf}, {@code exp},
 * {@code status}, {@code can_issue}.</p>
 *
 * <p>Fixed header {@code typ}:
 * {@code swiyu-protected-issuance-authorization-trust-statement+jwt}</p>
 */
public class PiaTsBuilder extends AbstractTrustStatementBuilder<PiaTsBuilder> {

    private static final String TYP = "swiyu-protected-issuance-authorization-trust-statement+jwt";
    private static final int MAX_VCT_NAME_LENGTH = 500;
    private static final int MAX_REASON_LENGTH = 50;

    /**
     * Creates a new {@code PiaTsBuilder} and sets the {@code typ} header to
     * {@code swiyu-protected-issuance-authorization-trust-statement+jwt}.
     */
    public PiaTsBuilder() {
        setTypHeader(TYP);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected PiaTsBuilder self() {
        return this;
    }

    /**
     * Sets the {@code can_issue} payload claim declaring that the subject is authorized to
     * issue the given VCT, with a localized VCT name and an optional localized reason.
     * <p>
     * Serialized as a single JSON object (not an array):
     * </p>
     * <pre>{@code
     * "can_issue": {
     *   "vct": "<vct>",
     *   "vct_name":   "<vctName>",   // or "vct_name#<locale>"
     *   "reason":     "<reason>"     // optional, or "reason#<locale>"
     * }
     * }</pre>
     * <p>
     * {@code vctName} must not exceed 500 characters; {@code reason} must not exceed
     * 50 characters.
     * </p>
     *
     * @param vct     the Verifiable Credential Type identifier (e.g.
     *                {@code urn:ch.admin.fedpol.betaid}), must not be {@code null} or blank
     * @param locale  the BCP 47 language tag for {@code vctName} and {@code reason};
     *                may be {@code null} for the default (non-localized) claim
     * @param vctName a human-readable name for the VCT, max 500 characters,
     *                must not be {@code null} or blank
     * @param reason  a human-readable reason why the subject is permitted to issue this
     *                credential, max 50 characters; may be {@code null} if not provided
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code vctName} exceeds 500 characters
     *                                           or {@code reason} exceeds 50 characters
     */
    public PiaTsBuilder withCanIssue(String vct, String locale, String vctName, String reason) {
        if (vct == null || vct.isBlank()) {
            throw new TrustStatementValidationException("can_issue vct must not be null or blank");
        }
        if (vctName == null || vctName.isBlank()) {
            throw new TrustStatementValidationException("can_issue vct_name must not be null or blank");
        }
        validateMaxLength(vctName, MAX_VCT_NAME_LENGTH, "can_issue vct_name");
        if (reason != null) {
            validateMaxLength(reason, MAX_REASON_LENGTH, "can_issue reason");
        }

        Map<String, Object> canIssue = new LinkedHashMap<>();
        canIssue.put("vct", vct);
        canIssue.put(localizedKey("vct_name", locale), vctName);
        if (reason != null && !reason.isBlank()) {
            canIssue.put(localizedKey("reason", locale), reason);
        }
        product.addPayloadClaim("can_issue", canIssue);
        return self();
    }

    /**
     * Validates all required claims and builds the unsigned Protected Issuance Authorization
     * Trust Statement JWT.
     * <p>
     * Required: {@code kid}, {@code sub}, {@code iat}, {@code nbf}, {@code exp},
     * {@code status}, {@code can_issue}.
     * </p>
     *
     * @return the assembled, unsigned {@link TrustStatementJwt}
     * @throws TrustStatementValidationException if any required claim is missing or invalid
     */
    @Override
    public TrustStatementJwt build() throws TrustStatementValidationException {
        super.build();
        validateRequired("sub", "sub (subject) payload claim is required");
        validateRequired("status", "status payload claim is required – call withStatus()");
        validateRequired("can_issue", "can_issue payload claim is required – call withCanIssue()");
        return product;
    }
}
