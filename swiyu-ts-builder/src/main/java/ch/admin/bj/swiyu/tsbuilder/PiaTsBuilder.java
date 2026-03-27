package ch.admin.bj.swiyu.tsbuilder;

/**
 * Builder for Protected Issuance Authorization Trust Statements (piaTS).
 * <p>
 * A piaTS proves that an issuer has state authorization to issue specific Verifiable Credential
 * types (VCTs) within the Swiss trust infrastructure.
 * </p>
 *
 * <p>Required claims: {@code sub}, {@code iat}, {@code nbf}, {@code exp},
 * {@code status}, {@code can_issue}.</p>
 *
 * <p>Fixed header {@code typ}:
 * {@code swiyu-protected-issuance-authorization-trust-statement+jwt}</p>
 */
public class PiaTsBuilder extends AbstractTrustStatementBuilder<PiaTsBuilder> {

    /**
     * Creates a new {@code PiaTsBuilder} and sets the {@code typ} header to
     * {@code swiyu-protected-issuance-authorization-trust-statement+jwt}.
     */
    public PiaTsBuilder() {
        // TODO – setTypHeader("swiyu-protected-issuance-authorization-trust-statement+jwt")
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected PiaTsBuilder self() {
        return this;
    }

    /**
     * Adds an entry declaring that the subject is authorized to issue the given VCT,
     * with a localized VCT name and an optional localized reason.
     * <p>
     * The entry is appended to the {@code can_issue} array as:
     * </p>
     * <pre>{@code
     * {
     *   "vct": "<vct>",
     *   "vct_name#<locale>": "<vctName>",
     *   "reason#<locale>": "<reason>"   // optional
     * }
     * }</pre>
     * <p>
     * {@code vctName} must not exceed 500 characters; {@code reason} must not exceed 50
     * characters. Multiple VCTs may be registered by calling this method repeatedly.
     * </p>
     *
     * @param vct     the Verifiable Credential Type identifier (e.g.
     *                {@code urn:ch.admin.fedpol.eid}), must not be {@code null} or blank
     * @param locale  the BCP 47 language tag for {@code vctName} and {@code reason},
     *                must not be {@code null} or blank
     * @param vctName a human-readable name for the VCT in the given locale,
     *                max 500 characters, must not be {@code null} or blank
     * @param reason  a human-readable reason for the authorization in the given locale,
     *                max 50 characters; may be {@code null} if no reason is provided
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code vctName} exceeds 500 characters
     *                                           or {@code reason} exceeds 50 characters
     */
    public PiaTsBuilder addCanIssue(String vct, String locale, String vctName, String reason) {
        // TODO – validate vctName max 500, reason max 50; assemble can_issue object
        return self();
    }

    /**
     * Validates all required claims and builds the unsigned Protected Issuance Authorization
     * Trust Statement JWT.
     * <p>
     * Required: {@code kid}, {@code iss}, {@code sub}, {@code iat}, {@code nbf}, {@code exp},
     * {@code status}, at least one entry in {@code can_issue}.
     * </p>
     *
     * @return the assembled, unsigned {@link TrustStatementJwt}
     * @throws TrustStatementValidationException if any required claim is missing or invalid
     */
    @Override
    public TrustStatementJwt build() throws TrustStatementValidationException {
        // TODO
        return null;
    }
}
