package ch.admin.bj.swiyu.tsbuilder;

import java.util.List;

/**
 * Builder for Protected Issuance Trust List Statements (piTLS).
 * <p>
 * A piTLS defines an exhaustive list of Verifiable Credential Types (VCTs) whose issuance
 * is protected within the Swiss trust infrastructure.
 * </p>
 *
 * <p>Required claims: {@code jti}, {@code iat}, {@code nbf}, {@code exp},
 * {@code status}, {@code vct_values}.</p>
 *
 * <p>Fixed header {@code typ}: {@code swiyu-protected-issuance-trust-list-statement+jwt}</p>
 */
public class PiTlsBuilder extends AbstractTrustStatementBuilder<PiTlsBuilder> {

    private static final String TYP = "swiyu-protected-issuance-trust-list-statement+jwt";

    /**
     * Creates a new {@code PiTlsBuilder} and sets the {@code typ} header to
     * {@code swiyu-protected-issuance-trust-list-statement+jwt}.
     */
    public PiTlsBuilder() {
        setTypHeader(TYP);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected PiTlsBuilder self() {
        return this;
    }

    /**
     * Sets the {@code jti} claim with a UUIDv4 identifier for this trust statement.
     * <p>
     * The provided value is validated immediately against UUID version 4 format (RFC 9562).
     * </p>
     *
     * @param uuid a valid UUIDv4 string, must not be {@code null} or blank
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code uuid} is not a valid UUIDv4
     */
    public PiTlsBuilder withJti(String uuid) {
        validateUuidV4(uuid, "jti");
        claimsBuilder.jwtID(uuid);
        return self();
    }

    /**
     * Sets the list of protected Verifiable Credential Type identifiers for this trust list
     * statement.
     * <p>
     * Serialized as a non-empty JSON array under the {@code vct_values} claim.
     * At least one VCT identifier must be provided.
     * </p>
     *
     * @param vctValues the non-empty list of VCT identifiers
     *                  (e.g. {@code ["urn:ch.admin.fedpol.eid"]}),
     *                  must not be {@code null} or empty
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code vctValues} is {@code null} or empty
     */
    public PiTlsBuilder withVctValues(List<String> vctValues) {
        if (vctValues == null || vctValues.isEmpty()) {
            throw new TrustStatementValidationException("vct_values must not be null or empty");
        }
        claimsBuilder.claim("vct_values", vctValues);
        return self();
    }

    /**
     * Validates all required claims and builds the unsigned Protected Issuance Trust List
     * Statement JWT.
     * <p>
     * Required: {@code kid}, {@code jti}, {@code iat}, {@code nbf}, {@code exp},
     * {@code status}, {@code vct_values} (non-empty).
     * </p>
     *
     * @return the assembled, unsigned {@link TrustStatementJwt}
     * @throws TrustStatementValidationException if any required claim is missing or invalid
     */
    @Override
    public TrustStatementJwt build() throws TrustStatementValidationException {
        TrustStatementJwt ts = super.build();
        validateRequired("status", "status payload claim is required – call withStatus()");
        validateRequired("jti", "jti payload claim is required – call withJti()");
        validateRequired("vct_values", "vct_values payload claim is required – call withVctValues()");
        return ts;
    }
}
