package ch.admin.bj.swiyu.tsbuilder;

import java.util.List;

/**
 * Builder for Protected Issuance Trust List Statements (piTLS).
 * <p>
 * A piTLS defines an exhaustive list of Verifiable Credential Types (VCTs) whose issuance
 * is protected within the Swiss trust infrastructure.
 * </p>
 *
 * <p>Required claims: {@code jti}, {@code iss}, {@code iat}, {@code nbf}, {@code exp},
 * {@code status}, {@code vct_values}.</p>
 *
 * <p>Fixed header {@code typ}: {@code swiyu-protected-issuance-trust-list-statement+jwt}</p>
 */
public class PiTlsBuilder extends AbstractTrustStatementBuilder<PiTlsBuilder> {

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
        // TODO – validate UUIDv4
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
        // TODO – validate not empty
        return self();
    }

    /**
     * Validates all required claims and builds the unsigned Protected Issuance Trust List
     * Statement JWT.
     * <p>
     * Required: {@code kid}, {@code iss}, {@code jti}, {@code iat}, {@code nbf}, {@code exp},
     * {@code status}, {@code vct_values} (non-empty).
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
