package ch.admin.bj.swiyu.tsbuilder;

import java.util.List;

/**
 * Builder for Protected Verification Authorization Trust Statements (pvaTS).
 * <p>
 * A pvaTS grants a verifier the authorization to request specific protected credential fields
 * (e.g. personal administrative numbers) from a holder.
 * </p>
 *
 * <p>Required claims: {@code jti}, {@code sub}, {@code iat}, {@code exp},
 * {@code status}, {@code authorized_fields}.</p>
 *
 * <p>Fixed header {@code typ}:
 * {@code swiyu-protected-verification-authorization-trust-statement+jwt}</p>
 */
public class PvaTsBuilder extends AbstractTrustStatementBuilder<PvaTsBuilder> {

    private static final String TYP = "swiyu-protected-verification-authorization-trust-statement+jwt";

    /**
     * Creates a new {@code PvaTsBuilder} and sets the {@code typ} header to
     * {@code swiyu-protected-verification-authorization-trust-statement+jwt}.
     */
    public PvaTsBuilder() {
        setTypHeader(TYP);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected PvaTsBuilder self() {
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
    public PvaTsBuilder withJti(String uuid) {
        validateUuidV4(uuid, "jti");
        claimsBuilder.jwtID(uuid);
        return self();
    }

    /**
     * Sets the list of credential fields the verifier is authorized to request.
     * <p>
     * Serialized as a non-empty JSON array under the {@code authorized_fields} claim.
     * At least one field must be specified.
     * </p>
     *
     * @param fields the non-empty list of authorized field identifiers
     *               (e.g. {@code ["personal_administrative_number"]}),
     *               must not be {@code null} or empty
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code fields} is {@code null} or empty
     */
    public PvaTsBuilder withAuthorizedFields(List<String> fields) {
        if (fields == null || fields.isEmpty()) {
            throw new TrustStatementValidationException(
                    "authorized_fields must not be null or empty");
        }
        claimsBuilder.claim("authorized_fields", fields);
        return self();
    }

    /**
     * Validates all required claims and builds the unsigned Protected Verification Authorization
     * Trust Statement JWT.
     * <p>
     * Required: {@code kid}, {@code iss}, {@code sub}, {@code jti}, {@code iat}, {@code exp},
     * {@code status}, {@code authorized_fields} (non-empty).
     * </p>
     *
     * @return the assembled, unsigned {@link TrustStatementJwt}
     * @throws TrustStatementValidationException if any required claim is missing or invalid
     */
    @Override
    public TrustStatementJwt build() throws TrustStatementValidationException {
        TrustStatementJwt ts = super.build();
        validateRequired("sub", "sub (subject) payload claim is required");
        validateRequired("status", "status payload claim is required – call withStatus()");
        validateRequired("jti", "jti payload claim is required – call withJti()");
        validateRequired("authorized_fields",
                "authorized_fields payload claim is required – call withAuthorizedFields()");
        return ts;
    }
}
