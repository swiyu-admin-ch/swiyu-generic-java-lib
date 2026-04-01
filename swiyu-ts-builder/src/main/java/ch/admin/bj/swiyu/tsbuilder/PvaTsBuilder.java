package ch.admin.bj.swiyu.tsbuilder;

import com.nimbusds.jwt.JWTClaimsSet;

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
     * Validates all required claims for the Protected Verification Authorization Trust Statement.
     * Called by {@link AbstractTrustStatementBuilder#build()} before constructing the JWT.
     * <p>
     * Required: {@code kid}, {@code sub}, {@code jti}, {@code iat}, {@code exp},
     * {@code status}, {@code authorized_fields} (non-empty).
     * </p>
     *
     * @param claims the fully-built claims snapshot
     * @throws TrustStatementValidationException if any required claim is missing
     */
    @Override
    protected void validateSubclass(JWTClaimsSet claims) {
        validateRequired(claims, "sub", "sub (subject) payload claim is required");
        validateRequired(claims, "status", "status payload claim is required – call withStatus()");
        validateRequired(claims, "jti", "jti payload claim is required – call withJti()");
        validateRequired(claims, "authorized_fields",
                "authorized_fields payload claim is required – call withAuthorizedFields()");
    }
}
