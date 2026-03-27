package ch.admin.bj.swiyu.tsbuilder;

/**
 * Builder for Verification Query Public Statements (vqPS).
 * <p>
 * A vqPS provides public transparency on a verifier's data request, including the purpose of
 * the request and the exact credential fields queried via a DCQL expression.
 * </p>
 *
 * <p>Required claims: {@code jti}, {@code sub}, {@code iat}, {@code exp},
 * {@code purpose_name}, {@code purpose_description}, {@code request}.</p>
 *
 * <p>Fixed header {@code typ}: {@code swiyu-verification-query-public-statement+jwt}</p>
 */
public class VqPsBuilder extends AbstractTrustStatementBuilder<VqPsBuilder> {

    /**
     * {@inheritDoc}
     */
    @Override
    protected VqPsBuilder self() {
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
    public VqPsBuilder withJti(String uuid) {
        // TODO – validate UUIDv4
        return self();
    }

    /**
     * Adds a default (non-localized) purpose name claim.
     * <p>
     * Serialized as {@code "purpose_name": "<name>"} in the JWT payload.
     * The name must not exceed 50 characters.
     * </p>
     *
     * @param name the purpose name, max 50 characters, must not be {@code null} or blank
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code name} exceeds 50 characters
     */
    public VqPsBuilder addPurposeName(String name) {
        // TODO – max 50
        return self();
    }

    /**
     * Adds a localized purpose name claim following RFC 5646 / BCP 47 locale tags.
     * <p>
     * Serialized as {@code "purpose_name#<locale>": "<name>"} in the JWT payload.
     * The name must not exceed 50 characters.
     * </p>
     *
     * @param locale the BCP 47 language tag, must not be {@code null} or blank
     * @param name   the purpose name in the given locale, max 50 characters
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code name} exceeds 50 characters
     */
    public VqPsBuilder addPurposeName(String locale, String name) {
        // TODO – max 50
        return self();
    }

    /**
     * Adds a default (non-localized) purpose description claim.
     * <p>
     * Serialized as {@code "purpose_description": "<desc>"} in the JWT payload.
     * The description must not exceed 500 characters.
     * </p>
     *
     * @param desc the purpose description, max 500 characters, must not be {@code null} or blank
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code desc} exceeds 500 characters
     */
    public VqPsBuilder addPurposeDesc(String desc) {
        // TODO – max 500
        return self();
    }

    /**
     * Adds a localized purpose description claim following RFC 5646 / BCP 47 locale tags.
     * <p>
     * Serialized as {@code "purpose_description#<locale>": "<desc>"} in the JWT payload.
     * The description must not exceed 500 characters.
     * </p>
     *
     * @param locale the BCP 47 language tag, must not be {@code null} or blank
     * @param desc   the purpose description in the given locale, max 500 characters
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code desc} exceeds 500 characters
     */
    public VqPsBuilder addPurposeDesc(String locale, String desc) {
        // TODO – max 500
        return self();
    }

    /**
     * Sets the credential request on the trust statement using a DCQL query expression.
     * <p>
     * The request is serialized as:
     * </p>
     * <pre>{@code
     * "request": {
     *   "type": "DCQL",
     *   "scope": "<scope>",
     *   "query": <dcqlQuery>
     * }
     * }</pre>
     *
     * @param scope     the OpenID4VP scope associated with this request, must not be {@code null}
     *                  or blank
     * @param dcqlQuery the DCQL JSON query string, must not be {@code null} or blank
     * @return this builder for fluent chaining
     */
    public VqPsBuilder withRequest(String scope, String dcqlQuery) {
        // TODO – set type=DCQL, scope and query in request object
        return self();
    }

    /**
     * Validates all required claims and builds the unsigned Verification Query Public
     * Statement JWT.
     * <p>
     * Required: {@code kid}, {@code iss}, {@code sub}, {@code jti}, {@code iat}, {@code exp},
     * at least one {@code purpose_name}, at least one {@code purpose_description},
     * {@code request}.
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
