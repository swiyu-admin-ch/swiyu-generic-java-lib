package ch.admin.bj.swiyu.tsbuilder;

import com.nimbusds.jwt.JWTClaimsSet;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
public class VqPsBuilder extends AbstractTrustStatementBuilder<VqPsBuilder> implements PublicStatement {

    private static final String TYP = "swiyu-verification-query-public-statement+jwt";
    private static final int MAX_PURPOSE_NAME_LENGTH = 50;
    private static final int MAX_PURPOSE_DESC_LENGTH = 500;

    /**
     * Creates a new {@code VqPsBuilder} and sets the {@code typ} header to
     * {@code swiyu-verification-query-public-statement+jwt}.
     */
    public VqPsBuilder() {
        setTypHeader(TYP);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected VqPsBuilder self() {
        return this;
    }

    /**
     * Adds a non-localized purpose name claim.
     * <p>
     * Serialized as {@code "purpose_name": "<name>"} in the JWT payload.
     * The name must not exceed 50 characters.
     * Use {@link #addPurposeName(String, String)} to add additional localized variants.
     * </p>
     *
     * @param name the purpose name, max 50 characters, must not be {@code null} or blank
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code name} is blank or exceeds 50 characters
     */
    public VqPsBuilder addPurposeName(String name) {
        validatePurposeName(name);
        claim("purpose_name", name);
        return self();
    }

    /**
     * Adds a localized purpose name claim following RFC 5646 / BCP 47 locale tags.
     * <p>
     * Serialized as {@code "purpose_name#<locale>": "<name>"} in the JWT payload.
     * The name must not exceed 50 characters.
     * </p>
     *
     * @param name   the purpose name in the given locale, max 50 characters,
     *               must not be {@code null} or blank
     * @param locale the BCP 47 language tag (e.g. {@code de-CH}, {@code fr}),
     *               must not be {@code null} or blank
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code locale} or {@code name} is blank,
     *                                           or {@code name} exceeds 50 characters
     */
    public VqPsBuilder addPurposeName(String name, String locale) {
        if (locale == null || locale.isBlank()) {
            throw new TrustStatementValidationException(
                    "locale must not be null or blank – use addPurposeName(String name) for a non-localized purpose name");
        }
        validatePurposeName(name);
        claim(localizedKey("purpose_name", locale), name);
        return self();
    }

    private void validatePurposeName(String name) {
        if (name == null || name.isBlank()) {
            throw new TrustStatementValidationException("purpose_name must not be null or blank");
        }
        validateMaxLength(name, MAX_PURPOSE_NAME_LENGTH, "purpose_name");
    }

    /**
     * Adds a non-localized purpose description claim.
     * <p>
     * Serialized as {@code "purpose_description": "<desc>"} in the JWT payload.
     * The description must not exceed 500 characters.
     * Use {@link #addPurposeDesc(String, String)} to add additional localized variants.
     * </p>
     *
     * @param desc the purpose description, max 500 characters, must not be {@code null} or blank
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code desc} is blank or exceeds 500 characters
     */
    public VqPsBuilder addPurposeDesc(String desc) {
        validatePurposeDesc(desc);
        claim("purpose_description", desc);
        return self();
    }

    /**
     * Adds a localized purpose description claim following RFC 5646 / BCP 47 locale tags.
     * <p>
     * Serialized as {@code "purpose_description#<locale>": "<desc>"} in the JWT payload.
     * The description must not exceed 500 characters.
     * </p>
     *
     * @param desc   the purpose description in the given locale, max 500 characters,
     *               must not be {@code null} or blank
     * @param locale the BCP 47 language tag (e.g. {@code de-CH}, {@code fr}),
     *               must not be {@code null} or blank
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code locale} or {@code desc} is blank,
     *                                           or {@code desc} exceeds 500 characters
     */
    public VqPsBuilder addPurposeDesc(String desc, String locale) {
        if (locale == null || locale.isBlank()) {
            throw new TrustStatementValidationException(
                    "locale must not be null or blank – use addPurposeDesc(String desc) for a non-localized purpose description");
        }
        validatePurposeDesc(desc);
        claim(localizedKey("purpose_description", locale), desc);
        return self();
    }

    private void validatePurposeDesc(String desc) {
        if (desc == null || desc.isBlank()) {
            throw new TrustStatementValidationException("purpose_description must not be null or blank");
        }
        validateMaxLength(desc, MAX_PURPOSE_DESC_LENGTH, "purpose_description");
    }

    /**
     * Sets the credential request on the trust statement using a DCQL query object.
     * <p>
     * The request is serialized as:
     * </p>
     * <pre>{@code
     * "request": {
     *   "type": "DCQL",
     *   "scope": "<scope>",
     *   "query": { "credentials": [...] }
     * }
     * }</pre>
     *
     * @param scope     the OpenID4VP scope string, must not be {@code null} or blank
     * @param dcqlQuery the DCQL query as a structured map; each credential query MUST contain
     *                  a {@code meta.vct_values} non-empty array
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code scope} is blank, {@code dcqlQuery}
     *                                           is {@code null}, or any credential query
     *                                           is missing a non-empty {@code meta.vct_values}
     */
    @SuppressWarnings("unchecked")
    public VqPsBuilder withRequest(String scope, Map<String, Object> dcqlQuery) {
        if (scope == null || scope.isBlank()) {
            throw new TrustStatementValidationException("request scope must not be null or blank");
        }
        if (dcqlQuery == null) {
            throw new TrustStatementValidationException("request dcqlQuery must not be null");
        }
        validateDcqlQuery(dcqlQuery);

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("type", "DCQL");
        request.put("scope", scope);
        request.put("query", dcqlQuery);
        claim("request", request);
        return self();
    }

    /**
     * Validates the top-level DCQL query structure.
     * <p>
     * Ensures the {@code credentials} array is present and non-empty,
     * then delegates per-entry validation to {@link #validateCredentialQuery(Map, int)}.
     * </p>
     *
     * @param dcqlQuery the DCQL query map to validate
     * @throws TrustStatementValidationException if the structure is invalid
     */
    private void validateDcqlQuery(Map<String, Object> dcqlQuery) {
        Object credentialsObj = dcqlQuery.get("credentials");
        if (!(credentialsObj instanceof List<?> credentials) || credentials.isEmpty()) {
            throw new TrustStatementValidationException(
                    "dcqlQuery must contain a non-empty 'credentials' array");
        }
        for (int i = 0; i < credentials.size(); i++) {
            Object credObj = credentials.get(i);
            if (!(credObj instanceof Map<?, ?> cred)) {
                throw new TrustStatementValidationException(
                        credentialPath(i) + " must be an object");
            }
            validateCredentialQuery(cred, i);
        }
    }

    /**
     * Returns the error message prefix for a credential entry at the given index,
     * e.g. {@code "dcqlQuery credentials[2]"}.
     */
    private static String credentialPath(int index) {
        return "dcqlQuery credentials[" + index + "]";
    }

    /**
     * Validates a single DCQL Credential Query entry (DCQL §6.1).
     * <p>
     * Enforces the following rules:
     * <ul>
     *   <li>{@code id}: required, non-empty, alphanumeric / underscore / hyphen only</li>
     *   <li>{@code format}: required, non-blank</li>
     *   <li>{@code meta}: required object with non-empty {@code vct_values} array
     *       (TP2 restriction)</li>
     * </ul>
     *
     * @param cred  the credential query map to validate
     * @param index the zero-based index in the credentials array, used in error messages
     * @throws TrustStatementValidationException if any required field is missing or invalid
     */
    private void validateCredentialQuery(Map<?, ?> cred, int index) {
        validateCredentialId(cred, index);
        validateCredentialFormat(cred, index);
        validateCredentialMeta(cred, index);
    }

    private void validateCredentialId(Map<?, ?> cred, int index) {
        Object idObj = cred.get("id");
        if (!(idObj instanceof String id) || id.isBlank()) {
            throw new TrustStatementValidationException(
                    credentialPath(index) + ".id must be a non-empty string");
        }
        if (!id.matches("[A-Za-z0-9_\\-]+")) {
            throw new TrustStatementValidationException(
                    credentialPath(index) + ".id must consist of alphanumeric, "
                            + "underscore, or hyphen characters only, got: " + id);
        }
    }

    private void validateCredentialFormat(Map<?, ?> cred, int index) {
        Object formatObj = cred.get("format");
        if (!(formatObj instanceof String format) || format.isBlank()) {
            throw new TrustStatementValidationException(
                    credentialPath(index) + ".format must be a non-empty string");
        }
    }

    private void validateCredentialMeta(Map<?, ?> cred, int index) {
        Object metaObj = cred.get("meta");
        if (!(metaObj instanceof Map<?, ?> meta)) {
            throw new TrustStatementValidationException(
                    credentialPath(index) + " must contain a 'meta' object");
        }
        Object vctValues = meta.get("vct_values");
        if (!(vctValues instanceof List<?> vct) || vct.isEmpty()) {
            throw new TrustStatementValidationException(
                    credentialPath(index) + ".meta.vct_values must be a non-empty array");
        }
    }

    /**
     * Validates all required claims for the Verification Query Public Statement.
     * Called by {@link AbstractTrustStatementBuilder#build()} before constructing the JWT.
     * <p>
     * Required: {@code kid}, {@code sub}, {@code jti}, {@code iat}, {@code exp},
     * at least one {@code purpose_name}, at least one {@code purpose_description},
     * {@code request}.
     * </p>
     *
     * @param claims the fully-built claims snapshot
     * @throws TrustStatementValidationException if any required claim is missing
     */
    @Override
    protected void validateSubclass(JWTClaimsSet claims) {
        validateRequired(claims, "sub", "sub (subject) payload claim is required");
        validateRequired(claims, "jti", "jti payload claim is required – call withJti()");

        boolean hasPurposeName = claims.getClaims().keySet().stream()
                .anyMatch(k -> k.equals("purpose_name") || k.startsWith("purpose_name#"));
        if (!hasPurposeName) {
            throw new TrustStatementValidationException(
                    "at least one purpose_name claim is required – call addPurposeName()");
        }

        boolean hasPurposeDesc = claims.getClaims().keySet().stream()
                .anyMatch(k -> k.equals("purpose_description") || k.startsWith("purpose_description#"));
        if (!hasPurposeDesc) {
            throw new TrustStatementValidationException(
                    "at least one purpose_description claim is required – call addPurposeDesc()");
        }

        validateRequired(claims, "request", "request payload claim is required – call withRequest()");
    }
}
