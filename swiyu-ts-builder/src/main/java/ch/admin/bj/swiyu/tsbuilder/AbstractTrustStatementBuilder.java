package ch.admin.bj.swiyu.tsbuilder;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;

import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Abstract base class for all Trust Statement builders.
 * <p>
 * Uses the Curiously Recurring Template Pattern (CRTP) via the type parameter {@code T} to
 * enable a type-safe fluent API across inheritance boundaries. Subclasses must implement
 * {@link #self()} to return {@code this} cast to the concrete type, which allows chaining
 * inherited methods without losing type information.
 * </p>
 *
 * Handles all mandatory JOSE header claims and standard JWT payload claims that are common
 * to every Trust Statement type:
 * <ul>
 *   <li>Header: {@code alg} (fixed {@code ES256}), {@code kid}, {@code profile_version}
 *       (fixed {@code swiss-profile-trust:1.0.0}), {@code typ} (set by concrete subclass)</li>
 *   <li>Payload: {@code sub}, {@code iat}, {@code nbf}, {@code exp}</li>
 * </ul>
 * <p>
 * Note: {@code iss} is intentionally absent. As per the Trust Protocol 2.0 migration notes,
 * {@code iss} is no longer supported – the issuer is unambiguously identified by the
 * mandatory {@code kid} header.
 * </p>
 *
 * <p>Example usage in a subclass:</p>
 * <pre>{@code
 * public class IdTsBuilder extends AbstractTrustStatementBuilder<IdTsBuilder> {
 *     protected IdTsBuilder self() { return this; }
 * }
 * }</pre>
 *
 * @param <T> the concrete builder type, must extend {@code AbstractTrustStatementBuilder<T>}
 */
public abstract class AbstractTrustStatementBuilder<T extends AbstractTrustStatementBuilder<T>> {

    private static final String PROFILE_VERSION = "swiss-profile-trust:1.0.0";
    private static final JWSAlgorithm ALG = JWSAlgorithm.ES256;

    /**
     * Nimbus header builder – accumulates header claims set by this builder and subclasses.
     * Package-private so subclasses in this package can access it directly.
     */
    final JWSHeader.Builder headerBuilder;

    /**
     * Nimbus claims set builder – accumulates payload claims set by this builder and subclasses.
     * Package-private so subclasses in this package can access it directly.
     */
    final JWTClaimsSet.Builder claimsBuilder;

    /** Guards against calling {@link #build()} more than once on the same builder instance. */
    private boolean built = false;

    /**
     * Initialises a new builder instance with pre-populated {@code alg} and
     * {@code profile_version} header claims (fixed per Trust Protocol 2.0).
     */
    protected AbstractTrustStatementBuilder() {
        this.headerBuilder = new JWSHeader.Builder(ALG)
                .customParam("profile_version", PROFILE_VERSION);
        this.claimsBuilder = new JWTClaimsSet.Builder();
    }

    /**
     * Returns the concrete builder instance ({@code this}) typed as {@code T}.
     * <p>
     * Every subclass must implement this method by simply returning {@code this}.
     * It is the key mechanism that makes the CRTP-based fluent API work without unsafe casting.
     * </p>
     *
     * @return {@code this} as the concrete builder type
     */
    protected abstract T self();

    /**
     * Sets the {@code typ} header claim.
     * <p>
     * Called internally by each concrete builder in its constructor
     * using the fixed value defined in the Swiss Trust Protocol 2.0 specification.
     * </p>
     *
     * @param typ the {@code typ} header value (e.g. {@code swiyu-identity-trust-statement+jwt})
     */
    protected void setTypHeader(String typ) {
        headerBuilder.type(new JOSEObjectType(typ));
    }

    /**
     * Sets the {@code kid} protected header claim.
     * <p>
     * The value MUST be an absolute DID with a key reference fragment
     * (e.g. {@code did:tdw:QmZytP...#assert-key-01}).
     * </p>
     *
     * @param kid the absolute DID key reference, must not be {@code null} or blank
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code kid} does not start with {@code did:}
     *                                           or contains no {@code #} key reference fragment
     */
    public T withKid(String kid) {
        if (kid == null || kid.isBlank()) {
            throw new TrustStatementValidationException("kid must not be null or blank");
        }
        if (!kid.startsWith("did:") || !kid.contains("#")) {
            throw new TrustStatementValidationException(
                    "kid must be an absolute DID with a key reference fragment (e.g. did:tdw:...#key-1), got: " + kid);
        }
        headerBuilder.keyID(kid);
        return self();
    }

    /**
     * Sets the {@code sub} (subject) payload claim.
     * <p>
     * The value MUST be a valid DID (e.g. {@code did:tdw:...}).
     * </p>
     *
     * @param subject the subject DID, must not be {@code null} or blank
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code subject} does not start with {@code did:}
     */
    public T withSubject(String subject) {
        validateDid(subject, "sub");
        claimsBuilder.subject(subject);
        return self();
    }

    /**
     * Sets the validity window of the trust statement.
     * <p>
     * Sets {@code iat} (issued-at) and {@code exp} (expiration) from the provided instants.
     * {@code nbf} (not-before) is set equal to {@code issuedAt}.
     * The constraint {@code issuedAt <= expiresAt} is enforced immediately.
     * </p>
     *
     * @param issuedAt  the issuance instant (sets {@code iat} and {@code nbf}),
     *                  must not be {@code null}
     * @param expiresAt the expiration instant (sets {@code exp}), must not be {@code null}
     *                  and must not be before {@code issuedAt}
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code expiresAt} is before {@code issuedAt}
     */
    public T withValidity(Instant issuedAt, Instant expiresAt) {
        return withValidity(issuedAt, issuedAt, expiresAt);
    }

    /**
     * Sets the validity window of the trust statement with an explicit {@code nbf} instant.
     * <p>
     * Use this overload when the not-before time must differ from the issuance time
     * (e.g., for {@code piaTS} where {@code nbf} may be later than {@code iat}).
     * The constraints {@code issuedAt <= notBefore} and {@code notBefore <= expiresAt}
     * are enforced immediately.
     * </p>
     *
     * @param issuedAt   the issuance instant (sets {@code iat}), must not be {@code null}
     * @param notBefore  the not-before instant (sets {@code nbf}), must not be {@code null}
     *                   and must not be before {@code issuedAt}
     * @param expiresAt  the expiration instant (sets {@code exp}), must not be {@code null}
     *                   and must not be before {@code notBefore}
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if temporal ordering constraints are violated
     */
    public T withValidity(Instant issuedAt, Instant notBefore, Instant expiresAt) {
        validateInstantNotNull(issuedAt, "issuedAt");
        validateInstantNotNull(notBefore, "notBefore");
        validateInstantNotNull(expiresAt, "expiresAt");
        validateTemporalOrder(issuedAt, notBefore, "notBefore", "issuedAt");
        validateTemporalOrder(notBefore, expiresAt, "expiresAt", "notBefore");
        claimsBuilder.issueTime(Date.from(issuedAt));
        claimsBuilder.notBeforeTime(Date.from(notBefore));
        claimsBuilder.expirationTime(Date.from(expiresAt));
        return self();
    }

    /**
     * Sets the {@code status} payload claim as a structured Token Status List revocation entry.
     * <p>
     * The resulting JSON structure is:
     * </p>
     * <pre>{@code
     * "status": {
     *   "status_list": {
     *     "idx": <idx>,
     *     "uri": "<uri>"
     *   }
     * }
     * }</pre>
     *
     * @param idx the index of this trust statement in the status list, must be {@code >= 0}
     * @param uri the URL of the status list credential, must not be {@code null} or blank
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code idx} is negative or {@code uri} is blank
     */
    public T withStatus(int idx, String uri) {
        if (idx < 0) {
            throw new TrustStatementValidationException("status idx must be >= 0, got: " + idx);
        }
        if (uri == null || uri.isBlank()) {
            throw new TrustStatementValidationException("status uri must not be null or blank");
        }
        Map<String, Object> statusList = new LinkedHashMap<>();
        statusList.put("idx", idx);
        statusList.put("uri", uri);

        Map<String, Object> status = new LinkedHashMap<>();
        status.put("status_list", statusList);

        claimsBuilder.claim("status", status);
        return self();
    }

    /**
     * Validates that a required claim is present in the claims builder snapshot.
     * <p>
     * Throws {@link TrustStatementValidationException} if the claim is absent.
     * </p>
     *
     * @param claimKey     the payload claim key to check
     * @param errorMessage the exception message to use if validation fails
     * @throws TrustStatementValidationException if the required claim is missing
     */
    protected void validateRequired(String claimKey, String errorMessage) {
        JWTClaimsSet snapshot = claimsBuilder.build();
        if (snapshot.getClaim(claimKey) == null) {
            throw new TrustStatementValidationException(errorMessage);
        }
    }

    /**
     * Validates all required base claims and assembles the final {@link TrustStatementJwt}.
     * <p>
     * Subclasses must call {@code super.build()} at the start of their own {@code build()}
     * override to trigger base-class validation (e.g. {@code kid}, {@code exp})
     * before adding type-specific claim validation.
     * </p>
     * <p>
     * Note: the {@code iss} claim is intentionally not validated here. As per the
     * Trust Protocol 2.0 migration notes, {@code iss} is no longer supported – the issuer
     * is unambiguously identified by the mandatory {@code kid} header.
     * </p>
     * <p>
     * Note: each builder instance is single-use. Calling {@code build()} more than once
     * on the same instance throws {@link TrustStatementValidationException}.
     * </p>
     *
     * @return the fully assembled, unsigned {@link TrustStatementJwt}
     * @throws TrustStatementValidationException if any required base claim is missing or invalid,
     *                                           or if {@code build()} has already been called
     */
    public TrustStatementJwt build() throws TrustStatementValidationException {
        if (built) {
            throw new TrustStatementValidationException(
                    "This builder instance has already been used. Create a new instance for each Trust Statement.");
        }
        built = true;
        JWSHeader header = headerBuilder.build();
        if (header.getKeyID() == null || header.getKeyID().isBlank()) {
            throw new TrustStatementValidationException("kid header claim is required");
        }
        JWTClaimsSet claims = claimsBuilder.build();
        if (claims.getIssueTime() == null) {
            throw new TrustStatementValidationException("iat (issued-at) payload claim is required – call withValidity()");
        }
        if (claims.getNotBeforeTime() == null) {
            throw new TrustStatementValidationException("nbf (not-before) payload claim is required – call withValidity()");
        }
        if (claims.getExpirationTime() == null) {
            throw new TrustStatementValidationException("exp (expiration) payload claim is required – call withValidity()");
        }
        return new TrustStatementJwt(header, claims);
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /**
     * Asserts that the given {@link Instant} is not {@code null}.
     *
     * @param instant   the instant to check
     * @param fieldName the field name used in the error message
     * @throws TrustStatementValidationException if {@code instant} is {@code null}
     */
    private void validateInstantNotNull(Instant instant, String fieldName) {
        if (instant == null) {
            throw new TrustStatementValidationException(fieldName + " must not be null");
        }
    }

    /**
     * Asserts that {@code later} does not precede {@code earlier}.
     *
     * @param earlier      the reference instant (must come first chronologically)
     * @param later        the instant that must not be before {@code earlier}
     * @param laterName    field name of {@code later}, used in the error message
     * @param earlierName  field name of {@code earlier}, used in the error message
     * @throws TrustStatementValidationException if {@code later} is before {@code earlier}
     */
    private void validateTemporalOrder(Instant earlier, Instant later,
                                       String laterName, String earlierName) {
        if (later.isBefore(earlier)) {
            throw new TrustStatementValidationException(
                    laterName + " must not be before " + earlierName
                            + " (" + earlierName + "=" + earlier + ", " + laterName + "=" + later + ")");
        }
    }

    /**
     * Validates that the given value is a syntactically valid DID (starts with {@code did:}).
     *
     * @param did       the DID value to validate
     * @param claimName the claim name used in the error message
     * @throws TrustStatementValidationException if {@code did} is blank or does not start with
     *                                           {@code did:}
     */
    protected void validateDid(String did, String claimName) {
        if (did == null || did.isBlank()) {
            throw new TrustStatementValidationException(claimName + " must not be null or blank");
        }
        if (!did.startsWith("did:")) {
            throw new TrustStatementValidationException(
                    claimName + " must be a valid DID starting with 'did:', got: " + did);
        }
    }

    /**
     * Validates that the given string is a valid UUIDv4.
     *
     * @param uuid      the UUID string to validate
     * @param claimName the claim name used in the error message
     * @throws TrustStatementValidationException if {@code uuid} is blank or not a valid UUIDv4
     */
    protected void validateUuidV4(String uuid, String claimName) {
        if (uuid == null || uuid.isBlank()) {
            throw new TrustStatementValidationException(claimName + " must not be null or blank");
        }
        if (!uuid.matches("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")) {
            throw new TrustStatementValidationException(
                    claimName + " must be a valid UUIDv4 (RFC 9562), got: " + uuid);
        }
    }

    /**
     * Validates that the given string does not exceed a maximum length.
     *
     * @param value     the string to check
     * @param max       the maximum allowed length (inclusive)
     * @param claimName the claim name used in the error message
     * @throws TrustStatementValidationException if {@code value} exceeds {@code max} characters
     */
    protected void validateMaxLength(String value, int max, String claimName) {
        if (value != null && value.length() > max) {
            throw new TrustStatementValidationException(
                    claimName + " must not exceed " + max + " characters, got " + value.length());
        }
    }

    /**
     * Resolves the localized claim key following the BCP 47 convention used by TP2.
     * <p>
     * If {@code locale} is {@code null} or blank, returns {@code baseName} unchanged.
     * Otherwise returns {@code baseName + "#" + locale} (e.g. {@code "entity_name#de-CH"}).
     * </p>
     *
     * @param baseName the base claim name (e.g. {@code "entity_name"})
     * @param locale   the BCP 47 language tag, may be {@code null}
     * @return the locale-suffixed claim key
     */
    protected String localizedKey(String baseName, String locale) {
        if (locale == null || locale.isBlank()) {
            return baseName;
        }
        return baseName + "#" + locale;
    }
}
