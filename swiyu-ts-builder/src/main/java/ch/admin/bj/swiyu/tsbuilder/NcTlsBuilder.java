package ch.admin.bj.swiyu.tsbuilder;

/**
 * Builder for Non-Compliance Trust List Statements (ncTLS).
 * <p>
 * A ncTLS warns actors of known non-compliant or revoked participants within the Swiss trust
 * infrastructure. Each entry records the DID of the bad actor, the timestamp when they were
 * flagged, and an optional localized reason.
 * </p>
 *
 * <p>Required claims: {@code iat}, {@code exp}, {@code status},
 * {@code non_compliant_actors} (non-empty).</p>
 *
 * <p>Fixed header {@code typ}: {@code swiyu-non-compliance-trust-list-statement+jwt}</p>
 */
public class NcTlsBuilder extends AbstractTrustStatementBuilder<NcTlsBuilder> {

    /**
     * Creates a new {@code NcTlsBuilder} and sets the {@code typ} header to
     * {@code swiyu-non-compliance-trust-list-statement+jwt}.
     */
    public NcTlsBuilder() {
        // TODO – setTypHeader("swiyu-non-compliance-trust-list-statement+jwt")
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected NcTlsBuilder self() {
        return this;
    }

    /**
     * Adds an entry for a non-compliant actor to the trust list.
     * <p>
     * The entry is appended to the {@code non_compliant_actors} array as:
     * </p>
     * <pre>{@code
     * {
     *   "actor": "<did>",
     *   "flagged_at": "<flaggedAt>",
     *   "reason#<locale>": "<reason>"
     * }
     * }</pre>
     * <p>
     * {@code flaggedAt} is validated immediately against RFC 3339 format
     * (e.g. {@code 2026-02-25T07:07:35Z}). Multiple actors may be added by calling this method
     * repeatedly.
     * </p>
     *
     * @param did       the DID of the non-compliant actor, must not be {@code null} or blank
     * @param flaggedAt an RFC 3339 compliant date-time string indicating when the actor was
     *                  flagged, must not be {@code null} or blank
     * @param locale    the BCP 47 language tag for {@code reason}, must not be {@code null}
     *                  or blank
     * @param reason    a human-readable reason for the non-compliance flag in the given locale,
     *                  must not be {@code null} or blank
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code flaggedAt} does not conform to RFC 3339
     */
    public NcTlsBuilder addNonCompliantActor(String did, String flaggedAt, String locale, String reason) {
        // TODO – validate flaggedAt RFC 3339; assemble non_compliant_actors entry
        return self();
    }

    /**
     * Validates all required claims and builds the unsigned Non-Compliance Trust List Statement
     * JWT.
     * <p>
     * Required: {@code kid}, {@code iss}, {@code iat}, {@code exp}, {@code status},
     * at least one entry in {@code non_compliant_actors}.
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
