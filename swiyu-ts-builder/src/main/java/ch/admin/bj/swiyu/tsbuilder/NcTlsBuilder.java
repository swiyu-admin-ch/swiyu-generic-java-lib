package ch.admin.bj.swiyu.tsbuilder;

import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builder for Non-Compliance Trust List Statements (ncTLS).
 * <p>
 * A ncTLS warns actors of known non-compliant or revoked participants within the Swiss trust
 * infrastructure. Each entry records the DID of the bad actor, the timestamp when they were
 * flagged, and one or more (optionally localized) reasons.
 * </p>
 *
 * <p>Required claims: {@code iat}, {@code exp}, {@code status},
 * {@code non_compliant_actors} (non-empty).</p>
 *
 * <p>Fixed header {@code typ}: {@code swiyu-non-compliance-trust-list-statement+jwt}</p>
 *
 * <p>Usage example (multiple locales per entry):
 * <pre>{@code
 * new NcTlsBuilder()
 *     .withKid("did:example:trust-issuer#key-1")
 *     .withValidity(Instant.now(), Instant.now().plus(365, ChronoUnit.DAYS))
 *     .withStatus(0, "https://example.com/statuslists/1")
 *     .addNonCompliantActor(
 *         new NcTlsBuilder.NonCompliantActorBuilder("did:example:badActor",
 *                                                   "2026-02-25T07:07:35Z",
 *                                                   "Actor is not who they claim to be")
 *             .addReason("de",    "Akteur ist nicht wer er vorgibt zu sein")
 *             .addReason("fr-CH", "L'acteur n'est pas qui il prétend être")
 *     )
 *     .build();
 * }</pre>
 */
public class NcTlsBuilder extends AbstractTrustStatementBuilder<NcTlsBuilder> {

    private static final String TYP = "swiyu-non-compliance-trust-list-statement+jwt";

    private final List<Map<String, Object>> nonCompliantActors = new ArrayList<>();

    /**
     * Creates a new {@code NcTlsBuilder} and sets the {@code typ} header to
     * {@code swiyu-non-compliance-trust-list-statement+jwt}.
     */
    public NcTlsBuilder() {
        setTypHeader(TYP);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected NcTlsBuilder self() {
        return this;
    }

    // ── Inner Builder ─────────────────────────────────────────────────────────

    /**
     * Fluent builder for a single {@code non_compliant_actors} entry.
     * <p>
     * Construct with the required fields ({@code actor}, {@code flagged_at},
     * default {@code reason}) and optionally add localized reason variants via
     * {@link #addReason(String, String)}.
     * </p>
     */
    public static class NonCompliantActorBuilder {

        private final Map<String, Object> entry = new LinkedHashMap<>();

        /**
         * Creates a new actor entry with all required fields.
         *
         * @param did       the DID of the bad actor, must not be {@code null} or blank
         * @param flaggedAt an RFC 3339 compliant timestamp string (e.g.
         *                  {@code 2026-02-25T07:07:35Z}), must not be {@code null} or blank
         * @param reason    the default (non-localized) human-readable reason,
         *                  must not be {@code null} or blank
         * @throws TrustStatementValidationException if {@code flaggedAt} does not conform to
         *                                           RFC 3339 or any required field is blank
         */
        public NonCompliantActorBuilder(String did, String flaggedAt, String reason) {
            if (did == null || did.isBlank()) {
                throw new TrustStatementValidationException(
                        "non_compliant_actor actor must not be null or blank");
            }
            if (flaggedAt == null || flaggedAt.isBlank()) {
                throw new TrustStatementValidationException(
                        "non_compliant_actor flagged_at must not be null or blank");
            }
            try {
                DateTimeFormatter.ISO_OFFSET_DATE_TIME.parse(flaggedAt);
            } catch (DateTimeParseException e) {
                throw new TrustStatementValidationException(
                        "non_compliant_actor flagged_at must be a valid RFC 3339 timestamp "
                                + "(e.g. 2026-02-25T07:07:35Z), got: " + flaggedAt);
            }
            if (reason == null || reason.isBlank()) {
                throw new TrustStatementValidationException(
                        "non_compliant_actor reason must not be null or blank");
            }
            entry.put("actor", did);
            entry.put("flagged_at", flaggedAt);
            entry.put("reason", reason);
        }

        /**
         * Adds a localized reason claim following BCP 47 / RFC 5646 locale tags.
         * <p>
         * Serialized as {@code "reason#<locale>"} in the actor entry object,
         * e.g. {@code "reason#de": "Akteur ist nicht wer er vorgibt zu sein"}.
         * </p>
         *
         * @param locale the BCP 47 language tag, must not be {@code null} or blank
         * @param reason the reason in the given locale, must not be {@code null} or blank
         * @return this actor builder for fluent chaining
         * @throws TrustStatementValidationException if {@code locale} or {@code reason}
         *                                           is blank
         */
        public NonCompliantActorBuilder addReason(String locale, String reason) {
            if (locale == null || locale.isBlank()) {
                throw new TrustStatementValidationException(
                        "non_compliant_actor reason locale must not be null or blank");
            }
            if (reason == null || reason.isBlank()) {
                throw new TrustStatementValidationException(
                        "non_compliant_actor reason must not be null or blank");
            }
            entry.put("reason#" + locale, reason);
            return this;
        }

        /**
         * Returns the assembled entry map.
         *
         * @return an unmodifiable snapshot of the entry
         */
        Map<String, Object> build() {
            return new LinkedHashMap<>(entry);
        }
    }

    // ── Builder methods ───────────────────────────────────────────────────────

    /**
     * Adds a non-compliant actor entry to the trust list using a
     * {@link NonCompliantActorBuilder}.
     * <p>
     * Multiple actors may be added by calling this method repeatedly.
     * </p>
     *
     * @param actorBuilder the fully configured actor builder, must not be {@code null}
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code actorBuilder} is {@code null}
     */
    public NcTlsBuilder addNonCompliantActor(NonCompliantActorBuilder actorBuilder) {
        if (actorBuilder == null) {
            throw new TrustStatementValidationException(
                    "actorBuilder must not be null");
        }
        nonCompliantActors.add(actorBuilder.build());
        // Eagerly overwrite so the builder always reflects the current list.
        claimsBuilder.claim("non_compliant_actors", nonCompliantActors);
        return self();
    }

    /**
     * Validates all required claims and builds the unsigned Non-Compliance Trust List Statement
     * JWT.
     * <p>
     * Required: {@code kid}, {@code iat}, {@code exp}, {@code status},
     * at least one entry in {@code non_compliant_actors}.
     * </p>
     *
     * @return the assembled, unsigned {@link TrustStatementJwt}
     * @throws TrustStatementValidationException if any required claim is missing or invalid
     */
    @Override
    public TrustStatementJwt build() throws TrustStatementValidationException {
        TrustStatementJwt ts = super.build();
        validateRequired("status", "status payload claim is required – call withStatus()");
        if (nonCompliantActors.isEmpty()) {
            throw new TrustStatementValidationException(
                    "at least one non_compliant_actors entry is required – call addNonCompliantActor()");
        }
        return ts;
    }
}
