package ch.admin.bj.swiyu.tsbuilder;

import com.nimbusds.jwt.JWTClaimsSet;

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
 *     .withKid("did:tdw:QmZyt...#assert-key-01")
 *     .withValidity(Instant.now(), Instant.now().plus(365, ChronoUnit.DAYS))
 *     .withStatus(0, "https://example.com/statuslists/1")
 *     .addNonCompliantActor(
 *         new NcTlsBuilder.NonCompliantActorBuilder("did:tdw:QmBad...#",
 *                                                   "2026-02-25T07:07:35Z",
 *                                                   "Actor is not who they claim to be")
 *             .addReason("de",    "Akteur ist nicht wer er vorgibt zu sein")
 *             .addReason("fr-CH", "L'acteur n'est pas qui il prétend être")
 *             .build()
 *     )
 *     .build();
 * }</pre>
 */
public class NcTlsBuilder extends AbstractTrustStatementBuilder<NcTlsBuilder> implements TrustListStatement {

    private static final String TYP = "swiyu-non-compliance-trust-list-statement+jwt";

    private final List<NonCompliantActor> nonCompliantActors = new ArrayList<>();

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

    /**
     * Not supported for ncTLS – the {@code sub} claim is not defined for this trust statement
     * type by the Swiss Trust Protocol 2.0 specification.
     *
     * @throws TrustStatementValidationException always
     */
    @Override
    public NcTlsBuilder withSubject(String subject) {
        throw new TrustStatementValidationException(
                "sub (subject) is not supported for ncTLS – the non-compliance trust list " +
                "statement does not identify a single subject");
    }

    /**
     * Immutable value object representing a single non-compliant actor entry.
     * <p>
     * Instances are created via {@link NonCompliantActorBuilder}.
     * </p>
     */
    public static final class NonCompliantActor {

        private final Map<String, Object> entry;

        private NonCompliantActor(Map<String, Object> entry) {
            this.entry = Map.copyOf(entry);
        }

        Map<String, Object> toMap() {
            return entry;
        }
    }

    /**
     * Fluent builder for a {@link NonCompliantActor}.
     * <p>
     * Construct with the required fields ({@code actor}, {@code flagged_at},
     * default {@code reason}) and optionally add localized reason variants via
     * {@link #addReason(String, String)}. Call {@link #build()} to produce the
     * immutable {@link NonCompliantActor}.
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
         * Builds and returns an immutable {@link NonCompliantActor}.
         *
         * @return a new {@link NonCompliantActor} containing all configured fields
         */
        public NonCompliantActor build() {
            return new NonCompliantActor(entry);
        }
    }

    // ── Builder methods ───────────────────────────────────────────────────────

    /**
     * Adds a non-compliant actor entry to the trust list.
     * <p>
     * Create the actor via {@link NonCompliantActorBuilder}:
     * <pre>{@code
     * .addNonCompliantActor(
     *     new NcTlsBuilder.NonCompliantActorBuilder(did, flaggedAt, reason)
     *         .addReason("de", "Akteur ist nicht wer er vorgibt zu sein")
     *         .build()
     * )
     * }</pre>
     * Multiple actors may be added by calling this method repeatedly.
     *
     * @param actor the fully built {@link NonCompliantActor}, must not be {@code null}
     * @return this builder for fluent chaining
     * @throws TrustStatementValidationException if {@code actor} is {@code null}
     */
    public NcTlsBuilder addNonCompliantActor(NonCompliantActor actor) {
        if (actor == null) {
            throw new TrustStatementValidationException("actor must not be null");
        }
        nonCompliantActors.add(actor);
        claim("non_compliant_actors", nonCompliantActors.stream()
                .map(NonCompliantActor::toMap)
                .toList());
        return self();
    }

    /**
     * Validates all required claims for the Non-Compliance Trust List Statement.
     * Called by {@link AbstractTrustStatementBuilder#build()} before constructing the JWT.
     * <p>
     * Required: {@code kid}, {@code iat}, {@code exp}, {@code status},
     * at least one entry in {@code non_compliant_actors}.
     * </p>
     *
     * @param claims the fully-built claims snapshot
     * @throws TrustStatementValidationException if any required claim is missing
     */
    @Override
    protected void validateSubclass(JWTClaimsSet claims) {
        validateRequired(claims, "status", "status payload claim is required – call withStatus()");
        validateRequired(claims, "non_compliant_actors",
                "at least one non_compliant_actors entry is required – call addNonCompliantActor()");
    }
}
