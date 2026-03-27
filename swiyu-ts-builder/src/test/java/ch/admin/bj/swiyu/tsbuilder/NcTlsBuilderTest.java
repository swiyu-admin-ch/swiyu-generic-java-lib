package ch.admin.bj.swiyu.tsbuilder;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Blackbox unit tests for {@link NcTlsBuilder}.
 * <p>
 * Each test verifies observable output (header/payload claims) without any knowledge of
 * internal implementation details. Tests are structured according to the
 * {@code MethodName_StateUnderTest_ExpectedBehavior} convention.
 * </p>
 * <p>
 * Notes from spec analysis:
 * <ul>
 *   <li>{@code iss} is absent (TP2 migration: iss no longer supported).</li>
 *   <li>{@code sub} and {@code nbf} are not required for ncTLS.</li>
 *   <li>{@code non_compliant_actors} is a non-empty array of objects.</li>
 *   <li>Each actor object uses claim key {@code actor} (NOT {@code did}) – the second entry
 *       in the spec example uses {@code did} which is considered a spec error.</li>
 *   <li>{@code reason} is required; additional localized {@code reason#locale} entries are
 *       optional.</li>
 *   <li>{@code flagged_at} MUST be RFC 3339 compliant.</li>
 * </ul>
 * </p>
 */
class NcTlsBuilderTest {

    private static final String VALID_KID       = "did:example:trust-issuer#key-1";
    private static final String VALID_ACTOR_DID = "did:example:badActor";
    private static final String VALID_FLAGGED_AT = "2026-02-25T07:07:35Z";
    private static final String VALID_REASON    = "The issuer is not who they claim to be";
    private static final Instant IAT            = Instant.ofEpochSecond(1690360968L);
    private static final Instant EXP            = Instant.ofEpochSecond(1753432968L);

    // ── Helper ────────────────────────────────────────────────────────────────

    /** Returns a fully configured builder that will pass all required-claim checks. */
    private NcTlsBuilder validBuilder() {
        return new NcTlsBuilder()
                .withKid(VALID_KID)
                .withValidity(IAT, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .addNonCompliantActor(
                        new NcTlsBuilder.NonCompliantActorBuilder(
                                VALID_ACTOR_DID, VALID_FLAGGED_AT, VALID_REASON));
    }

    // ── Header claims ─────────────────────────────────────────────────────────

    @Test
    void build_validInput_headerContainsTypNcTls() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals("swiyu-non-compliance-trust-list-statement+jwt",
                jwt.getHeader().get("typ"));
    }

    @Test
    void build_validInput_headerContainsAlgES256() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals("ES256", jwt.getHeader().get("alg"));
    }

    @Test
    void build_validInput_headerContainsKid() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(VALID_KID, jwt.getHeader().get("kid"));
    }

    @Test
    void build_validInput_headerContainsProfileVersion() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals("swiss-profile-trust:1.0.0", jwt.getHeader().get("profile_version"));
    }

    // ── Payload – iss MUST NOT be present (TP2: iss no longer supported) ────────

    @Test
    void build_validInput_payloadDoesNotContainIss() {
        TrustStatementJwt jwt = validBuilder().build();
        assertFalse(jwt.getPayload().containsKey("iss"),
                "iss must not be present – TP2 removes iss in favour of kid header");
    }

    // ── Payload – sub and nbf are NOT required for ncTLS ──────────────────────

    @Test
    void build_withoutSub_doesNotThrow() {
        assertDoesNotThrow(() -> validBuilder().build(),
                "ncTLS does not require sub");
    }

    @Test
    void build_withoutSub_payloadDoesNotContainSub() {
        TrustStatementJwt jwt = validBuilder().build();
        assertFalse(jwt.getPayload().containsKey("sub"),
                "sub must not be present when not explicitly set");
    }

    // ── Payload – standard claims ──────────────────────────────────────────────

    @Test
    void build_validInput_payloadContainsIatAsEpochSeconds() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(1690360968L, jwt.getPayload().get("iat"));
    }

    @Test
    void build_validInput_payloadContainsExpAsEpochSeconds() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(1753432968L, jwt.getPayload().get("exp"));
    }

    @Test
    void build_twoParamValidity_payloadNbfEqualsIat() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(jwt.getPayload().get("iat"), jwt.getPayload().get("nbf"),
                "2-param withValidity must set nbf == iat");
    }

    // ── Payload – status ──────────────────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void build_validInput_payloadStatusHasCorrectStructure() {
        TrustStatementJwt jwt = validBuilder().build();

        Map<String, Object> status = (Map<String, Object>) jwt.getPayload().get("status");
        assertNotNull(status, "status claim must be present");

        Map<String, Object> statusList = (Map<String, Object>) status.get("status_list");
        assertNotNull(statusList, "status.status_list must be present");
        assertEquals(0, statusList.get("idx"));
        assertEquals("https://example.com/statuslists/1", statusList.get("uri"));
    }

    // ── Payload – non_compliant_actors ────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void build_singleActor_payloadContainsArrayWithOneEntry() {
        TrustStatementJwt jwt = validBuilder().build();

        List<Map<String, Object>> actors =
                (List<Map<String, Object>>) jwt.getPayload().get("non_compliant_actors");
        assertNotNull(actors);
        assertEquals(1, actors.size());
    }

    @Test
    @SuppressWarnings("unchecked")
    void build_singleActor_entryUsesActorKeyNotDid() {
        TrustStatementJwt jwt = validBuilder().build();

        List<Map<String, Object>> actors =
                (List<Map<String, Object>>) jwt.getPayload().get("non_compliant_actors");
        Map<String, Object> entry = actors.get(0);

        assertTrue(entry.containsKey("actor"),
                "entry must use claim key 'actor' (not 'did')");
        assertFalse(entry.containsKey("did"),
                "entry must NOT use claim key 'did' – spec table defines 'actor'");
        assertEquals(VALID_ACTOR_DID, entry.get("actor"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void build_singleActor_entryContainsFlaggedAt() {
        TrustStatementJwt jwt = validBuilder().build();

        List<Map<String, Object>> actors =
                (List<Map<String, Object>>) jwt.getPayload().get("non_compliant_actors");
        assertEquals(VALID_FLAGGED_AT, actors.get(0).get("flagged_at"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void build_singleActor_entryContainsDefaultReason() {
        TrustStatementJwt jwt = validBuilder().build();

        List<Map<String, Object>> actors =
                (List<Map<String, Object>>) jwt.getPayload().get("non_compliant_actors");
        assertEquals(VALID_REASON, actors.get(0).get("reason"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void build_actorWithLocalizedReasons_entryContainsAllReasonKeys() {
        TrustStatementJwt jwt = new NcTlsBuilder()
                .withKid(VALID_KID)
                .withValidity(IAT, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .addNonCompliantActor(
                        new NcTlsBuilder.NonCompliantActorBuilder(
                                VALID_ACTOR_DID, VALID_FLAGGED_AT,
                                "The issuer is not who they claim to be (DE)")
                                .addReason("de",    "The issuer is not who they claim to be (DE)")
                                .addReason("en",    "The issuer is not who they claim to be (EN)")
                                .addReason("fr-CH", "The issuer is not who they claim to be (FR)")
                                .addReason("it-CH", "The issuer is not who they claim to be (IT)")
                                .addReason("rm-CH", "The issuer is not who they claim to be (RM)"))
                .build();

        List<Map<String, Object>> actors =
                (List<Map<String, Object>>) jwt.getPayload().get("non_compliant_actors");
        Map<String, Object> entry = actors.get(0);

        assertEquals("The issuer is not who they claim to be (DE)", entry.get("reason"));
        assertEquals("The issuer is not who they claim to be (DE)", entry.get("reason#de"));
        assertEquals("The issuer is not who they claim to be (EN)", entry.get("reason#en"));
        assertEquals("The issuer is not who they claim to be (FR)", entry.get("reason#fr-CH"));
        assertEquals("The issuer is not who they claim to be (IT)", entry.get("reason#it-CH"));
        assertEquals("The issuer is not who they claim to be (RM)", entry.get("reason#rm-CH"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void build_multipleActors_payloadContainsAllEntries() {
        TrustStatementJwt jwt = new NcTlsBuilder()
                .withKid(VALID_KID)
                .withValidity(IAT, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .addNonCompliantActor(new NcTlsBuilder.NonCompliantActorBuilder(
                        "did:example:badActor1", "2026-02-25T07:07:35Z", "Reason 1"))
                .addNonCompliantActor(new NcTlsBuilder.NonCompliantActorBuilder(
                        "did:example:badActor2", "2025-01-13T07:13:00Z", "Reason 2"))
                .build();

        List<Map<String, Object>> actors =
                (List<Map<String, Object>>) jwt.getPayload().get("non_compliant_actors");
        assertEquals(2, actors.size());
        assertEquals("did:example:badActor1", actors.get(0).get("actor"));
        assertEquals("did:example:badActor2", actors.get(1).get("actor"));
        assertEquals("2026-02-25T07:07:35Z",  actors.get(0).get("flagged_at"));
        assertEquals("2025-01-13T07:13:00Z",  actors.get(1).get("flagged_at"));
    }

    // ── Validation – missing required claims ──────────────────────────────────

    @Test
    void build_missingKid_throwsValidationException() {
        NcTlsBuilder builder = new NcTlsBuilder()
                .withValidity(IAT, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .addNonCompliantActor(new NcTlsBuilder.NonCompliantActorBuilder(
                        VALID_ACTOR_DID, VALID_FLAGGED_AT, VALID_REASON));

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingValidity_throwsValidationException() {
        NcTlsBuilder builder = new NcTlsBuilder()
                .withKid(VALID_KID)
                .withStatus(0, "https://example.com/statuslists/1")
                .addNonCompliantActor(new NcTlsBuilder.NonCompliantActorBuilder(
                        VALID_ACTOR_DID, VALID_FLAGGED_AT, VALID_REASON));

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingStatus_throwsValidationException() {
        NcTlsBuilder builder = new NcTlsBuilder()
                .withKid(VALID_KID)
                .withValidity(IAT, EXP)
                .addNonCompliantActor(new NcTlsBuilder.NonCompliantActorBuilder(
                        VALID_ACTOR_DID, VALID_FLAGGED_AT, VALID_REASON));

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_noActors_throwsValidationException() {
        NcTlsBuilder builder = new NcTlsBuilder()
                .withKid(VALID_KID)
                .withValidity(IAT, EXP)
                .withStatus(0, "https://example.com/statuslists/1");

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    // ── Validation – Fail-Fast in NonCompliantActorBuilder constructor ─────────

    @Test
    void nonCompliantActorBuilder_blankDid_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new NcTlsBuilder.NonCompliantActorBuilder("  ", VALID_FLAGGED_AT, VALID_REASON));
    }

    @Test
    void nonCompliantActorBuilder_blankFlaggedAt_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new NcTlsBuilder.NonCompliantActorBuilder(VALID_ACTOR_DID, "  ", VALID_REASON));
    }

    @Test
    void nonCompliantActorBuilder_invalidRfc3339FlaggedAt_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new NcTlsBuilder.NonCompliantActorBuilder(
                        VALID_ACTOR_DID, "2026-02-25", VALID_REASON));
    }

    @Test
    void nonCompliantActorBuilder_flaggedAtWithoutOffset_throwsValidationException() {
        // ISO local datetime without timezone offset is NOT RFC 3339 compliant
        assertThrows(TrustStatementValidationException.class,
                () -> new NcTlsBuilder.NonCompliantActorBuilder(
                        VALID_ACTOR_DID, "2026-02-25T07:07:35", VALID_REASON));
    }

    @Test
    void nonCompliantActorBuilder_validRfc3339WithPositiveOffset_doesNotThrow() {
        assertDoesNotThrow(() -> new NcTlsBuilder.NonCompliantActorBuilder(
                VALID_ACTOR_DID, "2026-02-25T08:07:35+01:00", VALID_REASON));
    }

    @Test
    void nonCompliantActorBuilder_blankReason_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new NcTlsBuilder.NonCompliantActorBuilder(VALID_ACTOR_DID, VALID_FLAGGED_AT, "  "));
    }

    @Test
    void addNonCompliantActor_nullBuilder_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new NcTlsBuilder().addNonCompliantActor(null));
    }

    // ── Validation – Fail-Fast in NonCompliantActorBuilder.addReason ──────────

    @Test
    void addReason_blankLocale_throwsValidationException() {
        NcTlsBuilder.NonCompliantActorBuilder actor =
                new NcTlsBuilder.NonCompliantActorBuilder(VALID_ACTOR_DID, VALID_FLAGGED_AT, VALID_REASON);
        assertThrows(TrustStatementValidationException.class,
                () -> actor.addReason("  ", "Some reason"));
    }

    @Test
    void addReason_blankReason_throwsValidationException() {
        NcTlsBuilder.NonCompliantActorBuilder actor =
                new NcTlsBuilder.NonCompliantActorBuilder(VALID_ACTOR_DID, VALID_FLAGGED_AT, VALID_REASON);
        assertThrows(TrustStatementValidationException.class,
                () -> actor.addReason("de", "  "));
    }
}

