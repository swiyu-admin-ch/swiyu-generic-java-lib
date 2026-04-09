package ch.admin.bj.swiyu.tsbuilder;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
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

    private static final String VALID_KID       = "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch:api:v1:did#assert-key-01";
    private static final String VALID_ACTOR_DID = "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRBB1:identifier.admin.ch:api:v1:did";
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
                                VALID_ACTOR_DID, VALID_FLAGGED_AT, VALID_REASON).build());
    }

    // ── Header claims ─────────────────────────────────────────────────────────

    @Test
    void build_validInput_headerContainsTypNcTls() {
        SignedJWT jwt = validBuilder().build();
        assertEquals("swiyu-non-compliance-trust-list-statement+jwt",
                jwt.getHeader().getType().getType());
    }

    @Test
    void build_validInput_headerContainsAlgES256() {
        SignedJWT jwt = validBuilder().build();
        assertEquals("ES256", jwt.getHeader().getAlgorithm().getName());
    }

    @Test
    void build_validInput_headerContainsKid() {
        SignedJWT jwt = validBuilder().build();
        assertEquals(VALID_KID, jwt.getHeader().getKeyID());
    }

    @Test
    void build_validInput_headerContainsProfileVersion() {
        SignedJWT jwt = validBuilder().build();
        assertEquals("swiss-profile-trust:1.0.0", jwt.getHeader().getCustomParam("profile_version"));
    }

    // ── Payload – iss MUST NOT be present (TP2: iss no longer supported) ────────

    @Test
    void build_validInput_payloadDoesNotContainIss() throws ParseException {
        SignedJWT jwt = validBuilder().build();
        assertFalse(jwt.getJWTClaimsSet().getClaim("iss") != null,
                "iss must not be present – TP2 removes iss in favour of kid header");
    }

    // ── Payload – sub and nbf are NOT required for ncTLS ──────────────────────

    @Test
    void build_withoutSub_doesNotThrow() {
        assertDoesNotThrow(() -> validBuilder().build(),
                "ncTLS does not require sub");
    }

    @Test
    void build_withoutSub_payloadDoesNotContainSub() throws ParseException {
        SignedJWT jwt = validBuilder().build();
        assertFalse(jwt.getJWTClaimsSet().getClaims().containsKey("sub"),
                "sub must not be present when not explicitly set");
    }

    @Test
    void withSubject_always_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new NcTlsBuilder().withSubject(VALID_ACTOR_DID),
                "sub is not supported for ncTLS and must always throw");
    }

    // ── Payload – standard claims ──────────────────────────────────────────────

    @Test
    void build_validInput_payloadContainsIatAsEpochSeconds() throws ParseException {
        SignedJWT jwt = validBuilder().build();
        assertEquals(1690360968L, jwt.getJWTClaimsSet().getIssueTime().toInstant().getEpochSecond());
    }

    @Test
    void build_validInput_payloadContainsExpAsEpochSeconds() throws ParseException {
        SignedJWT jwt = validBuilder().build();
        assertEquals(1753432968L, jwt.getJWTClaimsSet().getExpirationTime().toInstant().getEpochSecond());
    }

    @Test
    void build_twoParamValidity_payloadNbfEqualsIat() throws ParseException {
        SignedJWT jwt = validBuilder().build();
        assertEquals(jwt.getJWTClaimsSet().getIssueTime().toInstant().getEpochSecond(), jwt.getJWTClaimsSet().getNotBeforeTime().toInstant().getEpochSecond(),
                "2-param withValidity must set nbf == iat");
    }

    // ── Payload – status ──────────────────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void build_validInput_payloadStatusHasCorrectStructure() throws ParseException {
        SignedJWT jwt = validBuilder().build();

        Map<String, Object> status = (Map<String, Object>) jwt.getJWTClaimsSet().getClaim("status");
        assertNotNull(status, "status claim must be present");

        Map<String, Object> statusList = (Map<String, Object>) status.get("status_list");
        assertNotNull(statusList, "status.status_list must be present");
        assertEquals(0, statusList.get("idx"));
        assertEquals("https://example.com/statuslists/1", statusList.get("uri"));
    }

    // ── Payload – non_compliant_actors ────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void build_singleActor_payloadContainsArrayWithOneEntry() throws ParseException {
        SignedJWT jwt = validBuilder().build();

        List<Map<String, Object>> actors =
                (List<Map<String, Object>>) jwt.getJWTClaimsSet().getClaims().get("non_compliant_actors");
        assertNotNull(actors);
        assertEquals(1, actors.size());
    }

    @Test
    @SuppressWarnings("unchecked")
    void build_singleActor_entryUsesActorKeyNotDid() throws ParseException {
        SignedJWT jwt = validBuilder().build();

        List<Map<String, Object>> actors =
                (List<Map<String, Object>>) jwt.getJWTClaimsSet().getClaim("non_compliant_actors");
        Map<String, Object> entry = actors.get(0);

        assertTrue(entry.containsKey("actor"),
                "entry must use claim key 'actor' (not 'did')");
        assertFalse(entry.containsKey("did"),
                "entry must NOT use claim key 'did' – spec table defines 'actor'");
        assertEquals(VALID_ACTOR_DID, entry.get("actor"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void build_singleActor_entryContainsFlaggedAt() throws ParseException {
        SignedJWT jwt = validBuilder().build();

        List<Map<String, Object>> actors =
                (List<Map<String, Object>>) jwt.getJWTClaimsSet().getClaims().get("non_compliant_actors");
        assertEquals(VALID_FLAGGED_AT, actors.get(0).get("flagged_at"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void build_singleActor_entryContainsDefaultReason() throws ParseException {
        SignedJWT jwt = validBuilder().build();

        List<Map<String, Object>> actors =
                (List<Map<String, Object>>) jwt.getJWTClaimsSet().getClaims().get("non_compliant_actors");
        assertEquals(VALID_REASON, actors.get(0).get("reason"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void build_actorWithLocalizedReasons_entryContainsAllReasonKeys() throws ParseException {
        SignedJWT jwt = new NcTlsBuilder()
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
                                .addReason("rm-CH", "The issuer is not who they claim to be (RM)")
                                .build())
                .build();

        List<Map<String, Object>> actors =
                (List<Map<String, Object>>) jwt.getJWTClaimsSet().getClaims().get("non_compliant_actors");
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
    void build_multipleActors_payloadContainsAllEntries() throws ParseException {
        SignedJWT jwt = new NcTlsBuilder()
                .withKid(VALID_KID)
                .withValidity(IAT, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .addNonCompliantActor(new NcTlsBuilder.NonCompliantActorBuilder(
                        "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRCC1:identifier.admin.ch:api:v1:did", "2026-02-25T07:07:35Z", "Reason 1").build())
                .addNonCompliantActor(new NcTlsBuilder.NonCompliantActorBuilder(
                        "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRDD1:identifier.admin.ch:api:v1:did", "2025-01-13T07:13:00Z", "Reason 2").build())
                .build();

        List<Map<String, Object>> actors =
                (List<Map<String, Object>>) jwt.getJWTClaimsSet().getClaims().get("non_compliant_actors");
        assertEquals(2, actors.size());
        assertEquals("did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRCC1:identifier.admin.ch:api:v1:did", actors.get(0).get("actor"));
        assertEquals("did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRDD1:identifier.admin.ch:api:v1:did", actors.get(1).get("actor"));
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
                        VALID_ACTOR_DID, VALID_FLAGGED_AT, VALID_REASON).build());

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingValidity_throwsValidationException() {
        NcTlsBuilder builder = new NcTlsBuilder()
                .withKid(VALID_KID)
                .withStatus(0, "https://example.com/statuslists/1")
                .addNonCompliantActor(new NcTlsBuilder.NonCompliantActorBuilder(
                        VALID_ACTOR_DID, VALID_FLAGGED_AT, VALID_REASON).build());

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingStatus_throwsValidationException() {
        NcTlsBuilder builder = new NcTlsBuilder()
                .withKid(VALID_KID)
                .withValidity(IAT, EXP)
                .addNonCompliantActor(new NcTlsBuilder.NonCompliantActorBuilder(
                        VALID_ACTOR_DID, VALID_FLAGGED_AT, VALID_REASON).build());

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

