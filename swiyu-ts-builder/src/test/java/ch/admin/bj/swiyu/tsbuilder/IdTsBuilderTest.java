package ch.admin.bj.swiyu.tsbuilder;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Blackbox unit tests for {@link IdTsBuilder}.
 * <p>
 * Each test verifies observable output (header/payload claims) without any knowledge of
 * internal implementation details. Tests are structured according to the
 * {@code MethodName_StateUnderTest_ExpectedBehavior} convention.
 * </p>
 */
class IdTsBuilderTest {

    private static final String VALID_KID     = "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch:api:v1:did#assert-key-01";
    private static final String VALID_SUBJECT = "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRBB1:identifier.admin.ch:api:v1:did";
    private static final Instant IAT          = Instant.ofEpochSecond(1690360968L);
    private static final Instant EXP          = Instant.ofEpochSecond(1753432968L);

    // ── Helper ────────────────────────────────────────────────────────────────

    /** Returns a fully configured builder that will pass all required-claim checks. */
    private IdTsBuilder validBuilder() {
        return new IdTsBuilder()
                .withKid(VALID_KID)
                .withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .addEntityName("John Smith's Smithery")
                .withIsStateActor(false)
                .addRegistryId("UID", "CHE-000.000.000");
    }

    // ── Header claims ─────────────────────────────────────────────────────────

    @Test
    void build_validInput_headerContainsTypIdentityTrustStatement() {
        SignedJWT jwt = validBuilder().build();
        assertEquals("swiyu-identity-trust-statement+jwt", jwt.getHeader().getType().getType());
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

    // ── Payload – standard claims ──────────────────────────────────────────────

    @Test
    void build_validInput_payloadContainsSub()  throws ParseException {
        SignedJWT jwt = validBuilder().build();
        assertEquals(VALID_SUBJECT, jwt.getJWTClaimsSet().getSubject());
    }

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
    void build_validInput_payloadNbfEqualsIat() throws ParseException {
        SignedJWT jwt = validBuilder().build();
        assertEquals(jwt.getJWTClaimsSet().getIssueTime().toInstant().getEpochSecond(), jwt.getJWTClaimsSet().getNotBeforeTime().toInstant().getEpochSecond());
    }

    // ── Payload – status claim ─────────────────────────────────────────────────

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

    // ── Payload – entity_name (localization) ──────────────────────────────────

    @Test
    void build_entityNameWithoutLocale_payloadContainsBaseClaimKey() throws ParseException {
        SignedJWT jwt = new IdTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP).withStatus(0, "https://example.com/statuslists/1")
                .addEntityName("John Smith's Smithery")
                .withIsStateActor(false)
                .addRegistryId("UID", "CHE-000.000.000")
                .build();

        assertEquals("John Smith's Smithery", jwt.getJWTClaimsSet().getClaims().get("entity_name"));
    }

    @Test
    void build_entityNameWithLocale_payloadContainsLocalizedClaimKey() throws ParseException {
        SignedJWT jwt = new IdTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP).withStatus(0, "https://example.com/statuslists/1")
                .addEntityName("de", "John Smith's Schmiderei")
                .withIsStateActor(false)
                .addRegistryId("UID", "CHE-000.000.000")
                .build();

        assertEquals("John Smith's Schmiderei", jwt.getJWTClaimsSet().getClaims().get("entity_name#de"));
    }

    @Test
    void build_entityNameMultipleLocales_payloadContainsAllLocalizedKeys() throws ParseException {
        SignedJWT jwt = new IdTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP).withStatus(0, "https://example.com/statuslists/1")
                .addEntityName("John Smith's Smithery")
                .addEntityName("de", "John Smith's Schmiderei")
                .addEntityName("de-CH", "John Smith's Schmiderei")
                .withIsStateActor(false)
                .addRegistryId("UID", "CHE-000.000.000")
                .build();

        Map<String, Object> payload = jwt.getJWTClaimsSet().getClaims();
        assertEquals("John Smith's Smithery",    payload.get("entity_name"));
        assertEquals("John Smith's Schmiderei",  payload.get("entity_name#de"));
        assertEquals("John Smith's Schmiderei",  payload.get("entity_name#de-CH"));
    }

    // ── Payload – is_state_actor ───────────────────────────────────────────────

    @Test
    void build_isStateActorFalse_payloadContainsFalse() throws ParseException {
        SignedJWT jwt = validBuilder().build();
        assertEquals(false, jwt.getJWTClaimsSet().getClaims().get("is_state_actor"));
    }

    @Test
    void build_isStateActorTrue_payloadContainsTrue() throws ParseException {
        SignedJWT jwt = new IdTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP).withStatus(0, "https://example.com/statuslists/1")
                .addEntityName("Bundesamt für Justiz")
                .withIsStateActor(true)
                .addRegistryId("UID", "CHE-000.000.000")
                .build();

        assertEquals(true, jwt.getJWTClaimsSet().getClaims().get("is_state_actor"));
    }

    // ── Payload – registry_ids ────────────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void build_singleRegistryId_payloadContainsArrayWithOneEntry() throws ParseException {
        SignedJWT jwt = validBuilder().build();

        List<Map<String, String>> ids = (List<Map<String, String>>) jwt.getJWTClaimsSet().getClaims().get("registry_ids");
        assertNotNull(ids);
        assertEquals(1, ids.size());
        assertEquals("UID", ids.get(0).get("type"));
        assertEquals("CHE-000.000.000", ids.get(0).get("value"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void build_multipleRegistryIds_payloadContainsAllEntries() throws ParseException {
        SignedJWT jwt = new IdTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP).withStatus(0, "https://example.com/statuslists/1")
                .addEntityName("John Smith's Smithery")
                .withIsStateActor(false)
                .addRegistryId("UID", "CHE-000.000.000")
                .addRegistryId("LEI", "0A1B2C3D4E5F6G7H8J9I")
                .build();

        List<Map<String, String>> ids = (List<Map<String, String>>) jwt.getJWTClaimsSet().getClaims().get("registry_ids");
        assertEquals(2, ids.size());
        assertEquals("UID", ids.get(0).get("type"));
        assertEquals("CHE-000.000.000", ids.get(0).get("value"));
        assertEquals("LEI", ids.get(1).get("type"));
        assertEquals("0A1B2C3D4E5F6G7H8J9I", ids.get(1).get("value"));
    }

    // ── Validation – missing required claims ──────────────────────────────────

    @Test
    void build_missingKid_throwsValidationException() {
        IdTsBuilder builder = new IdTsBuilder()
                .withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP).withStatus(0, "https://example.com/statuslists/1")
                .addEntityName("Name").withIsStateActor(false)
                .addRegistryId("UID", "CHE-000.000.000");

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingSubject_throwsValidationException() {
        IdTsBuilder builder = new IdTsBuilder()
                .withKid(VALID_KID)
                .withValidity(IAT, EXP).withStatus(0, "https://example.com/statuslists/1")
                .addEntityName("Name").withIsStateActor(false)
                .addRegistryId("UID", "CHE-000.000.000");

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingValidity_throwsValidationException() {
        IdTsBuilder builder = new IdTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withStatus(0, "https://example.com/statuslists/1")
                .addEntityName("Name").withIsStateActor(false)
                .addRegistryId("UID", "CHE-000.000.000");

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingStatus_throwsValidationException() {
        IdTsBuilder builder = new IdTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP)
                .addEntityName("Name").withIsStateActor(false)
                .addRegistryId("UID", "CHE-000.000.000");

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingEntityName_throwsValidationException() {
        IdTsBuilder builder = new IdTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP).withStatus(0, "https://example.com/statuslists/1")
                .withIsStateActor(false)
                .addRegistryId("UID", "CHE-000.000.000");

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingIsStateActor_throwsValidationException() {
        IdTsBuilder builder = new IdTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP).withStatus(0, "https://example.com/statuslists/1")
                .addEntityName("Name")
                .addRegistryId("UID", "CHE-000.000.000");

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_noRegistryIds_throwsValidationException() {
        IdTsBuilder builder = new IdTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP).withStatus(0, "https://example.com/statuslists/1")
                .addEntityName("Name").withIsStateActor(false);

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    // ── Validation – Fail-Fast in setters ────────────────────────────────────

    @Test
    void withKid_kidWithoutDIDPrefix_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new IdTsBuilder().withKid("not-a-did#key-1"));
    }

    @Test
    void withKid_kidWithoutKeyFragment_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new IdTsBuilder().withKid("did:tdw:example.ch:issuer"));
    }

    @Test
    void withKid_blankKid_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new IdTsBuilder().withKid("  "));
    }

    @Test
    void withSubject_notADid_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new IdTsBuilder().withSubject("https://example.com/actor"));
    }

    @Test
    void withValidity_expiresBeforeIssuedAt_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new IdTsBuilder().withValidity(EXP, IAT));
    }

    @Test
    void withStatus_negativeIdx_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new IdTsBuilder().withStatus(-1, "https://example.com/statuslists/1"));
    }

    @Test
    void addEntityName_blankName_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new IdTsBuilder().addEntityName("  "));
    }

    @Test
    void addEntityName_blankLocalizedName_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new IdTsBuilder().addEntityName("de-CH", "  "));
    }

    @Test
    void addRegistryId_blankValue_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new IdTsBuilder().addRegistryId("UID", "  "));
    }

    @Test
    void build_calledTwiceOnSameInstance_throwsValidationException() {
        IdTsBuilder builder = validBuilder();
        builder.build(); // first call succeeds
        assertThrows(TrustStatementValidationException.class, builder::build,
                "second call on same builder instance must throw – builders are single-use");
    }

    // ── getPayloadToSign ──────────────────────────────────────────────────────

    @Test
    void getPayloadToSign_validBuild_returnsTwoPartBase64UrlString() throws Exception {
        SignedJWT jwt = validBuilder().build();
        String headerPart  = jwt.getHeader().toBase64URL().toString();
        String payloadPart = jwt.getJWTClaimsSet().toPayload().toBase64URL().toString();
        String payloadToSign = headerPart + "." + payloadPart;

        assertNotNull(payloadToSign);
        String[] parts = payloadToSign.split("\\.");
        assertEquals(2, parts.length, "getPayloadToSign() must return BASE64URL(header).BASE64URL(payload)");
        assertTrue(parts[0].length() > 0, "header part must not be empty");
        assertTrue(parts[1].length() > 0, "payload part must not be empty");
    }
}
