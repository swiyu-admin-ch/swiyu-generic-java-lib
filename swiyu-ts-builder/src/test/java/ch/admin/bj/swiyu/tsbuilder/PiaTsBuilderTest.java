package ch.admin.bj.swiyu.tsbuilder;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Blackbox unit tests for {@link PiaTsBuilder}.
 * <p>
 * Each test verifies observable output (header/payload claims) without any knowledge of
 * internal implementation details. Tests are structured according to the
 * {@code MethodName_StateUnderTest_ExpectedBehavior} convention.
 * </p>
 * <p>
 * Note: {@code iss} is intentionally absent (TP2 migration: iss no longer supported).
 * Note: {@code nbf} MAY differ from {@code iat} – the example shows {@code iat=1690360968},
 * {@code nbf=1721896968}, which is a later activation date.
 * Note: {@code can_issue} is a single JSON object, not an array.
 * </p>
 */
class PiaTsBuilderTest {

    private static final String VALID_KID     = "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch:api:v1:did#assert-key-01";
    private static final String VALID_SUBJECT = "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRBB1:identifier.admin.ch:api:v1:did";
    private static final String VALID_VCT     = "urn:ch.admin.fedpol.betaid";

    // Matches the non-normative example: iat < nbf < exp
    private static final Instant IAT = Instant.ofEpochSecond(1690360968L);
    private static final Instant NBF = Instant.ofEpochSecond(1721896968L);
    private static final Instant EXP = Instant.ofEpochSecond(1753432968L);

    // ── Helper ────────────────────────────────────────────────────────────────

    /** Returns a fully configured builder that will pass all required-claim checks. */
    private PiaTsBuilder validBuilder() {
        return new PiaTsBuilder()
                .withKid(VALID_KID)
                .withSubject(VALID_SUBJECT)
                .withValidity(IAT, NBF, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .withCanIssue(VALID_VCT, null, "Beta credential", "Eligible per AwG Art.6b");
    }

    // ── Header claims ─────────────────────────────────────────────────────────

    @Test
    void build_validInput_headerContainsTypPiaTs() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(
                "swiyu-protected-issuance-authorization-trust-statement+jwt",
                jwt.getJwsHeader().getType().getType());
    }

    @Test
    void build_validInput_headerContainsAlgES256() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals("ES256", jwt.getJwsHeader().getAlgorithm().getName());
    }

    @Test
    void build_validInput_headerContainsKid() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(VALID_KID, jwt.getJwsHeader().getKeyID());
    }

    @Test
    void build_validInput_headerContainsProfileVersion() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals("swiss-profile-trust:1.0.0", jwt.getJwsHeader().getCustomParam("profile_version"));
    }

    // ── Payload – iss MUST NOT be present (TP2: iss no longer supported) ────────

    @Test
    void build_validInput_payloadDoesNotContainIss() {
        TrustStatementJwt jwt = validBuilder().build();
        assertFalse(jwt.getClaimsSet().getClaim("iss") != null,
                "iss must not be present – TP2 removes iss in favour of kid header");
    }

    // ── Payload – standard claims ──────────────────────────────────────────────

    @Test
    void build_validInput_payloadContainsSub() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(VALID_SUBJECT, jwt.getClaimsSet().getSubject());
    }

    @Test
    void build_validInput_payloadContainsIatAsEpochSeconds() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(1690360968L, jwt.getClaimsSet().getIssueTime().toInstant().getEpochSecond());
    }

    @Test
    void build_validInput_payloadContainsNbfAsEpochSeconds() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(1721896968L, jwt.getClaimsSet().getNotBeforeTime().toInstant().getEpochSecond());
    }

    @Test
    void build_validInput_payloadNbfCanDifferFromIat() {
        TrustStatementJwt jwt = validBuilder().build();
        assertNotEquals(jwt.getClaimsSet().getIssueTime().toInstant().getEpochSecond(), jwt.getClaimsSet().getNotBeforeTime().toInstant().getEpochSecond(),
                "piaTS allows nbf to differ from iat (delayed activation)");
    }

    @Test
    void build_validInput_payloadContainsExpAsEpochSeconds() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(1753432968L, jwt.getClaimsSet().getExpirationTime().toInstant().getEpochSecond());
    }

    @Test
    void build_twoParamValidity_payloadNbfEqualsIat() {
        // when using the 2-parameter shorthand, nbf should equal iat
        TrustStatementJwt jwt = new PiaTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .withCanIssue(VALID_VCT, null, "Beta credential", null)
                .build();

        assertEquals(jwt.getClaimsSet().getIssueTime().toInstant().getEpochSecond(), jwt.getClaimsSet().getNotBeforeTime().toInstant().getEpochSecond());
    }

    // ── Payload – status ──────────────────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void build_validInput_payloadStatusHasCorrectStructure() {
        TrustStatementJwt jwt = validBuilder().build();

        Map<String, Object> status = (Map<String, Object>) jwt.getClaimsSet().getClaim("status");
        assertNotNull(status, "status claim must be present");

        Map<String, Object> statusList = (Map<String, Object>) status.get("status_list");
        assertNotNull(statusList, "status.status_list must be present");
        assertEquals(0, statusList.get("idx"));
        assertEquals("https://example.com/statuslists/1", statusList.get("uri"));
    }

    // ── Payload – can_issue (single object, not array) ────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void build_validInput_canIssueIsObjectNotArray() {
        TrustStatementJwt jwt = validBuilder().build();
        Object canIssue = jwt.getClaimsSet().getClaims().get("can_issue");
        assertNotNull(canIssue);
        assertInstanceOf(Map.class, canIssue,
                "can_issue must be a single JSON object, not an array");
    }

    @Test
    @SuppressWarnings("unchecked")
    void build_validInput_canIssueContainsVct() {
        TrustStatementJwt jwt = validBuilder().build();
        Map<String, Object> canIssue = (Map<String, Object>) jwt.getClaimsSet().getClaims().get("can_issue");
        assertEquals(VALID_VCT, canIssue.get("vct"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void build_canIssueWithoutLocale_vctNameUsesBaseKey() {
        TrustStatementJwt jwt = new PiaTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, NBF, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .withCanIssue(VALID_VCT, null, "Beta credential", null)
                .build();

        Map<String, Object> canIssue = (Map<String, Object>) jwt.getClaimsSet().getClaims().get("can_issue");
        assertEquals("Beta credential", canIssue.get("vct_name"));
        assertFalse(canIssue.containsKey("reason"),
                "reason must be absent when not provided");
    }

    @Test
    @SuppressWarnings("unchecked")
    void build_canIssueWithLocale_vctNameUsesLocalizedKey() {
        TrustStatementJwt jwt = new PiaTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, NBF, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .withCanIssue(VALID_VCT, "de-CH", "Beta-Ausweis", null)
                .build();

        Map<String, Object> canIssue = (Map<String, Object>) jwt.getClaimsSet().getClaims().get("can_issue");
        assertEquals("Beta-Ausweis", canIssue.get("vct_name#de-CH"));
        assertFalse(canIssue.containsKey("vct_name"),
                "non-localized vct_name must be absent when locale is provided");
    }

    @Test
    @SuppressWarnings("unchecked")
    void build_canIssueWithReason_reasonPresentInObject() {
        TrustStatementJwt jwt = new PiaTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, NBF, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .withCanIssue(VALID_VCT, null, "Beta credential",
                        "Eligible per AwG Art.6b")
                .build();

        Map<String, Object> canIssue = (Map<String, Object>) jwt.getClaimsSet().getClaims().get("can_issue");
        assertEquals("Eligible per AwG Art.6b", canIssue.get("reason"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void build_canIssueWithLocalizedReason_reasonUsesLocalizedKey() {
        TrustStatementJwt jwt = new PiaTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, NBF, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .withCanIssue(VALID_VCT, "de-CH", "Beta-Ausweis",
                        "Berechtigt gemäss AwG Art.6b")
                .build();

        Map<String, Object> canIssue = (Map<String, Object>) jwt.getClaimsSet().getClaims().get("can_issue");
        assertEquals("Berechtigt gemäss AwG Art.6b", canIssue.get("reason#de-CH"));
    }

    // ── Validation – missing required claims ──────────────────────────────────

    @Test
    void build_missingKid_throwsValidationException() {
        PiaTsBuilder builder = new PiaTsBuilder()
                .withSubject(VALID_SUBJECT)
                .withValidity(IAT, NBF, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .withCanIssue(VALID_VCT, null, "Beta credential", null);

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingSubject_throwsValidationException() {
        PiaTsBuilder builder = new PiaTsBuilder()
                .withKid(VALID_KID)
                .withValidity(IAT, NBF, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .withCanIssue(VALID_VCT, null, "Beta credential", null);

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingValidity_throwsValidationException() {
        PiaTsBuilder builder = new PiaTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withStatus(0, "https://example.com/statuslists/1")
                .withCanIssue(VALID_VCT, null, "Beta credential", null);

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingStatus_throwsValidationException() {
        PiaTsBuilder builder = new PiaTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, NBF, EXP)
                .withCanIssue(VALID_VCT, null, "Beta credential", null);

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingCanIssue_throwsValidationException() {
        PiaTsBuilder builder = new PiaTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, NBF, EXP)
                .withStatus(0, "https://example.com/statuslists/1");

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    // ── Validation – Fail-Fast in setters ─────────────────────────────────────

    @Test
    void withCanIssue_blankVct_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new PiaTsBuilder().withCanIssue("  ", null, "Name", null));
    }

    @Test
    void withCanIssue_blankVctName_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new PiaTsBuilder().withCanIssue(VALID_VCT, null, "  ", null));
    }

    @Test
    void withCanIssue_vctNameExceedsMaxLength_throwsValidationException() {
        String name501 = "A".repeat(501);
        assertThrows(TrustStatementValidationException.class,
                () -> new PiaTsBuilder().withCanIssue(VALID_VCT, null, name501, null));
    }

    @Test
    void withCanIssue_vctNameAtExactMaxLength_doesNotThrow() {
        String name500 = "A".repeat(500);
        assertDoesNotThrow(() -> new PiaTsBuilder().withCanIssue(VALID_VCT, null, name500, null));
    }

    @Test
    void withCanIssue_reasonExceedsMaxLength_throwsValidationException() {
        String desc51 = "A".repeat(51);
        assertThrows(TrustStatementValidationException.class,
                () -> new PiaTsBuilder().withCanIssue(VALID_VCT, null, "Name", desc51));
    }

    @Test
    void withCanIssue_reasonAtExactMaxLength_doesNotThrow() {
        String desc50 = "A".repeat(50);
        assertDoesNotThrow(() -> new PiaTsBuilder().withCanIssue(VALID_VCT, null, "Name", desc50));
    }

    @Test
    void withValidity_nbfBeforeIat_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new PiaTsBuilder().withValidity(NBF, IAT, EXP));
    }

    @Test
    void withValidity_expBeforeNbf_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new PiaTsBuilder().withValidity(IAT, EXP, NBF));
    }
}

