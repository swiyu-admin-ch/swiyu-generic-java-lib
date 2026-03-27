package ch.admin.bj.swiyu.tsbuilder;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Blackbox unit tests for {@link PvaTsBuilder}.
 * <p>
 * Each test verifies observable output (header/payload claims) without any knowledge of
 * internal implementation details. Tests are structured according to the
 * {@code MethodName_StateUnderTest_ExpectedBehavior} convention.
 * </p>
 */
class PvaTsBuilderTest {

    private static final String VALID_KID     = "did:tdw:example.ch:verifier#assert-key-01";
    
    private static final String VALID_SUBJECT = "did:tdw:example.ch:verifier";
    private static final String VALID_JTI     = "550e8400-e29b-41d4-a716-446655440000";
    private static final Instant IAT          = Instant.ofEpochSecond(1690360968L);
    private static final Instant EXP          = Instant.ofEpochSecond(1753432968L);

    // ── Helper ────────────────────────────────────────────────────────────────

    /** Returns a fully configured builder that will pass all required-claim checks. */
    private PvaTsBuilder validBuilder() {
        return new PvaTsBuilder()
                .withKid(VALID_KID)
                
                .withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP)
                .withStatus(7, "https://example.com/statuslists/1")
                .withJti(VALID_JTI)
                .withAuthorizedFields(List.of("personal_administrative_number"));
    }

    // ── Header claims ─────────────────────────────────────────────────────────

    @Test
    void build_validInput_headerContainsTypPvaTs() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(
                "swiyu-protected-verification-authorization-trust-statement+jwt",
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

    // ── Payload – standard claims ──────────────────────────────────────────────

    @Test
    void build_validInput_payloadContainsSub() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(VALID_SUBJECT, jwt.getPayload().get("sub"));
    }


    @Test
    void build_validInput_payloadContainsIatAsEpochSeconds() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(1690360968L, jwt.getPayload().get("iat"));
    }

    @Test
    void build_validInput_payloadContainsNbfAsEpochSeconds() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(1690360968L, jwt.getPayload().get("nbf"));
    }

    @Test
    void build_validInput_payloadNbfEqualsIat() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(jwt.getPayload().get("iat"), jwt.getPayload().get("nbf"));
    }

    @Test
    void build_validInput_payloadContainsExpAsEpochSeconds() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(1753432968L, jwt.getPayload().get("exp"));
    }

    @Test
    void build_validInput_payloadContainsJti() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(VALID_JTI, jwt.getPayload().get("jti"));
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
        assertEquals(7, statusList.get("idx"));
        assertEquals("https://example.com/statuslists/1", statusList.get("uri"));
    }

    // ── Payload – authorized_fields ───────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void build_singleAuthorizedField_payloadContainsArrayWithOneEntry() {
        TrustStatementJwt jwt = validBuilder().build();

        List<String> fields = (List<String>) jwt.getPayload().get("authorized_fields");
        assertNotNull(fields);
        assertEquals(1, fields.size());
        assertEquals("personal_administrative_number", fields.get(0));
    }

    @Test
    @SuppressWarnings("unchecked")
    void build_multipleAuthorizedFields_payloadContainsAllEntries() {
        TrustStatementJwt jwt = new PvaTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP).withStatus(7, "https://example.com/statuslists/1")
                .withJti(VALID_JTI)
                .withAuthorizedFields(List.of("personal_administrative_number", "date_of_birth"))
                .build();

        List<String> fields = (List<String>) jwt.getPayload().get("authorized_fields");
        assertEquals(2, fields.size());
        assertTrue(fields.contains("personal_administrative_number"));
        assertTrue(fields.contains("date_of_birth"));
    }

    // ── Validation – missing required claims ──────────────────────────────────

    @Test
    void build_missingKid_throwsValidationException() {
        PvaTsBuilder builder = new PvaTsBuilder()
                .withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP).withStatus(7, "https://example.com/statuslists/1")
                .withJti(VALID_JTI)
                .withAuthorizedFields(List.of("personal_administrative_number"));

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingSubject_throwsValidationException() {
        PvaTsBuilder builder = new PvaTsBuilder()
                .withKid(VALID_KID)
                .withValidity(IAT, EXP).withStatus(7, "https://example.com/statuslists/1")
                .withJti(VALID_JTI)
                .withAuthorizedFields(List.of("personal_administrative_number"));

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingValidity_throwsValidationException() {
        PvaTsBuilder builder = new PvaTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withStatus(7, "https://example.com/statuslists/1")
                .withJti(VALID_JTI)
                .withAuthorizedFields(List.of("personal_administrative_number"));

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingStatus_throwsValidationException() {
        PvaTsBuilder builder = new PvaTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP)
                .withJti(VALID_JTI)
                .withAuthorizedFields(List.of("personal_administrative_number"));

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingJti_throwsValidationException() {
        PvaTsBuilder builder = new PvaTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP).withStatus(7, "https://example.com/statuslists/1")
                .withAuthorizedFields(List.of("personal_administrative_number"));

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingAuthorizedFields_throwsValidationException() {
        PvaTsBuilder builder = new PvaTsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP).withStatus(7, "https://example.com/statuslists/1")
                .withJti(VALID_JTI);

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    // ── Validation – Fail-Fast in setters ─────────────────────────────────────

    @Test
    void withJti_notUuidV4_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new PvaTsBuilder().withJti("not-a-uuid"));
    }

    @Test
    void withJti_uuidV1_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new PvaTsBuilder().withJti("550e8400-e29b-11d4-a716-446655440000"));
    }

    @Test
    void withJti_blankValue_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new PvaTsBuilder().withJti("  "));
    }

    @Test
    void withAuthorizedFields_emptyList_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new PvaTsBuilder().withAuthorizedFields(List.of()));
    }

    @Test
    void withAuthorizedFields_nullList_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new PvaTsBuilder().withAuthorizedFields(null));
    }

    @Test
    void withStatus_negativeIdx_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new PvaTsBuilder().withStatus(-1, "https://example.com/statuslists/1"));
    }

    @Test
    void withStatus_blankUri_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new PvaTsBuilder().withStatus(0, "  "));
    }

    // ── nbf required (RFC 7519 base spec) ─────────────────────────────────────

    @Test
    void build_validInput_payloadContainsNbf() {
        TrustStatementJwt jwt = validBuilder().build();
        assertNotNull(jwt.getPayload().get("nbf"), "nbf claim must be present (required by RFC 7519)");
    }
}

