package ch.admin.bj.swiyu.tsbuilder;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Blackbox unit tests for {@link PiTlsBuilder}.
 * <p>
 * Each test verifies observable output (header/payload claims) without any knowledge of
 * internal implementation details. Tests are structured according to the
 * {@code MethodName_StateUnderTest_ExpectedBehavior} convention.
 * </p>
 * <p>
 * Note: {@code iss} is intentionally absent (TP2 migration: iss no longer supported).
 * Note: {@code sub} is not a required claim for piTLS.
 * Note: {@code nbf} MAY differ from {@code iat} – the example shows {@code iat=1690360968},
 * {@code nbf=1721896968}.
 * </p>
 */
class PiTlsBuilderTest {

    private static final String VALID_KID = "did:example:trust-issuer#key-1";
    private static final String VALID_JTI = "07f289d5-8b1f-4604-bf72-53bdcb71ee05";

    // Matches the non-normative example: iat < nbf < exp
    private static final Instant IAT = Instant.ofEpochSecond(1690360968L);
    private static final Instant NBF = Instant.ofEpochSecond(1721896968L);
    private static final Instant EXP = Instant.ofEpochSecond(1753432968L);

    // ── Helper ────────────────────────────────────────────────────────────────

    /** Returns a fully configured builder that will pass all required-claim checks. */
    private PiTlsBuilder validBuilder() {
        return new PiTlsBuilder()
                .withKid(VALID_KID)
                .withValidity(IAT, NBF, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .withJti(VALID_JTI)
                .withVctValues(List.of("urn:ch.admin.fedpol.eid"));
    }

    // ── Header claims ─────────────────────────────────────────────────────────

    @Test
    void build_validInput_headerContainsTypPiTls() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals("swiyu-protected-issuance-trust-list-statement+jwt",
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

    // ── Payload – sub is NOT required for piTLS ────────────────────────────────

    @Test
    void build_withoutSub_doesNotThrow() {
        assertDoesNotThrow(() -> validBuilder().build(),
                "piTLS does not require sub – build must succeed without withSubject()");
    }

    @Test
    void build_withoutSub_payloadDoesNotContainSub() {
        TrustStatementJwt jwt = validBuilder().build();
        assertFalse(jwt.getPayload().containsKey("sub"),
                "sub must not be present when not explicitly set");
    }

    // ── Payload – standard claims ──────────────────────────────────────────────

    @Test
    void build_validInput_payloadContainsJti() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(VALID_JTI, jwt.getPayload().get("jti"));
    }

    @Test
    void build_validInput_payloadContainsIatAsEpochSeconds() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(1690360968L, jwt.getPayload().get("iat"));
    }

    @Test
    void build_validInput_payloadContainsNbfAsEpochSeconds() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(1721896968L, jwt.getPayload().get("nbf"));
    }

    @Test
    void build_validInput_payloadNbfCanDifferFromIat() {
        TrustStatementJwt jwt = validBuilder().build();
        assertNotEquals(jwt.getPayload().get("iat"), jwt.getPayload().get("nbf"),
                "piTLS allows nbf to differ from iat (delayed activation)");
    }

    @Test
    void build_validInput_payloadContainsExpAsEpochSeconds() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(1753432968L, jwt.getPayload().get("exp"));
    }

    @Test
    void build_twoParamValidity_payloadNbfEqualsIat() {
        TrustStatementJwt jwt = new PiTlsBuilder()
                .withKid(VALID_KID)
                .withValidity(IAT, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .withJti(VALID_JTI)
                .withVctValues(List.of("urn:ch.admin.fedpol.eid"))
                .build();

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

    // ── Payload – vct_values ──────────────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void build_singleVctValue_payloadContainsArrayWithOneEntry() {
        TrustStatementJwt jwt = validBuilder().build();

        List<String> vctValues = (List<String>) jwt.getPayload().get("vct_values");
        assertNotNull(vctValues);
        assertEquals(1, vctValues.size());
        assertEquals("urn:ch.admin.fedpol.eid", vctValues.get(0));
    }

    @Test
    @SuppressWarnings("unchecked")
    void build_multipleVctValues_payloadContainsAllEntries() {
        TrustStatementJwt jwt = new PiTlsBuilder()
                .withKid(VALID_KID)
                .withValidity(IAT, NBF, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .withJti(VALID_JTI)
                .withVctValues(List.of(
                        "urn:ch.admin.fedpol.eid",
                        "urn:ch.admin.asa.driving-licence"))
                .build();

        List<String> vctValues = (List<String>) jwt.getPayload().get("vct_values");
        assertEquals(2, vctValues.size());
        assertEquals("urn:ch.admin.fedpol.eid", vctValues.get(0));
        assertEquals("urn:ch.admin.asa.driving-licence", vctValues.get(1));
    }

    // ── Validation – missing required claims ──────────────────────────────────

    @Test
    void build_missingKid_throwsValidationException() {
        PiTlsBuilder builder = new PiTlsBuilder()
                .withValidity(IAT, NBF, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .withJti(VALID_JTI)
                .withVctValues(List.of("urn:ch.admin.fedpol.eid"));

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingValidity_throwsValidationException() {
        PiTlsBuilder builder = new PiTlsBuilder()
                .withKid(VALID_KID)
                .withStatus(0, "https://example.com/statuslists/1")
                .withJti(VALID_JTI)
                .withVctValues(List.of("urn:ch.admin.fedpol.eid"));

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingStatus_throwsValidationException() {
        PiTlsBuilder builder = new PiTlsBuilder()
                .withKid(VALID_KID)
                .withValidity(IAT, NBF, EXP)
                .withJti(VALID_JTI)
                .withVctValues(List.of("urn:ch.admin.fedpol.eid"));

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingJti_throwsValidationException() {
        PiTlsBuilder builder = new PiTlsBuilder()
                .withKid(VALID_KID)
                .withValidity(IAT, NBF, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .withVctValues(List.of("urn:ch.admin.fedpol.eid"));

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    @Test
    void build_missingVctValues_throwsValidationException() {
        PiTlsBuilder builder = new PiTlsBuilder()
                .withKid(VALID_KID)
                .withValidity(IAT, NBF, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .withJti(VALID_JTI);

        assertThrows(TrustStatementValidationException.class, builder::build);
    }

    // ── Validation – Fail-Fast in setters ─────────────────────────────────────

    @Test
    void withJti_notUuidV4_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new PiTlsBuilder().withJti("not-a-uuid"));
    }

    @Test
    void withJti_uuidV1_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new PiTlsBuilder().withJti("550e8400-e29b-11d4-a716-446655440000"));
    }

    @Test
    void withJti_blankValue_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new PiTlsBuilder().withJti("  "));
    }

    @Test
    void withVctValues_emptyList_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new PiTlsBuilder().withVctValues(List.of()));
    }

    @Test
    void withVctValues_nullList_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new PiTlsBuilder().withVctValues(null));
    }

    @Test
    void withValidity_nbfBeforeIat_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new PiTlsBuilder().withValidity(NBF, IAT, EXP));
    }

    @Test
    void withValidity_expBeforeNbf_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new PiTlsBuilder().withValidity(IAT, EXP, NBF));
    }
}

