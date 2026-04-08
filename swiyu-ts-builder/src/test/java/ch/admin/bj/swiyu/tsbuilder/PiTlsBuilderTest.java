package ch.admin.bj.swiyu.tsbuilder;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Blackbox unit tests for {@link PiTlsBuilder}.
 */
class PiTlsBuilderTest {

    private static final String VALID_KID = "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch:api:v1:did#assert-key-01";
    private static final String VALID_JTI = "07f289d5-8b1f-4604-bf72-53bdcb71ee05";

    private static final Instant IAT = Instant.ofEpochSecond(1690360968L);
    private static final Instant NBF = Instant.ofEpochSecond(1721896968L);
    private static final Instant EXP = Instant.ofEpochSecond(1753432968L);

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
        SignedJWT jwt = validBuilder().build();
        assertEquals("swiyu-protected-issuance-trust-list-statement+jwt",
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
        assertEquals("swiss-profile-trust:1.0.0",
                jwt.getHeader().getCustomParam("profile_version"));
    }

    // ── Payload – iss MUST NOT be present ─────────────────────────────────────

    @Test
    void build_validInput_payloadDoesNotContainIss() throws ParseException {
        SignedJWT jwt = validBuilder().build();
        assertNull(jwt.getJWTClaimsSet().getIssuer(),
                "iss must not be present – TP2 removes iss in favour of kid header");
    }

    // ── Payload – sub is NOT required for piTLS ────────────────────────────────

    @Test
    void build_withoutSub_doesNotThrow() {
        assertDoesNotThrow(() -> validBuilder().build(),
                "piTLS does not require sub – build must succeed without withSubject()");
    }

    @Test
    void build_withoutSub_payloadDoesNotContainSub() throws ParseException {
        SignedJWT jwt = validBuilder().build();
        assertNull(jwt.getJWTClaimsSet().getSubject(),
                "sub must not be present when not explicitly set");
    }

    @Test
    void withSubject_always_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new NcTlsBuilder().withSubject("did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRBB1:identifier.admin.ch:api:v1:did"),
                "sub is not supported for ncTLS and must always throw");
    }

    // ── Payload – standard claims ──────────────────────────────────────────────

    @Test
    void build_validInput_payloadContainsJti() throws ParseException {
        SignedJWT jwt = validBuilder().build();
        assertEquals(VALID_JTI, jwt.getJWTClaimsSet().getJWTID());
    }

    @Test
    void build_validInput_payloadContainsIatAsEpochSeconds() throws ParseException {
        SignedJWT jwt = validBuilder().build();
        assertEquals(1690360968L, jwt.getJWTClaimsSet().getIssueTime().toInstant().getEpochSecond());
    }

    @Test
    void build_validInput_payloadContainsNbfAsEpochSeconds() throws ParseException {
        SignedJWT jwt = validBuilder().build();
        assertEquals(1721896968L, jwt.getJWTClaimsSet().getNotBeforeTime().toInstant().getEpochSecond());
    }

    @Test
    void build_validInput_payloadNbfCanDifferFromIat() throws ParseException {
        SignedJWT jwt = validBuilder().build();
        assertNotEquals(jwt.getJWTClaimsSet().getIssueTime(), jwt.getJWTClaimsSet().getNotBeforeTime(),
                "piTLS allows nbf to differ from iat (delayed activation)");
    }

    @Test
    void build_validInput_payloadContainsExpAsEpochSeconds() throws ParseException {
        SignedJWT jwt = validBuilder().build();
        assertEquals(1753432968L, jwt.getJWTClaimsSet().getExpirationTime().toInstant().getEpochSecond());
    }

    @Test
    void build_twoParamValidity_payloadNbfEqualsIat() throws ParseException {
        SignedJWT jwt = new PiTlsBuilder()
                .withKid(VALID_KID)
                .withValidity(IAT, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .withJti(VALID_JTI)
                .withVctValues(List.of("urn:ch.admin.fedpol.eid"))
                .build();

        assertEquals(jwt.getJWTClaimsSet().getIssueTime(), jwt.getJWTClaimsSet().getNotBeforeTime(),
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

    // ── Payload – vct_values ──────────────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void build_singleVctValue_payloadContainsArrayWithOneEntry() throws ParseException {
        SignedJWT jwt = validBuilder().build();

        List<String> vctValues = (List<String>) jwt.getJWTClaimsSet().getClaim("vct_values");
        assertNotNull(vctValues);
        assertEquals(1, vctValues.size());
        assertEquals("urn:ch.admin.fedpol.eid", vctValues.getFirst());
    }

    @Test
    @SuppressWarnings("unchecked")
    void build_multipleVctValues_payloadContainsAllEntries() throws ParseException {
        SignedJWT jwt = new PiTlsBuilder()
                .withKid(VALID_KID)
                .withValidity(IAT, NBF, EXP)
                .withStatus(0, "https://example.com/statuslists/1")
                .withJti(VALID_JTI)
                .withVctValues(List.of(
                        "urn:ch.admin.fedpol.eid",
                        "urn:ch.admin.asa.driving-licence"))
                .build();

        List<String> vctValues = (List<String>) jwt.getJWTClaimsSet().getClaim("vct_values");
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
