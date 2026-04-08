package ch.admin.bj.swiyu.tsbuilder;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;
/**
 * Blackbox unit tests for {@link VqPsBuilder}.
 * <p>
 * Each test verifies observable output (header/payload claims) without any knowledge of
 * internal implementation details. Tests are structured according to the
 * {@code MethodName_StateUnderTest_ExpectedBehavior} convention.
 * </p>
 * <p>
 * Notes from spec analysis:
 * <ul>
 *   <li>{@code iss} is absent (TP2 migration: iss no longer supported).</li>
 *   <li>{@code request.query} is a structured JSON object (not a string).</li>
 *   <li>Each DCQL credential query MUST have {@code meta.vct_values} (non-empty array).</li>
 *   <li>{@code purpose_name} / {@code purpose_description} MAY be localization-only (no default required).</li>
 * </ul>
 * </p>
 */
class VqPsBuilderTest {
    private static final String VALID_KID     = "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch:api:v1:did#assert-key-01";
    private static final String VALID_SUBJECT = "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRBB1:identifier.admin.ch:api:v1:did";
    private static final String VALID_JTI     = "07f289d5-8b1f-4604-bf72-53bdcb71ee05";
    private static final String VALID_SCOPE   = "com.example.identityCardCredential_presentation";
    private static final Instant IAT          = Instant.ofEpochSecond(1690360968L);
    private static final Instant EXP          = Instant.ofEpochSecond(1753432968L);
    // ── DCQL query helper ─────────────────────────────────────────────────────
    /**
     * Builds a minimal valid DCQL query map matching the spec example.
     * Each credential has meta.vct_values (required).
     */
    private Map<String, Object> validDcqlQuery() {
        return Map.of("credentials", List.of(
                Map.of(
                        "id", "my_credential",
                        "format", "dc+sd-jwt",
                        "meta", Map.of("vct_values",
                                List.of("https://credentials.example.com/identity_credential")),
                        "claims", List.of(Map.of("path", List.of("last_name")))
                )
        ));
    }
    // ── Helper ────────────────────────────────────────────────────────────────
    /** Returns a fully configured builder that will pass all required-claim checks. */
    private VqPsBuilder validBuilder() {
        return new VqPsBuilder()
                .withKid(VALID_KID)
                .withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP)
                .withJti(VALID_JTI)
                .addPurposeName("Age verification")
                .addPurposeDesc("Checks whether the requesting person is of legal age.")
                .withRequest(VALID_SCOPE, validDcqlQuery());
    }
    // ── Header claims ─────────────────────────────────────────────────────────
    @Test
    void build_validInput_headerContainsTypVqPs() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals("swiyu-verification-query-public-statement+jwt", jwt.getJwsHeader().getType().getType());
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
        assertEquals(1690360968L, jwt.getClaimsSet().getNotBeforeTime().toInstant().getEpochSecond());
    }
    @Test
    void build_validInput_payloadNbfEqualsIat() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(jwt.getClaimsSet().getIssueTime().toInstant().getEpochSecond(), jwt.getClaimsSet().getNotBeforeTime().toInstant().getEpochSecond());
    }
    @Test
    void build_validInput_payloadContainsExpAsEpochSeconds() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(1753432968L, jwt.getClaimsSet().getExpirationTime().toInstant().getEpochSecond());
    }
    // ── Payload – jti ─────────────────────────────────────────────────────────
    @Test
    void build_validInput_payloadContainsJti() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(VALID_JTI, jwt.getClaimsSet().getJWTID());
    }
    // ── Payload – purpose_name (localization) ─────────────────────────────────
    @Test
    void build_purposeNameWithoutLocale_payloadContainsBaseClaimKey() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals("Age verification", jwt.getClaimsSet().getClaims().get("purpose_name"));
    }
    @Test
    void build_purposeNameWithLocale_payloadContainsLocalizedClaimKey() {
        TrustStatementJwt jwt = new VqPsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP).withJti(VALID_JTI)
                .addPurposeName("de-ch", "beispiel abfrage")
                .addPurposeDesc("frage ab zum beispiel")
                .withRequest(VALID_SCOPE, validDcqlQuery())
                .build();
        assertEquals("beispiel abfrage", jwt.getClaimsSet().getClaims().get("purpose_name#de-ch"));
        assertFalse(jwt.getClaimsSet().getClaims().containsKey("purpose_name"),
                "non-localized purpose_name must be absent when only locale variant was added");
    }
    @Test
    void build_purposeNameMultipleLocales_payloadContainsAllLocalizedKeys() {
        TrustStatementJwt jwt = new VqPsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP).withJti(VALID_JTI)
                .addPurposeName("Age verification")
                .addPurposeName("de-CH", "Altersnachweis")
                .addPurposeName("fr-CH", "Vérification de l'âge")
                .addPurposeDesc("Checks whether the requesting person is of legal age.")
                .withRequest(VALID_SCOPE, validDcqlQuery())
                .build();
        Map<String, Object> payload = jwt.getClaimsSet().getClaims();
        assertEquals("Age verification",           payload.get("purpose_name"));
        assertEquals("Altersnachweis",             payload.get("purpose_name#de-CH"));
        assertEquals("Vérification de l'âge",      payload.get("purpose_name#fr-CH"));
    }
    @Test
    void build_purposeNameAtExactMaxLength_doesNotThrow() {
        String name50 = "A".repeat(50);
        assertDoesNotThrow(() -> new VqPsBuilder().addPurposeName(name50));
    }
    // ── Payload – purpose_description (localization) ──────────────────────────
    @Test
    void build_purposeDescWithoutLocale_payloadContainsBaseClaimKey() {
        TrustStatementJwt jwt = validBuilder().build();
        assertEquals(
                "Checks whether the requesting person is of legal age.",
                jwt.getClaimsSet().getClaims().get("purpose_description"));
    }
    @Test
    void build_purposeDescWithLocale_payloadContainsLocalizedClaimKey() {
        TrustStatementJwt jwt = new VqPsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT)
                .withValidity(IAT, EXP).withJti(VALID_JTI)
                .addPurposeName("Age verification")
                .addPurposeDesc("de-ch", "frage ab zum beispiel")
                .withRequest(VALID_SCOPE, validDcqlQuery())
                .build();
        assertEquals("frage ab zum beispiel", jwt.getClaimsSet().getClaims().get("purpose_description#de-ch"));
        assertFalse(jwt.getClaimsSet().getClaims().containsKey("purpose_description"),
                "non-localized purpose_description must be absent when only locale variant was added");
    }
    @Test
    void build_purposeDescAtExactMaxLength_doesNotThrow() {
        String desc500 = "A".repeat(500);
        assertDoesNotThrow(() -> new VqPsBuilder().addPurposeDesc(desc500));
    }
    // ── Payload – request object ───────────────────────────────────────────────
    @Test
    @SuppressWarnings("unchecked")
    void build_validInput_requestContainsTypeDCQL() {
        TrustStatementJwt jwt = validBuilder().build();
        Map<String, Object> request = (Map<String, Object>) jwt.getClaimsSet().getClaims().get("request");
        assertNotNull(request, "request claim must be present");
        assertEquals("DCQL", request.get("type"));
    }
    @Test
    @SuppressWarnings("unchecked")
    void build_validInput_requestContainsScope() {
        TrustStatementJwt jwt = validBuilder().build();
        Map<String, Object> request = (Map<String, Object>) jwt.getClaimsSet().getClaims().get("request");
        assertEquals(VALID_SCOPE, request.get("scope"));
    }
    @Test
    @SuppressWarnings("unchecked")
    void build_validInput_requestQueryIsObjectNotString() {
        TrustStatementJwt jwt = validBuilder().build();
        Map<String, Object> request = (Map<String, Object>) jwt.getClaimsSet().getClaims().get("request");
        Object query = request.get("query");
        assertInstanceOf(Map.class, query,
                "request.query must be a JSON object (Map), not a String");
    }
    @Test
    @SuppressWarnings("unchecked")
    void build_validInput_requestQueryContainsCredentials() {
        TrustStatementJwt jwt = validBuilder().build();
        Map<String, Object> request = (Map<String, Object>) jwt.getClaimsSet().getClaims().get("request");
        Map<String, Object> query = (Map<String, Object>) request.get("query");
        List<?> credentials = (List<?>) query.get("credentials");
        assertNotNull(credentials);
        assertFalse(credentials.isEmpty());
    }
    @Test
    @SuppressWarnings("unchecked")
    void build_validInput_requestQueryCredentialHasMetaVctValues() {
        TrustStatementJwt jwt = validBuilder().build();
        Map<String, Object> request = (Map<String, Object>) jwt.getClaimsSet().getClaims().get("request");
        Map<String, Object> query = (Map<String, Object>) request.get("query");
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) query.get("credentials");
        Map<String, Object> meta = (Map<String, Object>) credentials.get(0).get("meta");
        List<?> vctValues = (List<?>) meta.get("vct_values");
        assertNotNull(vctValues);
        assertFalse(vctValues.isEmpty());
        assertEquals("https://credentials.example.com/identity_credential", vctValues.get(0));
    }
    // ── Validation – missing required claims ──────────────────────────────────
    @Test
    void build_missingKid_throwsValidationException() {
        VqPsBuilder builder = new VqPsBuilder()
                .withSubject(VALID_SUBJECT).withValidity(IAT, EXP).withJti(VALID_JTI)
                .addPurposeName("Name").addPurposeDesc("Desc.")
                .withRequest(VALID_SCOPE, validDcqlQuery());
        assertThrows(TrustStatementValidationException.class, builder::build);
    }
    @Test
    void build_missingSubject_throwsValidationException() {
        VqPsBuilder builder = new VqPsBuilder()
                .withKid(VALID_KID).withValidity(IAT, EXP).withJti(VALID_JTI)
                .addPurposeName("Name").addPurposeDesc("Desc.")
                .withRequest(VALID_SCOPE, validDcqlQuery());
        assertThrows(TrustStatementValidationException.class, builder::build);
    }
    @Test
    void build_missingValidity_throwsValidationException() {
        VqPsBuilder builder = new VqPsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT).withJti(VALID_JTI)
                .addPurposeName("Name").addPurposeDesc("Desc.")
                .withRequest(VALID_SCOPE, validDcqlQuery());
        assertThrows(TrustStatementValidationException.class, builder::build);
    }
    @Test
    void build_missingJti_throwsValidationException() {
        VqPsBuilder builder = new VqPsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT).withValidity(IAT, EXP)
                .addPurposeName("Name").addPurposeDesc("Desc.")
                .withRequest(VALID_SCOPE, validDcqlQuery());
        assertThrows(TrustStatementValidationException.class, builder::build);
    }
    @Test
    void build_missingPurposeName_throwsValidationException() {
        VqPsBuilder builder = new VqPsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT).withValidity(IAT, EXP).withJti(VALID_JTI)
                .addPurposeDesc("Desc.")
                .withRequest(VALID_SCOPE, validDcqlQuery());
        assertThrows(TrustStatementValidationException.class, builder::build);
    }
    @Test
    void build_missingPurposeDesc_throwsValidationException() {
        VqPsBuilder builder = new VqPsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT).withValidity(IAT, EXP).withJti(VALID_JTI)
                .addPurposeName("Name")
                .withRequest(VALID_SCOPE, validDcqlQuery());
        assertThrows(TrustStatementValidationException.class, builder::build);
    }
    @Test
    void build_missingRequest_throwsValidationException() {
        VqPsBuilder builder = new VqPsBuilder()
                .withKid(VALID_KID).withSubject(VALID_SUBJECT).withValidity(IAT, EXP).withJti(VALID_JTI)
                .addPurposeName("Name").addPurposeDesc("Desc.");
        assertThrows(TrustStatementValidationException.class, builder::build);
    }
    // ── Validation – Fail-Fast in setters ─────────────────────────────────────
    @Test
    void withJti_notUuidV4_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new VqPsBuilder().withJti("not-a-uuid"));
    }
    @Test
    void withJti_uuidV1_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new VqPsBuilder().withJti("550e8400-e29b-11d4-a716-446655440000"));
    }
    @Test
    void withJti_blankValue_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new VqPsBuilder().withJti("  "));
    }
    @Test
    void addPurposeName_exceedsMaxLength_throwsValidationException() {
        String name51 = "A".repeat(51);
        assertThrows(TrustStatementValidationException.class,
                () -> new VqPsBuilder().addPurposeName(name51));
    }
    @Test
    void addPurposeName_localizedExceedsMaxLength_throwsValidationException() {
        String name51 = "A".repeat(51);
        assertThrows(TrustStatementValidationException.class,
                () -> new VqPsBuilder().addPurposeName("de-CH", name51));
    }
    @Test
    void addPurposeName_blankValue_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new VqPsBuilder().addPurposeName("  "));
    }
    @Test
    void addPurposeDesc_exceedsMaxLength_throwsValidationException() {
        String desc501 = "A".repeat(501);
        assertThrows(TrustStatementValidationException.class,
                () -> new VqPsBuilder().addPurposeDesc(desc501));
    }
    @Test
    void addPurposeDesc_blankValue_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new VqPsBuilder().addPurposeDesc("  "));
    }
    @Test
    void withRequest_blankScope_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new VqPsBuilder().withRequest("  ", validDcqlQuery()));
    }
    @Test
    void withRequest_nullQuery_throwsValidationException() {
        assertThrows(TrustStatementValidationException.class,
                () -> new VqPsBuilder().withRequest(VALID_SCOPE, null));
    }
    @Test
    void withRequest_emptyCredentialsArray_throwsValidationException() {
        Map<String, Object> badQuery = Map.of("credentials", List.of());
        assertThrows(TrustStatementValidationException.class,
                () -> new VqPsBuilder().withRequest(VALID_SCOPE, badQuery));
    }
    @Test
    void withRequest_credentialMissingMeta_throwsValidationException() {
        Map<String, Object> badQuery = Map.of("credentials", List.of(
                Map.of("id", "c1", "format", "dc+sd-jwt")
        ));
        assertThrows(TrustStatementValidationException.class,
                () -> new VqPsBuilder().withRequest(VALID_SCOPE, badQuery));
    }
    @Test
    void withRequest_credentialMissingVctValues_throwsValidationException() {
        Map<String, Object> badQuery = Map.of("credentials", List.of(
                Map.of("id", "c1", "format", "dc+sd-jwt", "meta", Map.of())
        ));
        assertThrows(TrustStatementValidationException.class,
                () -> new VqPsBuilder().withRequest(VALID_SCOPE, badQuery));
    }
    @Test
    void withRequest_credentialEmptyVctValues_throwsValidationException() {
        Map<String, Object> badQuery = Map.of("credentials", List.of(
                Map.of("id", "c1", "format", "dc+sd-jwt",
                        "meta", Map.of("vct_values", List.of()))
        ));
        assertThrows(TrustStatementValidationException.class,
                () -> new VqPsBuilder().withRequest(VALID_SCOPE, badQuery));
    }
    @Test
    void withRequest_credentialMissingId_throwsValidationException() {
        Map<String, Object> badQuery = Map.of("credentials", List.of(
                Map.of("format", "dc+sd-jwt",
                        "meta", Map.of("vct_values", List.of("urn:example:vc1")))
        ));
        assertThrows(TrustStatementValidationException.class,
                () -> new VqPsBuilder().withRequest(VALID_SCOPE, badQuery));
    }

    @Test
    void withRequest_credentialIdWithInvalidCharacters_throwsValidationException() {
        // DCQL §6.1: id MUST consist of alphanumeric, underscore, or hyphen only
        Map<String, Object> badQuery = Map.of("credentials", List.of(
                Map.of("id", "invalid id!", "format", "dc+sd-jwt",
                        "meta", Map.of("vct_values", List.of("urn:example:vc1")))
        ));
        assertThrows(TrustStatementValidationException.class,
                () -> new VqPsBuilder().withRequest(VALID_SCOPE, badQuery));
    }

    @Test
    void withRequest_credentialMissingFormat_throwsValidationException() {
        Map<String, Object> badQuery = Map.of("credentials", List.of(
                Map.of("id", "my_credential",
                        "meta", Map.of("vct_values", List.of("urn:example:vc1")))
        ));
        assertThrows(TrustStatementValidationException.class,
                () -> new VqPsBuilder().withRequest(VALID_SCOPE, badQuery));
    }

    @Test
    void withRequest_credentialIdWithUnderscoreAndHyphen_doesNotThrow() {
        // DCQL §6.1: alphanumeric, underscore and hyphen are all valid
        Map<String, Object> validQuery = Map.of("credentials", List.of(
                Map.of("id", "my_credential-1", "format", "dc+sd-jwt",
                        "meta", Map.of("vct_values", List.of("urn:example:vc1")))
        ));
        assertDoesNotThrow(() -> new VqPsBuilder().withRequest(VALID_SCOPE, validQuery));
    }

    @Test
    void withRequest_multipleCredentials_allMustHaveVctValues() {
        // first credential valid, second missing meta → must throw
        Map<String, Object> badQuery = Map.of("credentials", List.of(
                Map.of("id", "c1", "format", "dc+sd-jwt",
                        "meta", Map.of("vct_values", List.of("urn:example:vc1"))),
                Map.of("id", "c2", "format", "dc+sd-jwt")  // missing meta
        ));
        assertThrows(TrustStatementValidationException.class,
                () -> new VqPsBuilder().withRequest(VALID_SCOPE, badQuery));
    }
}
