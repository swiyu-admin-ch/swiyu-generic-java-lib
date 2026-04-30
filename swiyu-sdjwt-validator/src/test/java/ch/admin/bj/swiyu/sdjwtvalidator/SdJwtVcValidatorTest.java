package ch.admin.bj.swiyu.sdjwtvalidator;

import ch.admin.bj.swiyu.jwtvalidator.DidJwtValidator;
import ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class SdJwtVcValidatorTest {

    private static final String KID =
            "did:tdw:Qma6mc1qZw3NqxwX6SB5GPQYzP4pHN1f7iLTaU6p7SBms:identifier.admin.ch#key-01";

    private static final String DISCLOSURE_GIVEN_NAME =
            Base64.getUrlEncoder().withoutPadding().encodeToString(
                    "[\"salt1\",\"given_name\",\"Max\"]".getBytes(StandardCharsets.UTF_8));
    private static final String DISCLOSURE_ISS =
            Base64.getUrlEncoder().withoutPadding().encodeToString(
                    "[\"salt2\",\"iss\",\"https://issuer.example.com\"]".getBytes(StandardCharsets.UTF_8));

    private DidJwtValidator mockDidJwtValidator;
    private SdJwtVcValidator validator;
    private ECKey ecKey;

    @BeforeEach
    void setUp() throws Exception {
        mockDidJwtValidator = mock(DidJwtValidator.class);
        validator = new SdJwtVcValidator(mockDidJwtValidator);
        ecKey = new ECKeyGenerator(Curve.P_256).keyID(KID).generate();
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    @Test
    void constructor_nullDidJwtValidator_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new SdJwtVcValidator(null));
    }

    @Test
    void constructor_emptyAcceptedTypValues_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new SdJwtVcValidator(mockDidJwtValidator, Set.of()));
    }

    // -------------------------------------------------------------------------
    // typ header validation
    // -------------------------------------------------------------------------

    @Test
    void validateSdJwtVc_missingTypHeader_throwsJwtValidatorException() throws Exception {
        String sdJwt = buildSdJwt(null, "sha-256") + DISCLOSURE_GIVEN_NAME + "~";
        JwtValidatorException ex = assertThrows(JwtValidatorException.class,
                () -> validator.validateSdJwtVc(sdJwt, (com.nimbusds.jose.jwk.JWKSet) null));
        assertTrue(ex.getMessage().contains("typ"));
    }

    @Test
    void validateSdJwtVc_wrongTypHeader_throwsJwtValidatorException() throws Exception {
        String sdJwt = buildSdJwt("JWT", "sha-256") + DISCLOSURE_GIVEN_NAME + "~";
        JwtValidatorException ex = assertThrows(JwtValidatorException.class,
                () -> validator.validateSdJwtVc(sdJwt, (JWKSet) null));
        assertTrue(ex.getMessage().contains("'typ'") || ex.getMessage().contains("typ"));
    }

    @Test
    void validateSdJwtVc_dcSdJwtTyp_passes() throws Exception {
        String sdJwt = buildSdJwt(SdJwtVcValidator.TYP_DC_SD_JWT, "sha-256") + DISCLOSURE_GIVEN_NAME + "~";
        JWKSet jwkSet = new JWKSet(ecKey.toPublicJWK());
        doNothing().when(mockDidJwtValidator).validateJwt(anyString(), any(JWKSet.class));
        assertDoesNotThrow(() -> validator.validateSdJwtVc(sdJwt, jwkSet));
    }

    @Test
    void validateSdJwtVc_migrationMode_acceptsVcSdJwt() throws Exception {
        SdJwtVcValidator migrationValidator = new SdJwtVcValidator(
                mockDidJwtValidator,
                Set.of(SdJwtVcValidator.TYP_DC_SD_JWT, SdJwtVcValidator.TYP_VC_SD_JWT));
        String sdJwt = buildSdJwt(SdJwtVcValidator.TYP_VC_SD_JWT, "sha-256") + DISCLOSURE_GIVEN_NAME + "~";
        JWKSet jwkSet = new JWKSet(ecKey.toPublicJWK());
        doNothing().when(mockDidJwtValidator).validateJwt(anyString(), any(JWKSet.class));
        assertDoesNotThrow(() -> migrationValidator.validateSdJwtVc(sdJwt, jwkSet));
    }

    @Test
    void validateSdJwtVc_migrationMode_strictMode_rejectsVcSdJwt() throws Exception {
        // Default validator only accepts dc+sd-jwt
        String sdJwt = buildSdJwt(SdJwtVcValidator.TYP_VC_SD_JWT, "sha-256") + DISCLOSURE_GIVEN_NAME + "~";
        assertThrows(JwtValidatorException.class,
                () -> validator.validateSdJwtVc(sdJwt, (JWKSet) null));
    }

    // -------------------------------------------------------------------------
    // _sd_alg validation
    // -------------------------------------------------------------------------

    @Test
    void validateSdJwtVc_missingSdAlg_throwsJwtValidatorException() throws Exception {
        String sdJwt = buildSdJwtWithoutSdAlg() + DISCLOSURE_GIVEN_NAME + "~";
        JwtValidatorException ex = assertThrows(JwtValidatorException.class,
                () -> validator.validateSdJwtVc(sdJwt, (JWKSet) null));
        assertTrue(ex.getMessage().contains("_sd_alg"));
    }

    @Test
    void validateSdJwtVc_wrongSdAlg_throwsJwtValidatorException() throws Exception {
        String sdJwt = buildSdJwt(SdJwtVcValidator.TYP_DC_SD_JWT, "sha-512") + DISCLOSURE_GIVEN_NAME + "~";
        JwtValidatorException ex = assertThrows(JwtValidatorException.class,
                () -> validator.validateSdJwtVc(sdJwt, (JWKSet) null));
        assertTrue(ex.getMessage().contains("sha-256"));
    }

    // -------------------------------------------------------------------------
    // Protected claims in Disclosures
    // -------------------------------------------------------------------------

    @Test
    void validateSdJwtVc_issInDisclosure_throwsJwtValidatorException() throws Exception {
        String sdJwt = buildSdJwt(SdJwtVcValidator.TYP_DC_SD_JWT, "sha-256")
                + DISCLOSURE_ISS + "~";
        JwtValidatorException ex = assertThrows(JwtValidatorException.class,
                () -> validator.validateSdJwtVc(sdJwt, (JWKSet) null));
        assertTrue(ex.getMessage().contains("'iss'"));
    }

    @Test
    void validateSdJwtVc_allProtectedClaimsRejected() {
        for (String claim : SdJwtVcValidator.PROTECTED_CLAIMS) {
            String disclosure = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    ("[\"salt\",\"" + claim + "\",\"value\"]").getBytes(StandardCharsets.UTF_8));
            String sdJwt;
            try {
                sdJwt = buildSdJwt(SdJwtVcValidator.TYP_DC_SD_JWT, "sha-256") + disclosure + "~";
            } catch (Exception e) {
                fail("Failed to build SD-JWT for claim: " + claim);
                return;
            }
            assertThrows(JwtValidatorException.class,
                    () -> validator.validateSdJwtVc(sdJwt, (JWKSet) null),
                    "Expected rejection for protected claim: " + claim);
        }
    }

    @Test
    void validateSdJwtVc_arrayElementDisclosure_size2_doesNotThrow() throws Exception {
        // Array element disclosures have format [salt, value] (size 2) – no claim name to check
        String arrayElementDisclosure = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "[\"salt3\",\"some-array-value\"]".getBytes(StandardCharsets.UTF_8));
        String sdJwt = buildSdJwt(SdJwtVcValidator.TYP_DC_SD_JWT, "sha-256")
                + arrayElementDisclosure + "~";
        JWKSet jwkSet = new JWKSet(ecKey.toPublicJWK());
        doNothing().when(mockDidJwtValidator).validateJwt(anyString(), any(JWKSet.class));
        assertDoesNotThrow(() -> validator.validateSdJwtVc(sdJwt, jwkSet));
    }

    @Test
    void validateSdJwtVc_invalidDisclosureSize_throwsJwtValidatorException() throws Exception {
        // A disclosure with only 1 element is invalid
        String invalidDisclosure = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "[\"only-one-element\"]".getBytes(StandardCharsets.UTF_8));
        String sdJwt = buildSdJwt(SdJwtVcValidator.TYP_DC_SD_JWT, "sha-256")
                + invalidDisclosure + "~";
        assertThrows(JwtValidatorException.class,
                () -> validator.validateSdJwtVc(sdJwt, (JWKSet) null));
    }

    @Test
    void validateSdJwtVc_validDisclosure_doesNotThrow() throws Exception {
        String sdJwt = buildSdJwt(SdJwtVcValidator.TYP_DC_SD_JWT, "sha-256")
                + DISCLOSURE_GIVEN_NAME + "~";
        JWKSet jwkSet = new JWKSet(ecKey.toPublicJWK());
        doNothing().when(mockDidJwtValidator).validateJwt(anyString(), any(JWKSet.class));
        assertDoesNotThrow(() -> validator.validateSdJwtVc(sdJwt, jwkSet));
    }

    // -------------------------------------------------------------------------
    // getAndValidateResolutionUrl
    // -------------------------------------------------------------------------

    @Test
    void getAndValidateResolutionUrl_invalidTyp_throwsBeforeDelegating() throws Exception {
        String sdJwt = buildSdJwt("JWT", "sha-256") + DISCLOSURE_GIVEN_NAME + "~";
        assertThrows(JwtValidatorException.class,
                () -> validator.getAndValidateResolutionUrl(sdJwt));
        verify(mockDidJwtValidator, never()).getAndValidateResolutionUrl(anyString());
    }

    @Test
    void getAndValidateResolutionUrl_validTyp_delegatesToDidJwtValidator() throws Exception {
        String sdJwt = buildSdJwt(SdJwtVcValidator.TYP_DC_SD_JWT, "sha-256")
                + DISCLOSURE_GIVEN_NAME + "~";
        when(mockDidJwtValidator.getAndValidateResolutionUrl(anyString()))
                .thenReturn("https://identifier.admin.ch/abc/did.jsonl");

        String url = validator.getAndValidateResolutionUrl(sdJwt);

        assertEquals("https://identifier.admin.ch/abc/did.jsonl", url);
        verify(mockDidJwtValidator).getAndValidateResolutionUrl(anyString());
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Builds a signed SD-JWT Issuer-Signed JWT with a trailing {@code ~} ready
     * for Disclosure appending. Returns {@code "<jwt>~"}.
     */
    private String buildSdJwt(String typ, String sdAlg) throws Exception {
        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(KID);
        if (typ != null) {
            headerBuilder.type(new com.nimbusds.jose.JOSEObjectType(typ));
        }
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("_sd_alg", sdAlg)
                .claim("vct", "https://example.com/MyCredential")
                .build();
        return sign(headerBuilder.build(), claims) + "~";
    }

    /** Builds a signed SD-JWT without any {@code _sd_alg} claim. */
    private String buildSdJwtWithoutSdAlg() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(KID)
                .type(new com.nimbusds.jose.JOSEObjectType(SdJwtVcValidator.TYP_DC_SD_JWT))
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("vct", "https://example.com/MyCredential")
                .build();
        return sign(header, claims) + "~";
    }

    private String sign(JWSHeader header, JWTClaimsSet claims) throws Exception {
        JWSSigner signer = new ECDSASigner(ecKey);
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(signer);
        return jwt.serialize();
    }
}

