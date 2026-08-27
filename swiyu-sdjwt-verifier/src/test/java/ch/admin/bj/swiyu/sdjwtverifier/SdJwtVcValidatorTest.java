package ch.admin.bj.swiyu.sdjwtverifier;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ch.admin.bj.swiyu.jwtvalidator.DidJwtValidator;
import ch.admin.bj.swiyu.sdjwtutil.SdJwtConstants;
import ch.admin.bj.swiyu.sdjwtverifier.exception.SdJwtVerificationException;

/**
 * 
 * Test edge cases for SdJwtVcValidator. For happy path see {@link SdJwtUsageTest}
 */
class SdJwtVcValidatorTest {

    private static final String KID =
    "did:webvh:scid:example.com#key-01";
    
    private static final String NONCE = UUID.randomUUID().toString();
    private static final String AUDIENCE = "did:webvh:scid:example.com";
    private static final String SD_HASH = "sha256-9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    private static ECKey ecKey;
    
    private DidJwtValidator mockDidJwtValidator;
    private SdJwtVcValidator validator;
    private SdJwt sdJwt;
    
    @BeforeAll
    static void init() throws Exception {
        ecKey = new ECKeyGenerator(Curve.P_256).keyID(KID).generate();
    }

    @BeforeEach
    void setUp() throws Exception {
        mockDidJwtValidator = mock(DidJwtValidator.class);
        validator = new SdJwtVcValidator(mockDidJwtValidator);
        sdJwt = mock(SdJwt.class);
    }

    @Test
    void validateHeader_whenKIDmissing_thenThrows() {
        SignedJWT testJwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).build(), new JWTClaimsSet.Builder().build());
        when(sdJwt.getJwt()).thenReturn(testJwt);
        assertThatThrownBy(() -> validator.validateHeader(sdJwt)).isInstanceOf(SdJwtVerificationException.class).hasMessageContaining("kid");
    }


    @Test
    void validateKeyBinding_whenNoConfirmationKey_thenThrows() {
        when(sdJwt.getClaims()).thenReturn(new JWTClaimsSet.Builder().build());
        assertThatThrownBy(() -> validator.validateKeyBinding(sdJwt, "", "", 0))
            .isInstanceOf(SdJwtVerificationException.class)
            .hasMessageContaining("No Key Binding Key found");
    }

    @Test
    void validateKeyBinding_whenMalformedConfirmationKey_thenThrows() {
        when(sdJwt.getClaims()).thenReturn(new JWTClaimsSet.Builder().claim("cnf", Map.of("jwk", "jwk")).build());
        assertThatThrownBy(() -> validator.validateKeyBinding(sdJwt, "", "", 0))
            .isInstanceOf(SdJwtVerificationException.class)
            .hasMessageContaining("Key Binding Key cannot be parsed");
    }

    @ParameterizedTest
    @MethodSource("keyBindingJwtMissingParameter")
    void validateKeyBinding_whenIncorrectKeyBinding_thenThrows(KeyBindingTestData keyBindingJwt) {
        // Get through key binding key checks
        prepareSdJwtForKeyBindingTest(sdJwt, ecKey);
        when(sdJwt.getKeyBinding()).thenReturn(Optional.of(keyBindingJwt.kbjwt()));
        if(keyBindingJwt.succeeds) {
            assertDoesNotThrow( () -> validator.validateKeyBinding(sdJwt, AUDIENCE, NONCE, 20));
        } else {
            assertThatThrownBy(() -> validator.validateKeyBinding(sdJwt, AUDIENCE, NONCE, 20))
                .isInstanceOf(SdJwtVerificationException.class);
        }
    }

    /**
     * Generator Function to test various key binding jwt faults
     */
    static Stream<KeyBindingTestData> keyBindingJwtMissingParameter() throws JOSEException {
        ECKey otherKey = assertDoesNotThrow(() -> new ECKeyGenerator(Curve.P_256).generate());
        return Stream.of(
            new KeyBindingTestData(false, createKeyBindingJwt(ecKey, null, NONCE, 1, SD_HASH)), // Missing Parameters
            new KeyBindingTestData(false, createKeyBindingJwt(ecKey, AUDIENCE, null, 1, SD_HASH)), // Missing Parameters
            new KeyBindingTestData(false, createKeyBindingJwt(ecKey, AUDIENCE, NONCE, 0, SD_HASH)), // Missing Parameter iat
            new KeyBindingTestData(false, createKeyBindingJwt(ecKey, "did:webvh:scid:some.other.com", NONCE, 1, SD_HASH)), // Wrong Audience
            new KeyBindingTestData(false, createKeyBindingJwt(ecKey, AUDIENCE, UUID.randomUUID().toString(), 1, SD_HASH)), // Wrong Nonce
            new KeyBindingTestData(false, createKeyBindingJwt(ecKey, AUDIENCE, NONCE, 120, SD_HASH)), // Expired
            new KeyBindingTestData(false, createKeyBindingJwt(ecKey, AUDIENCE, NONCE, -120, SD_HASH)), // in future
            new KeyBindingTestData(false, createKeyBindingJwt(otherKey, AUDIENCE, NONCE, 1, SD_HASH)), // Used different key for signature
            new KeyBindingTestData(false, createKeyBindingJwt(ecKey, AUDIENCE, NONCE, 1, "sha256-80a8a128935abce56f0bd8ef8036bf67aaca3ac05bd8b52cb31e11fdb66b5024")), // Wrong SD-Hash
            new KeyBindingTestData(true, createKeyBindingJwt(ecKey, AUDIENCE, NONCE, 1, SD_HASH)) // Valid, so a bug in configuring the test key bindings can be ruled out
        );
    }

    record KeyBindingTestData(boolean succeeds, String kbjwt){}

    static String createKeyBindingJwt(ECKey signingKey, String audience, String nonce, int ageSeconds, String sdHash) {
        var claims = new JWTClaimsSet.Builder()
            .audience(audience)
            .claim("nonce", nonce)
            .issueTime(ageSeconds != 0 ? Date.from(Instant.now().minusSeconds(ageSeconds)) : null)
            .claim("sd_hash", sdHash)
            .build();
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(SdJwtConstants.KEY_BINDING_TYPE).build(),
            claims);
        assertDoesNotThrow( () -> jwt.sign(new ECDSASigner(signingKey)));
        return jwt.serialize();
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Prepares SdJwt mock with confirmation key
     * @param key 
     */
    private void prepareSdJwtForKeyBindingTest(SdJwt sdJwt, JWK key) {
        when(sdJwt.getClaims()).thenReturn(new JWTClaimsSet.Builder().claim("cnf", Map.of("jwk", key.toPublicJWK().toJSONObject())).build());
        when(sdJwt.getPresentationHash()).thenReturn(SD_HASH);
    }
}

