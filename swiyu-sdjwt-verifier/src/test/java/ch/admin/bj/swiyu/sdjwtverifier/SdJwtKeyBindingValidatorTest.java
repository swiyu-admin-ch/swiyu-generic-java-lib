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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ch.admin.bj.swiyu.sdjwtutil.SdJwtConstants;
import ch.admin.bj.swiyu.sdjwtverifier.exception.SdJwtVerificationException;

/**
 * Unit tests for {@link SdJwtKeyBindingValidator} in isolation (RFC 9901 §7.3).
 *
 * <p>Broader end-to-end/edge-case coverage of the orchestrated key binding flow lives in
 * {@link SdJwtVcValidatorTest}; this test focuses on the collaborator's own contract.</p>
 */
class SdJwtKeyBindingValidatorTest {

    private static final String AUDIENCE = "did:webvh:scid:example.com";
    private static final String SD_HASH = "sha256-9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    private static ECKey ecKey;
    private String nonce;

    private final SdJwtKeyBindingValidator validator = new SdJwtKeyBindingValidator();
    private SdJwt sdJwt;

    @BeforeAll
    static void generateKey() throws JOSEException {
        ecKey = new ECKeyGenerator(Curve.P_256).keyID("holder-key-1").generate();
    }

    @BeforeEach
    void setUp() {
        nonce = UUID.randomUUID().toString();
        sdJwt = mock(SdJwt.class);
        when(sdJwt.getClaims()).thenReturn(new JWTClaimsSet.Builder()
                .claim("cnf", Map.of("jwk", ecKey.toPublicJWK().toJSONObject())).build());
        when(sdJwt.getPresentationHash()).thenReturn(SD_HASH);
    }

    @Test
    void validate_withFreshAndMatchingKeyBinding_thenSucceeds() {
        when(sdJwt.getKeyBinding()).thenReturn(Optional.of(createKeyBindingJwt(ecKey, AUDIENCE, nonce, 0, SD_HASH)));

        assertDoesNotThrow(() -> validator.validate(sdJwt, AUDIENCE, nonce, 30));
    }

    @Test
    void validate_whenNoKeyBindingPresent_thenThrows() {
        when(sdJwt.getKeyBinding()).thenReturn(Optional.empty());

        assertThatThrownBy(() -> validator.validate(sdJwt, AUDIENCE, nonce, 30))
                .isInstanceOf(SdJwtVerificationException.class)
                .hasMessageContaining("No Key Binding found");
    }

    @Test
    void validate_whenSdHashDoesNotMatchPresentation_thenThrows() {
        when(sdJwt.getKeyBinding()).thenReturn(Optional.of(createKeyBindingJwt(ecKey, AUDIENCE, nonce, 0,
                "sha256-80a8a128935abce56f0bd8ef8036bf67aaca3ac05bd8b52cb31e11fdb66b5024")));

        assertThatThrownBy(() -> validator.validate(sdJwt, AUDIENCE, nonce, 30))
                .isInstanceOf(SdJwtVerificationException.class);
    }

    @Test
    void validate_whenKeyBindingProofIsExpired_thenThrows() {
        when(sdJwt.getKeyBinding()).thenReturn(Optional.of(createKeyBindingJwt(ecKey, AUDIENCE, nonce, 300, SD_HASH)));

        assertThatThrownBy(() -> validator.validate(sdJwt, AUDIENCE, nonce, 30))
                .isInstanceOf(SdJwtVerificationException.class)
                .hasMessageContaining("not recent enough");
    }

    private static String createKeyBindingJwt(ECKey signingKey, String audience, String nonce, int ageSeconds, String sdHash) {
        var claims = new JWTClaimsSet.Builder()
                .audience(audience)
                .claim("nonce", nonce)
                .issueTime(Date.from(Instant.now().minusSeconds(ageSeconds)))
                .claim("sd_hash", sdHash)
                .build();
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(SdJwtConstants.KEY_BINDING_TYPE).build(), claims);
        assertDoesNotThrow(() -> jwt.sign(new ECDSASigner(signingKey)));
        return jwt.serialize();
    }
}
