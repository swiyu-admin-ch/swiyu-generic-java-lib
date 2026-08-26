package ch.admin.bj.swiyu.sdjwtverifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ch.admin.bj.swiyu.jwtvalidator.DidJwtValidator;
import ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException;
import ch.admin.bj.swiyu.sdjwtverifier.exception.SdJwtVerificationException;

/**
 * Unit tests for {@link SdJwtSignatureValidator} in isolation, i.e. without exercising the
 * real {@link DidJwtValidator} (which is mocked here).
 */
class SdJwtSignatureValidatorTest {

    private DidJwtValidator didJwtValidator;
    private SdJwtSignatureValidator validator;
    private SdJwt sdJwt;
    private SignedJWT jwt;
    private JWK issuerJwk;

    @BeforeEach
    void setUp() throws Exception {
        didJwtValidator = mock(DidJwtValidator.class);
        validator = new SdJwtSignatureValidator(didJwtValidator);
        sdJwt = mock(SdJwt.class);
        issuerJwk = new ECKeyGenerator(Curve.P_256).keyID("key-1").generate();
        jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("key-1").build(),
                new JWTClaimsSet.Builder().claim("foo", "bar").build());
        when(sdJwt.getSerializedJWT()).thenReturn("dummy.jwt.string");
        when(sdJwt.getJwt()).thenReturn(jwt);
    }

    @Test
    void validate_whenDidJwtValidatorAccepts_thenClaimsAreSetOnSdJwt() throws Exception {
        validator.validate(sdJwt, issuerJwk);

        verify(didJwtValidator).validateJwt("dummy.jwt.string", issuerJwk);
        verify(sdJwt).setClaims(jwt.getJWTClaimsSet());
    }

    @Test
    void validate_whenDidJwtValidatorRejects_thenThrowsSdJwtVerificationException() {
        doThrow(new JwtValidatorException("signature invalid")).when(didJwtValidator).validateJwt("dummy.jwt.string", issuerJwk);

        assertThatThrownBy(() -> validator.validate(sdJwt, issuerJwk))
                .isInstanceOf(SdJwtVerificationException.class)
                .hasMessageContaining("SD-JWT claims are not valid")
                .hasCauseInstanceOf(JwtValidatorException.class);
    }
}
