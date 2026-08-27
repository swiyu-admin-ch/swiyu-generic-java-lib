package ch.admin.bj.swiyu.sdjwtverifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ch.admin.bj.swiyu.sdjwtverifier.exception.SdJwtVerificationException;

/**
 * Unit tests for {@link SdJwtHeaderValidator} in isolation.
 */
class SdJwtHeaderValidatorTest {

    private final SdJwtHeaderValidator validator = new SdJwtHeaderValidator();

    @Test
    void validate_whenKidPresent_thenSetsHeaderOnSdJwt() throws SdJwtVerificationException {
        SdJwt sdJwt = mock(SdJwt.class);
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("did:example:123#key-1").build(),
                new JWTClaimsSet.Builder().build());
        when(sdJwt.getJwt()).thenReturn(jwt);

        validator.validateandSetHeader(sdJwt);

        assertThat(jwt.getHeader().getKeyID()).isEqualTo("did:example:123#key-1");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "   "})
    void validate_whenKidBlankOrMissing_thenThrows(String kid) {
        SdJwt sdJwt = mock(SdJwt.class);
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(kid).build(),
                new JWTClaimsSet.Builder().build());
        when(sdJwt.getJwt()).thenReturn(jwt);

        assertThatThrownBy(() -> validator.validateandSetHeader(sdJwt))
                .isInstanceOf(SdJwtVerificationException.class)
                .hasMessageContaining("kid");
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"jwt", "sd-jwt", "kb+sd-jwt"})
    void parseSdJwt_wrongJWSHeaderType_thenThrows(String type) throws JOSEException {
        SdJwt sdJwt = mock(SdJwt.class);
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(type == null ? null : new JOSEObjectType(type) ).build(), new JWTClaimsSet.Builder().build());
        when(sdJwt.getJwt()).thenReturn(jwt);
        assertThatThrownBy(() -> validator.validateandSetHeader(sdJwt))
                .isInstanceOf(SdJwtVerificationException.class)
                .hasMessageContaining("typ");
    }
}
