package ch.admin.bj.swiyu.sdjwtverifier;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import org.junit.jupiter.api.BeforeAll;
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

import ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException;

/**
 * Unit tests for {@link SdJwtTimeClaimsValidator}.
 */
class SdJwtTimeClaimsValidatorTest {

    private final SdJwtTimeClaimsValidator validator = new SdJwtTimeClaimsValidator();
    private static ECKey signingKey;

    @BeforeAll
    static void generateKey() throws JOSEException {
        signingKey = new ECKeyGenerator(Curve.P_256).keyID("key-1").generate();
    }

    @Test
    void validate_whenExpAndNbfWithinValidWindow_thenDoesNotThrow() {
        String jwt = createJwt(Instant.now().minus(1, ChronoUnit.HOURS), Instant.now().plus(1, ChronoUnit.HOURS));

        assertDoesNotThrow(() -> validator.validate(jwt));
    }

    @Test
    void validate_whenNoTimeClaimsPresent_thenDoesNotThrow() {
        String jwt = createJwt(null, null);

        assertDoesNotThrow(() -> validator.validate(jwt));
    }

    @Test
    void validate_whenExpired_thenThrows() {
        String jwt = createJwt(Instant.now().minus(2, ChronoUnit.HOURS), Instant.now().minus(1, ChronoUnit.HOURS));

        assertThatThrownBy(() -> validator.validate(jwt))
                .isInstanceOf(JwtValidatorException.class);
    }

    @Test
    void validate_whenNotYetValid_thenThrows() {
        String jwt = createJwt(Instant.now().plus(1, ChronoUnit.HOURS), Instant.now().plus(2, ChronoUnit.HOURS));

        assertThatThrownBy(() -> validator.validate(jwt))
                .isInstanceOf(JwtValidatorException.class);
    }

    @Test
    void validate_whenJwtCannotBeParsed_thenThrows() {
        assertThatThrownBy(() -> validator.validate("not-a-valid-jwt"))
                .isInstanceOf(JwtValidatorException.class)
                .hasMessageContaining("parse");
    }

    private static String createJwt(Instant notBefore, Instant expiry) {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder();
        if (notBefore != null) {
            claims.notBeforeTime(Date.from(notBefore));
        }
        if (expiry != null) {
            claims.expirationTime(Date.from(expiry));
        }
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(signingKey.getKeyID()).build(), claims.build());
        try {
            jwt.sign(new ECDSASigner(signingKey));
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
        return jwt.serialize();
    }
}
