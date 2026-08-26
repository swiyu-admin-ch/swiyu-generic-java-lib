package ch.admin.bj.swiyu.sdjwtvalidator.verifier;

import java.text.ParseException;

import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;

import ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException;
import lombok.extern.slf4j.Slf4j;

/**
 * Validates the time-based JWT claims ({@code exp} and {@code nbf}) using Nimbus
 * {@link DefaultJWTClaimsVerifier} with a fixed clock skew tolerance.
 *
 * <p>This class is framework-agnostic and has no Spring dependencies.</p>
 */
@Slf4j
class SdJwtTimeClaimsValidator {

    private static final int MAX_CLOCK_SKEW_SECONDS = 60;

    /**
     * Validates the time-based JWT claims ({@code exp} and {@code nbf}) using Nimbus
     * {@link DefaultJWTClaimsVerifier} with the configured clock skew tolerance.
     *
     * <p>The {@code iss} claim is intentionally <em>ignored</em> (not verified, not forbidden)
     * per PARENT-ADR-027. {@code exp} and {@code nbf} are checked when present.</p>
     *
     * @param jwtString the compact serialized JWT
     * @throws JwtValidatorException if {@code exp} or {@code nbf} are violated
     */
    void validate(String jwtString) {
        try {
            SignedJWT jwt = SignedJWT.parse(jwtString);
            DefaultJWTClaimsVerifier<SecurityContext> verifier = new DefaultJWTClaimsVerifier<>(
                    null,                  // no required audience
                    new JWTClaimsSet.Builder().build(), // no exact match required
                    java.util.Set.of(),              // no required claims (exp/nbf checked if present)
                    java.util.Set.of()               // no prohibited claims – iss is ignored, not forbidden
            );
            verifier.setMaxClockSkew(MAX_CLOCK_SKEW_SECONDS);
            verifier.verify(jwt.getJWTClaimsSet(), null);
            log.debug("JWT time claims (exp/nbf) verified successfully");
        } catch (ParseException e) {
            throw new JwtValidatorException("Failed to parse JWT for claims verification", e);
        } catch (BadJOSEException e) {
            throw new JwtValidatorException("JWT time claim validation failed: " + e.getMessage(), e);
        }
    }
}
