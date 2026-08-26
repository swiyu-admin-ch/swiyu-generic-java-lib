package ch.admin.bj.swiyu.sdjwtvalidator.verifier;

import java.text.ParseException;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;

import ch.admin.bj.swiyu.jwtutil.JwtUtil;
import ch.admin.bj.swiyu.jwtutil.JwtUtilException;
import ch.admin.bj.swiyu.sdjwtvalidator.SdJwtConstants;
import ch.admin.bj.swiyu.sdjwtvalidator.exception.SdJwtVerificationException;

/**
 * Validates the Key Binding JWT of an SD-JWT according to RFC 9901 §7.3 (Key Binding Verification).
 *
 * <p>This class is framework-agnostic and has no Spring dependencies.</p>
 */
class SdJwtKeyBindingValidator {

    /**
     * Validates the Key Binding JWT of the SD-JWT, ensuring that it is fresh
     * and intended the correct audience according to RFC 9901 7.3 Key Binding Verification.
     * This function should only be called if a key binding proof is required.
     *
     * @param sdJwt the full validated SD-JWT
     * @param audience the audience (SD-JWT Verifier) for which the Key Binding should be issued
     * @param nonce the nonce which should be included in the Key Binding
     * @param acceptableKeyBindingWindow the acceptable window in seconds for the key binding, ensuring its freshness
     * @throws SdJwtVerificationException if no Key Binding is found or the key binding is not valid
     */
    void validate(SdJwt sdJwt, String audience, String nonce, int acceptableKeyBindingWindow) throws SdJwtVerificationException {
        JWK keyBindingKeyJwk = extractKeyBindingKey(sdJwt);
        try {
            SignedJWT keyBindingJWT = SignedJWT.parse(sdJwt.getKeyBinding().orElseThrow(() -> new SdJwtVerificationException("No Key Binding found")));
            // Validate the type
            JOSEObjectTypeVerifier<SecurityContext> typeVerifier = new DefaultJOSEObjectTypeVerifier<>(SdJwtConstants.KEY_BINDING_TYPE);
            typeVerifier.verify(keyBindingJWT.getHeader().getType(), null);
            // Validate the JWT before working with the claims
            JwtUtil.verifySignedJwt(keyBindingJWT, keyBindingKeyJwk);
            DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier = new DefaultJWTClaimsVerifier<>(
                    Set.of(audience), // the key binding must be adressed to us
                    new JWTClaimsSet.Builder()
                        .claim("nonce", nonce) // must be for the noncewe requested
                        .claim("sd_hash", sdJwt.getPresentationHash()).build(), // must match the hash of the sd-jwt the key binding is a proof for
                    Set.of("iat", "aud", "nonce", "sd_hash"),              // RFC 9901 required claims (exp/nbf checked if present)
                    Set.of()               // no prohibited claims
            );
            claimsVerifier.verify(keyBindingJWT.getJWTClaimsSet(), null);
            // Validate freshness of Key Binding Proof
            validateKeyBindingJWTCreationTime(keyBindingJWT.getJWTClaimsSet().getIssueTime().toInstant(), acceptableKeyBindingWindow);

        } catch (ParseException e) {
            throw new SdJwtVerificationException("Key binding JWT cannot be parsed", e);
        } catch (JwtUtilException | BadJOSEException e) {
            throw new SdJwtVerificationException("Key binding JWT is invalid", e);
        }
    }

    /**
     * @param proofIssueTime Instant when the Key Binding JWT was issued
     * @param acceptableKeyBindingWindow time window which is acceptable for the issue time, allowing for some clock skew and delays
     * @throws SdJwtVerificationException if the issue time verification was not successful
     */
    private void validateKeyBindingJWTCreationTime(Instant proofIssueTime, int acceptableKeyBindingWindow)
            throws SdJwtVerificationException {

        Instant now = Instant.now();
        // iat not within acceptable proof time window
        if (proofIssueTime.isBefore(now.minusSeconds(acceptableKeyBindingWindow))
                || proofIssueTime.isAfter(now.plusSeconds(acceptableKeyBindingWindow))) {
            throw new SdJwtVerificationException(String.format("Key Binding proof is not recent enough. iat must be within +/- %d seconds of %d", acceptableKeyBindingWindow, now.getEpochSecond()));
        }
    }

    /**
     * Extract the key binding from the sd jwt
     *
     * @return the JWK bound as confirmation (cnf) key to the sd-jwt
     * @throws SdJwtVerificationException if the cnf key cannot be parsed
     */
    private JWK extractKeyBindingKey(SdJwt sdJwt) throws SdJwtVerificationException {
        // Get the RFC 7800 cnf claim
        if (sdJwt.getClaims().getClaim("cnf") instanceof Map confirmation) {

            // Some legacy VCs may still hold an incorrect cnf structure with additional jwk wrapping
            if (confirmation.containsKey("jwk") && confirmation.get("jwk") instanceof Map wrappedConfirmation) {
                confirmation = wrappedConfirmation;
            }

            try {
                return JWK.parse(confirmation);
            } catch (ParseException e) {
                throw new SdJwtVerificationException("Key Binding Key cannot be parsed", e);
            }
        }
        throw new SdJwtVerificationException("No Key Binding Key found");
    }
}
