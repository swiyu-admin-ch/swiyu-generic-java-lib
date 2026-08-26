package ch.admin.bj.swiyu.sdjwtverifier;

import java.text.ParseException;

import com.nimbusds.jose.jwk.JWK;

import ch.admin.bj.swiyu.jwtvalidator.DidJwtValidator;
import ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException;
import ch.admin.bj.swiyu.sdjwtverifier.exception.SdJwtVerificationException;

/**
 * Validates the signature and DID-anchored issuer key of the JWT part of an SD-JWT VC by
 * delegating to the underlying {@link DidJwtValidator}.
 *
 * <p>This class is framework-agnostic and has no Spring dependencies.</p>
 */
class SdJwtSignatureValidator {

    private final DidJwtValidator didJwtValidator;

    SdJwtSignatureValidator(DidJwtValidator didJwtValidator) {
        this.didJwtValidator = didJwtValidator;
    }

    /**
     * Validates the signature of the JWT, ensuring the key is hosted on an acceptable registry.
     *
     * @param sdJwt the sd-jwt to be verified
     * @param issuerJWK the issuer's key resolved from the DID Document
     * @throws SdJwtVerificationException if the signature or claims are invalid
     */
    void validate(SdJwt sdJwt, JWK issuerJWK) throws SdJwtVerificationException {
        try {
            didJwtValidator.validateJwt(sdJwt.getSerializedJWT(), issuerJWK);
            sdJwt.setClaims(sdJwt.getJwt().getJWTClaimsSet());
        } catch (ParseException | JwtValidatorException e) {
            throw new SdJwtVerificationException("SD-JWT claims are not valid", e);
        }
    }
}
