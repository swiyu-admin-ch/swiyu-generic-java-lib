package ch.admin.bj.swiyu.sdjwtvalidator.verifier;

import com.nimbusds.jose.JWSHeader;

import ch.admin.bj.swiyu.sdjwtvalidator.exception.SdJwtVerificationException;

/**
 * Validates the JOSE header of an SD-JWT VC according to the Swiss Profile requirements.
 *
 * <p>This class is framework-agnostic and has no Spring dependencies.</p>
 */
class SdJwtHeaderValidator {

    /**
     * Validates the header to conform to swiss-profile 1.0 requirements.
     * Makes the header available in the provided {@link SdJwt} object
     *
     * @param sdJwt The sdJwt which will be verified and altered
     * @throws SdJwtVerificationException if the verification failed
     */
    void validate(SdJwt sdJwt) throws SdJwtVerificationException {
        JWSHeader header = sdJwt.getJwt().getHeader();

        if (header.getKeyID() == null || header.getKeyID().isBlank()) {
            throw new SdJwtVerificationException("Missing header attribute 'kid' for the issuer's Key Id in the JWT token");
        }
        sdJwt.setHeader(header);
    }
}
