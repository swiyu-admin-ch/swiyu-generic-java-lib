package ch.admin.bj.swiyu.sdjwtverifier;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;

import ch.admin.bj.swiyu.sdjwtutil.SdJwtConstants;
import ch.admin.bj.swiyu.sdjwtverifier.exception.SdJwtParseException;
import ch.admin.bj.swiyu.sdjwtverifier.exception.SdJwtVerificationException;

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
    void validateandSetHeader(SdJwt sdJwt) throws SdJwtVerificationException {
        JWSHeader header = sdJwt.getJwt().getHeader();

        validateKeyId(header);
        validateTypHeader(header);
        
        sdJwt.setHeader(header);
    }


    /**
     * Validates the {@code kid} JOSE header to be present
     * @param header
     * @throws SdJwtVerificationException
     */
    private void validateKeyId(JWSHeader header) throws SdJwtVerificationException {
        if (header.getKeyID() == null || header.getKeyID().isBlank()) {
            throw new SdJwtVerificationException("Missing header attribute 'kid' for the issuer's Key Id in the JWT token");
        }
    }


    /**
     * Validates the {@code typ} JOSE header against the configured accepted values.
     *
     * @param header the JOSE header of the parsed Issuer-Signed JWT
     * @throws SdJwtParseException if the {@code typ} is absent or not accepted
     */
    private static void validateTypHeader(JWSHeader header) throws SdJwtVerificationException {
        JOSEObjectType type = header.getType();
        if (type == null) {
            throw new SdJwtVerificationException(
                    "SD-JWT VC is missing the 'typ' JOSE header (must be '" + SdJwtConstants.TYP_DC_SD_JWT + "')");
        }
        if (!SdJwtConstants.ACCEPTED_TYP_VALUES.contains(type.getType())) {
            throw new SdJwtVerificationException(
                    "SD-JWT VC 'typ' is '" + type.getType() + "', expected one of: " + SdJwtConstants.ACCEPTED_TYP_VALUES);
        }
    }
}
