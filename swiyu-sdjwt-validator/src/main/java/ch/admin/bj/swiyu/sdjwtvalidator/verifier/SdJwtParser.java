package ch.admin.bj.swiyu.sdjwtvalidator.verifier;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Base64;
import java.util.Optional;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.SignedJWT;

import ch.admin.bj.swiyu.sdjwtvalidator.SdJwtConstants;
import ch.admin.bj.swiyu.sdjwtvalidator.exception.SdJwtParseException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
/**
 * Parses the compact serialization format of an SD-JWT.
 *
 * <p>An SD-JWT has the following structure (RFC 9901 §4):
 * <pre>
 *   &lt;Issuer-signed JWT&gt;~&lt;Disclosure 1&gt;~...~&lt;Disclosure N&gt;~
 * </pre>
 * The trailing {@code ~} after the last Disclosure is mandatory.
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class SdJwtParser {

    private static final String JWT_PART_DELINEATION_CHARACTER = SdJwtConstants.JWT_PART_DELINEATION_CHARACTER;


    public static SdJwt parseSdJwt(String serializedSdJwt) throws SdJwtParseException {
        if (!serializedSdJwt.contains(JWT_PART_DELINEATION_CHARACTER)
                || serializedSdJwt.contains(JWT_PART_DELINEATION_CHARACTER + JWT_PART_DELINEATION_CHARACTER) // denotes multiple tilde ('~') characters
        ) {
            throw new SdJwtParseException("SD-JWT is malformed: expected at least one non-empty part delineated by '~'");
        }
        // According to https://www.rfc-editor.org/rfc/rfc9901.html#section-4:
        // "The compact serialized format for the SD-JWT is the concatenation of each part delineated with a single tilde ('~') character"

        // CAUTION The String#split method ignores trailing delimiters unless a limit of -1 is explicitly specified:
        //         "If the limit is negative then the pattern will be applied as many times as possible and the array can have any length."
        String[] parts = serializedSdJwt.split(JWT_PART_DELINEATION_CHARACTER);
        if (parts.length == 0 || parts[0].isEmpty()) {
            // e.g. input consisting only of "~" splits into an empty array
            throw new SdJwtParseException("SD-JWT is malformed: missing Issuer-signed JWT part");
        }
        Optional<String> holderBindingProof = extractHolderBindingProof(serializedSdJwt, parts);
        String presentationHash = computeKeyBindingSdHash(serializedSdJwt);
        try {
            SdJwt sdJwt = new SdJwt(SignedJWT.parse(parts[0]), parts, holderBindingProof, presentationHash);
            validateStructure(sdJwt);
            return sdJwt;
             
        } catch (ParseException e) {
            throw new SdJwtParseException("Failed to parse JWT part of SD-JWT", e);
        }
    }


    /**
     * According to https://www.rfc-editor.org/rfc/rfc9901.html#section-4:
     * "In the case that there is no Key Binding JWT, the last element MUST be an
     * empty string and the last separating tilde character MUST NOT be omitted."
     * 
     * @param serializedSdJwt the full serialized sd jwt including all provided disclosure and optional holder binding
     * @param parts the already split parts of the sd jwt
     * @return Optional containing the serialized holder binding proof, if available. Empty if not present
     */
    private static Optional<String> extractHolderBindingProof(String serializedSdJwt, String[] parts) {
        if (!serializedSdJwt.endsWith(JWT_PART_DELINEATION_CHARACTER)) {
            return Optional.of(parts[parts.length - 1]);
        } else {
            return Optional.empty();
        }
    }

    /**
     * Compute the sd_hash of the base64url-encoded hash value over the Issuer-signed JWT and the selected Disclosures. 
     * This hash is contained in the key binding jwt.
     * @param rawSdJwt the full serialized sd-jwt
     * @return the base64url encoded hash without padding
     */
    private static String computeKeyBindingSdHash(String rawSdJwt) {
        // The jwt and disclosures without the key binding jwt
        var presentation = rawSdJwt.substring(0, rawSdJwt.lastIndexOf(JWT_PART_DELINEATION_CHARACTER) + 1);
        try {
            byte[] hashDigest = MessageDigest.getInstance("sha-256") // getInstance may throw NoSuchAlgorithmException
                            .digest(presentation.getBytes(StandardCharsets.UTF_8));
            var presentationHash = new String(Base64.getUrlEncoder().withoutPadding().encode(hashDigest));
            return presentationHash;
        } catch (NoSuchAlgorithmException exc) {
            // CAUTION No VerificationException.credentialError(VerificationErrorResponseCode.MALFORMED_CREDENTIAL, ...)
            //         should be called here, as there must be a provider supporting a MessageDigestSpi implementation
            //         for the (standard) "sha-256" algorithm
            throw new IllegalStateException("Loading hash algorithm failed. Please check the configuration", exc);
        }
    }


    /**
     * Runs all structural SD-JWT VC checks ({@code typ}, {@code _sd_alg}, protected claims).
     *
     * @param sdJwt the full SD-JWT string
     * @throws SdJwtParseException if any structural check fails
     */
    private static void validateStructure(SdJwt sdJwt) throws SdJwtParseException {
        SignedJWT jwt = sdJwt.getJwt();
        validateTypHeader(jwt.getHeader());
        validateNoProtectedClaimsInDisclosures(sdJwt);
        
    }

    /**
     * Validates the {@code typ} JOSE header against the configured accepted values.
     *
     * @param header the JOSE header of the parsed Issuer-Signed JWT
     * @throws SdJwtParseException if the {@code typ} is absent or not accepted
     */
    private static void validateTypHeader(JWSHeader header) throws SdJwtParseException {
        JOSEObjectType type = header.getType();
        if (type == null) {
            throw new SdJwtParseException(
                    "SD-JWT VC is missing the 'typ' JOSE header (must be '" + SdJwtConstants.TYP_DC_SD_JWT + "')");
        }
        if (!SdJwtConstants.ACCEPTED_TYP_VALUES.contains(type.getType())) {
            throw new SdJwtParseException(
                    "SD-JWT VC 'typ' is '" + type.getType() + "', expected one of: " + SdJwtConstants.ACCEPTED_TYP_VALUES);
        }
        log.debug("SD-JWT VC typ '{}' accepted", type.getType());
    }

    /**
     * Validates that none of the {@link SdJwtConstants#PROTECTED_CLAIMS} appear as the claim name
     * (index 1) in any Disclosure array {@code [salt, claim_name, claim_value]}.
     *
     * @param sdJwt the full SD-JWT string including all Disclosures
     * @throws SdJwtParseException if any Disclosure contains a protected claim name
     */
    private static void validateNoProtectedClaimsInDisclosures(SdJwt sdJwt) throws SdJwtParseException {
        if (sdJwt.getDisclosures().stream().filter(d -> d.getClaimName() != null).anyMatch(d -> SdJwtConstants.PROTECTED_CLAIMS.contains(d.getClaimName()))) {
            throw new SdJwtParseException("Presented SD-JWT contains a protected claim. This can indicate a malicious issuer.");
        }
    }
}
