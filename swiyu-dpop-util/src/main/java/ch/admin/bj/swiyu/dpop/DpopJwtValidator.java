package ch.admin.bj.swiyu.dpop;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.experimental.UtilityClass;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

/**
 * Shared validation helpers for DPoP JWTs.
 * <p>
 * Provides static methods for parsing and validating DPoP JWTs, including header, claims, signature,
 * and proof-of-possession requirements as per the DPoP specification.
 * </p>
 */
@UtilityClass
public final class DpopJwtValidator {

    /**
     * Parses a DPoP JWT string into a SignedJWT object.
     *
     * @param dpop the DPoP JWT as a string
     * @return the parsed SignedJWT
     * @throws ParseException if the JWT cannot be parsed
     */
    public static SignedJWT parse(String dpop) throws ParseException {
        return SignedJWT.parse(dpop);
    }

    /**
     * Validates that all mandatory header and payload claims are present in the DPoP JWT.
     *
     * @param header    the JWS header
     * @param jwtClaims the JWT claims set
     * @throws DpopValidationException if any mandatory claim is missing
     */
    public static void validateMandatoryClaims(JWSHeader header, JWTClaimsSet jwtClaims) {
        if (!header.toJSONObject().keySet().containsAll(DpopConstants.MANDATORY_HEADER_CLAIMS)) {
            throw new DpopValidationException("Missing mandatory JWS header claims");
        }
        if (!jwtClaims.getClaims().keySet().containsAll(DpopConstants.MANDATORY_PAYLOAD_CLAIMS)) {
            throw new DpopValidationException("Missing mandatory JWT payload claims");
        }
    }

    /**
     * Validates that the 'typ' header is set to 'dpop+jwt'.
     *
     * @param header the JWS header
     * @throws DpopValidationException if the 'typ' header is missing or incorrect
     */
    public static void validateTyp(JWSHeader header) {
        if (header.getType() == null || !DpopConstants.DPOP_JWT_HEADER_TYP.equals(header.getType().toString())) {
            throw new DpopValidationException("DPoP typ MUST be " + DpopConstants.DPOP_JWT_HEADER_TYP);
        }
    }

    /**
     * Validates that the algorithm used in the header is supported.
     *
     * @param header              the JWS header
     * @param supportedAlgorithms list of supported algorithm names
     * @throws DpopValidationException if the algorithm is not supported
     */
    public static void validateAlgorithm(JWSHeader header, List<String> supportedAlgorithms) {
        if (!supportedAlgorithms.contains(header.getAlgorithm().getName())) {
            throw new DpopValidationException("DPoP alg MUST be one of " + String.join(",", supportedAlgorithms));
        }
    }

    /**
     * Validates the signature of the DPoP JWT using the provided public JWK.
     *
     * @param dpopJwt the signed DPoP JWT
     * @param key     the public JWK from the JWT header
     * @throws JOSEException            if signature verification fails due to cryptographic error
     * @throws DpopValidationException  if the signature is invalid
     */
    public static void validateSignature(SignedJWT dpopJwt, JWK key) throws JOSEException {
        if (!dpopJwt.verify(new ECDSAVerifier(key.toECKey()))) {
            throw new DpopValidationException("DPoP signature is invalid");
        }
    }

    /**
     * Validates that the provided JWK is a public key (not private).
     *
     * @param key the JWK to check
     * @throws DpopValidationException if the key is private
     */
    public static void validatePublicKeyNotPrivate(JWK key) {
        if (key.isPrivate()) {
            throw new DpopValidationException("Key provided in DPoP MUST NOT be private!");
        }
    }

    /**
     * Validates that the HTTP method ('htm' claim) matches the request method.
     *
     * @param requestMethod the HTTP method of the request
     * @param jwtClaims     the JWT claims set
     * @throws ParseException           if the claim cannot be parsed
     * @throws DpopValidationException  if the method does not match
     */
    public static void validateHtm(String requestMethod, JWTClaimsSet jwtClaims) throws ParseException {
        String htm = jwtClaims.getStringClaim("htm");
        if (!requestMethod.equalsIgnoreCase(htm)) {
            throw new DpopValidationException("HTTP method mismatch between DPoP and request");
        }
    }

    /**
     * Validates that the HTTP URI ('htu' claim) matches the request URI.
     *
     * @param requestUri   the URI of the incoming request
     * @param htu          the 'htu' claim from the JWT
     * @param externalUri  the external URI to compare against
     * @throws URISyntaxException       if URI parsing fails
     * @throws DpopValidationException if the URIs do not match
     */
    public static void validateHtu(URI requestUri, String htu, URI externalUri) throws URISyntaxException {
        if (htu == null) {
            throw new DpopValidationException("Missing htu claim");
        }
        
        String requestSuffix = StringUtils.difference(externalUri.getPath(), requestUri.getPath());
        URI htuUri = new URI(htu).normalize();
        URI baseUri = new URI(requestUri.getScheme(),
                requestUri.getUserInfo(),
                externalUri.getHost(),
                externalUri.getPort(),
                Paths.get(externalUri.getPath(), requestSuffix).toString(),
                null, null).normalize();
        


        if (!baseUri.equals(htuUri)) {
            throw new DpopValidationException("URL mismatch between DPoP and request");
        }
    }

    /**
     * Validates that the issued-at ('iat') claim is within an acceptable time window.
     *
     * @param jwtClaims               the JWT claims set
     * @param acceptableWindowSeconds the allowed window in seconds
     * @param clock                   the clock to use for current time
     * @throws DpopValidationException if the issued-at time is outside the acceptable window
     */
    public static void validateIssuedAt(JWTClaimsSet jwtClaims, int acceptableWindowSeconds, Clock clock) {
        Instant issuedAt = jwtClaims.getIssueTime().toInstant();
        Instant upperBound = clock.instant().plusSeconds(acceptableWindowSeconds);
        Instant lowerBound = clock.instant().minusSeconds(acceptableWindowSeconds);
        if (issuedAt.isBefore(lowerBound) || issuedAt.isAfter(upperBound)) {
            throw new DpopValidationException("Issue time is not in an acceptable window; +/-" + acceptableWindowSeconds);
        }
    }
}
