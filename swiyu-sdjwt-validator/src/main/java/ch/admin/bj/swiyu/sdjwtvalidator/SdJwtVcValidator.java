package ch.admin.bj.swiyu.sdjwtvalidator;

import ch.admin.bj.swiyu.jwtvalidator.DidJwtValidator;
import ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException;
import ch.admin.eid.did_sidekicks.DidDoc;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.*;

/**
 * Validates SD-JWT VC tokens according to the Swiss Profile VC specification (RFC 9901).
 *
 * <p>Extends the base DID-based JWT validation provided by {@link DidJwtValidator} with
 * SD-JWT VC specific rules mandated by the Swiss Profile:</p>
 * <ul>
 *   <li>{@code typ} JOSE header must be {@code dc+sd-jwt} (configurable for migration phase)</li>
 *   <li>{@code _sd_alg} claim must be {@code sha-256}</li>
 *   <li>Registered claims ({@code iss}, {@code nbf}, {@code exp}, {@code iat}, {@code cnf},
 *       {@code vct}, {@code vct#integrity}, {@code status}, {@code vct_metadata_uri},
 *       {@code vct_metadata_uri#integrity}, {@code _sd}, {@code _sd_alg})
 *       MUST NOT appear as selectively disclosed claims (RFC 9901 §3.2.2.2)</li>
 * </ul>
 *
 * <p><strong>Typical usage – Flow B (two-step, no internal HTTP calls):</strong></p>
 * <pre>{@code
 * // Step 1: get the DID resolution URL, caller performs the HTTP GET
 * String didUrl = validator.getAndValidateResolutionUrl(sdJwt);
 *
 * // Step 2: validate with the fetched DID Document
 * boolean valid = validator.validateSdJwtVc(sdJwt, didDocument);
 * }</pre>
 *
 * <p><strong>Migration phase (accepting both {@code dc+sd-jwt} and {@code vc+sd-jwt}):</strong></p>
 * <pre>{@code
 * new SdJwtVcValidator(didJwtValidator,
 *     Set.of(SdJwtVcValidator.TYP_DC_SD_JWT, SdJwtVcValidator.TYP_VC_SD_JWT));
 * }</pre>
 *
 * <p>This class is framework-agnostic and has no Spring dependencies.</p>
 */
@Slf4j
public class SdJwtVcValidator {

    /** {@code typ} value required by SD-JWT VC spec (post-migration). */
    public static final String TYP_DC_SD_JWT = "dc+sd-jwt";

    /** {@code typ} value accepted during the migration phase alongside {@link #TYP_DC_SD_JWT}. */
    public static final String TYP_VC_SD_JWT = "vc+sd-jwt";

    private static final String SD_ALG_CLAIM = "_sd_alg";

    private static final int OBJECT_PROPERTY_DISCLOSURES_SIZE = 3;
    
    /**
     * Registered JWT claims that MUST NOT appear in any Disclosure per RFC 9901 4.1 and 7
     * and the Swiss Profile VC specification.
     */
    public static final Set<String> PROTECTED_CLAIMS = Set.of(
            "iss",
            "nbf", 
            "exp", 
            "iat", 
            "cnf",
            "vct", 
            "vct#integrity",
            "status",
            "vct_metadata_uri", 
            "vct_metadata_uri#integrity",
            "_sd",
            "...",
            "sd_hash",
            SD_ALG_CLAIM
    );

    
    private static final String REQUIRED_HASH_ALGORITHM = "sha-256";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final DidJwtValidator didJwtValidator;
    private final Set<String> acceptedTypValues;

    /**
     * Creates an {@code SdJwtVcValidator} that accepts only {@code dc+sd-jwt} as {@code typ}.
     *
     * @param didJwtValidator the underlying DID-based JWT validator; must not be {@code null}
     */
    public SdJwtVcValidator(DidJwtValidator didJwtValidator) {
        this(didJwtValidator, Set.of(TYP_DC_SD_JWT));
    }

    /**
     * Creates an {@code SdJwtVcValidator} with a configurable set of accepted {@code typ} values.
     *
     * <p>Use this constructor during the migration phase to accept both
     * {@code dc+sd-jwt} and {@code vc+sd-jwt}.</p>
     *
     * @param didJwtValidator   the underlying DID-based JWT validator; must not be {@code null}
     * @param acceptedTypValues the set of accepted {@code typ} header values; must not be empty
     */
    public SdJwtVcValidator(DidJwtValidator didJwtValidator, Set<String> acceptedTypValues) {
        if (didJwtValidator == null) throw new IllegalArgumentException("didJwtValidator must not be null");
        if (acceptedTypValues == null || acceptedTypValues.isEmpty())
            throw new IllegalArgumentException("acceptedTypValues must not be null or empty");
        this.didJwtValidator = didJwtValidator;
        this.acceptedTypValues = Set.copyOf(acceptedTypValues);
    }

    /**
     * Step 1 of Flow B – validates the {@code typ} header and returns the DID resolution URL.
     *
     * <p>The caller is expected to perform the HTTP GET to the returned URL to fetch the
     * DID Document, and then call {@link #validateSdJwtVc(String, DidDoc)}.</p>
     *
     * @param sdJwt the SD-JWT string ({@code <issuer-jwt>~[<disclosure>~]*})
     * @return the validated DID resolution URL for the caller to fetch
     * @throws JwtValidatorException if the {@code typ} is invalid or DID resolution fails
     */
    public String getAndValidateResolutionUrl(String sdJwt) {
        String issuerJwt = SdJwtParser.extractIssuerSignedJwt(sdJwt);
        try {
            validateTypHeader(SignedJWT.parse(issuerJwt));
        } catch (ParseException e) {
            throw new JwtValidatorException("Failed to parse Issuer-Signed JWT", e);
        }
        return didJwtValidator.getAndValidateResolutionUrl(issuerJwt);
    }

    /**
     * Step 2 of Flow B – validates the full SD-JWT VC against the pre-fetched DID Document.
     *
     * <p>Checks performed in order:</p>
     * <ol>
     *   <li>{@code typ} header is in the configured set of accepted values</li>
     *   <li>{@code _sd_alg} claim equals {@code sha-256}</li>
     *   <li>No registered/protected claim appears in any Disclosure</li>
     *   <li>DID-based signature verification (delegated to {@link DidJwtValidator})</li>
     * </ol>
     *
     * @param sdJwt       the SD-JWT string
     * @param didDocument the pre-fetched DID Document for signature verification
     * @throws JwtValidatorException if any check fails
     */
    public void validateSdJwtVc(String sdJwt, DidDoc didDocument) {
        String issuerJwt = validateStructure(sdJwt);
        didJwtValidator.validateJwt(issuerJwt, didDocument);
    }

    /**
     * Flow A – validates the SD-JWT VC directly against the provided JWK set.
     *
     * <p>Use this when the JWK set is already available and no DID resolution is needed.
     * Same structural checks ({@code typ}, {@code _sd_alg}, protected claims) are applied.</p>
     *
     * @param sdJwt  the SD-JWT string
     * @param jwkSet the JWK set containing the public key(s) to verify against
     * @throws JwtValidatorException if any check fails
     */
    public void validateSdJwtVc(String sdJwt, JWKSet jwkSet) {
        String issuerJwt = validateStructure(sdJwt);
        didJwtValidator.validateJwt(issuerJwt, jwkSet);
    }

    // -------------------------------------------------------------------------
    // Private validation helpers
    // -------------------------------------------------------------------------

    /**
     * Runs all structural SD-JWT VC checks ({@code typ}, {@code _sd_alg}, protected claims, disclosure hashes)
     * and returns the extracted Issuer-Signed JWT for subsequent signature verification.
     *
     * @param sdJwt the full SD-JWT string
     * @return the Issuer-Signed JWT portion
     * @throws JwtValidatorException if any structural check fails
     */
    private String validateStructure(String sdJwt) {
        String issuerJwt = SdJwtParser.extractIssuerSignedJwt(sdJwt);
        try {
            SignedJWT signedJwt = SignedJWT.parse(issuerJwt);
            validateTypHeader(signedJwt);
            validateSdAlg(signedJwt);
            validateNoProtectedClaimsInDisclosures(sdJwt);
            validateDisclosureHashes(sdJwt, signedJwt);
        } catch (ParseException e) {
            throw new JwtValidatorException("Failed to parse Issuer-Signed JWT", e);
        }
        return issuerJwt;
    }

    /**
     * Validates the {@code typ} JOSE header against the configured accepted values.
     *
     * @param signedJwt the parsed Issuer-Signed JWT
     * @throws JwtValidatorException if the {@code typ} is absent or not accepted
     */
    private void validateTypHeader(SignedJWT signedJwt) {
        JOSEObjectType type = signedJwt.getHeader().getType();
        if (type == null) {
            throw new JwtValidatorException(
                    "SD-JWT VC is missing the 'typ' JOSE header (must be '" + TYP_DC_SD_JWT + "')");
        }
        if (!acceptedTypValues.contains(type.getType())) {
            throw new JwtValidatorException(
                    "SD-JWT VC 'typ' is '" + type.getType() + "', expected one of: " + acceptedTypValues);
        }
        log.debug("SD-JWT VC typ '{}' accepted", type.getType());
    }

    /**
     * Validates that the {@code _sd_alg} claim is present and equals {@code sha-256}.
     *
     * @param signedJwt the parsed Issuer-Signed JWT
     * @throws JwtValidatorException if the claim is absent or has an unexpected value
     */
    private void validateSdAlg(SignedJWT signedJwt) throws ParseException {
        Object sdAlg = signedJwt.getJWTClaimsSet().getClaim(SD_ALG_CLAIM);
        if (sdAlg == null) {
            throw new JwtValidatorException(
                    "SD-JWT VC is missing the '_sd_alg' claim (must be '" + REQUIRED_HASH_ALGORITHM + "')");
        }
        if (!REQUIRED_HASH_ALGORITHM.equals(sdAlg.toString())) {
            throw new JwtValidatorException(
                    "'_sd_alg' must be '" + REQUIRED_HASH_ALGORITHM + "', but was: '" + sdAlg + "'");
        }
        log.debug("SD-JWT VC _sd_alg '{}' accepted", sdAlg);
    }

    /**
     * Validates that none of the {@link #PROTECTED_CLAIMS} appear as the claim name
     * (index 1) in any Disclosure array {@code [salt, claim_name, claim_value]}.
     *
     * @param sdJwt the full SD-JWT string including all Disclosures
     * @throws JwtValidatorException if any Disclosure contains a protected claim name
     */
    private void validateNoProtectedClaimsInDisclosures(String sdJwt) {
        List<String> disclosures = SdJwtParser.extractDisclosures(sdJwt);
        for (String disclosure : disclosures) {
            validateSingleDisclosure(disclosure);
        }
        log.debug("All {} Disclosure(s) passed protected-claim check", disclosures.size());
    }

    /**
     * Parses and validates a single base64url-encoded Disclosure.
     *
     * @param disclosure the base64url-encoded Disclosure
     * @throws JwtValidatorException if the Disclosure is malformed or contains a protected claim
     */
    private void validateSingleDisclosure(String disclosure) {
        String decoded = SdJwtParser.decodeDisclosure(disclosure);
        try {
            JsonNode array = OBJECT_MAPPER.readTree(decoded);
            validateDisclosureStructure(array, decoded);
            validateDisclosureClaimName(array);
        } catch (JsonProcessingException e) {
            throw new JwtValidatorException("Failed to parse Disclosure: " + decoded, e);
        }
    }

    /**
     * Validates that the decoded Disclosure is a JSON array with exactly 2 or 3 elements.
     *
     * <p>RFC 9901 §5.2 defines two Disclosure types:</p>
     * <ul>
     *   <li>Object Property: {@code [salt, claim_name, claim_value]} (size 3)</li>
     *   <li>Array Element:   {@code [salt, claim_value]}             (size 2)</li>
     * </ul>
     *
     * @param array   the parsed JSON node
     * @param decoded the decoded string (for error messages)
     * @throws JwtValidatorException if the structure is invalid
     */
    private void validateDisclosureStructure(JsonNode array, String decoded) {
        if (!array.isArray() || (array.size() != 2 && array.size() != OBJECT_PROPERTY_DISCLOSURES_SIZE)) {
            throw new JwtValidatorException(
                    "Invalid Disclosure format: expected JSON array with 2 or 3 elements, got: " + decoded);
        }
    }

    /**
     * Validates that an Object Property Disclosure does not carry a protected claim name.
     *
     * <p>Array Element Disclosures (size 2) pass implicitly – their array name is embedded
     * in the Issuer-Signed JWT, not in the Disclosure itself.</p>
     *
     * @param array the parsed Disclosure JSON array
     * @throws JwtValidatorException if the claim name is a protected claim
     */
    private void validateDisclosureClaimName(JsonNode array) {
        if (array.size() == OBJECT_PROPERTY_DISCLOSURES_SIZE) {
            String claimName = array.get(1).asText();
            if (PROTECTED_CLAIMS.contains(claimName)) {
                throw new JwtValidatorException(
                        "Registered claim '" + claimName +
                        "' MUST NOT be selectively disclosed (RFC 9901 §3.2.2.2 / Swiss Profile)");
            }
        }
    }

    /**
     * Validates that all disclosure hashes match the signed hashes in the {@code _sd} claim.
     *
     * @param sdJwt     the full SD-JWT string containing all disclosures
     * @param signedJwt the parsed Issuer-Signed JWT containing the {@code _sd} claim
     * @throws JwtValidatorException if any disclosure hash does not match a signed hash
     */
    private void validateDisclosureHashes(String sdJwt, SignedJWT signedJwt) throws ParseException {
        List<String> disclosures = SdJwtParser.extractDisclosures(sdJwt);
        if (disclosures.isEmpty()) {
            log.debug("No disclosures to validate");
            return;
        }

        // Extract the _sd claim array from the signed JWT
        Set<String> signedHashes = extractSignedHashes(signedJwt);
        if (signedHashes.isEmpty()) {
            throw new JwtValidatorException(
                    "SD-JWT contains " + disclosures.size() + " disclosure(s) but the '_sd' claim is missing or empty");
        }

        // Compute hash for each disclosure and verify it exists in the signed hashes
        for (String disclosure : disclosures) {
            String computedHash = computeDisclosureHash(disclosure);
            if (!signedHashes.contains(computedHash)) {
                throw new JwtValidatorException(
                        "Disclosure hash verification failed: computed hash '" + computedHash +
                        "' is not present in the '_sd' claim. This indicates the disclosure has been tampered with.");
            }
        }

        log.debug("All {} disclosure hash(es) successfully verified against '_sd' claim", disclosures.size());
    }

    /**
     * Extracts all hashes from the {@code _sd} claim in the JWT.
     * The {@code _sd} claim can appear at the top level or nested within objects.
     *
     * @param signedJwt the parsed Issuer-Signed JWT
     * @return a set of base64url-encoded hash strings
     * @throws ParseException if the JWT claims cannot be parsed
     */
    private Set<String> extractSignedHashes(SignedJWT signedJwt) throws ParseException {
        Set<String> hashes = new HashSet<>();
        Object sdClaim = signedJwt.getJWTClaimsSet().getClaim("_sd");

        if (sdClaim instanceof List<?> sdList) {
            for (Object item : sdList) {
                if (item instanceof String hash) {
                    hashes.add(hash);
                }
            }
        }

        // Also recursively extract _sd from nested objects in the claims
        extractNestedSdHashes(signedJwt.getJWTClaimsSet().getClaims(), hashes);

        return hashes;
    }

    /**
     * Recursively extracts {@code _sd} arrays from nested objects in the JWT claims.
     *
     * @param claims the claims map to search
     * @param hashes the set to populate with found hashes
     */
    private void extractNestedSdHashes(Map<String, Object> claims, Set<String> hashes) {
        // Delegation an die generische Hilfsmethode
        traverseForSdHashes(claims, hashes);
    }

    private void traverseForSdHashes(Object node, Set<String> hashes) {
        if (node instanceof Map<?, ?> map) {
            // 1. collect _sd Hashes
            if (map.get("_sd") instanceof List<?> sdList) {
                for (Object item : sdList) {
                    if (item instanceof String hash) {
                        hashes.add(hash);
                    }
                }
            }
            // 2. Recursion
            for (Object value : map.values()) {
                traverseForSdHashes(value, hashes);
            }

        } else if (node instanceof Iterable<?> iterable) {
            for (Object item : iterable) {
                traverseForSdHashes(item, hashes);
            }
        }
    }


    /**
     * Computes the SHA-256 hash of a disclosure and returns it as a base64url-encoded string.
     *
     * <p>According to RFC 9901, the hash is computed over the base64url-encoded disclosure string,
     * including any padding characters (though base64url typically omits padding).</p>
     *
     * @param disclosure the base64url-encoded disclosure string
     * @return the base64url-encoded SHA-256 hash
     * @throws JwtValidatorException if SHA-256 is not available (should never happen)
     */
    private String computeDisclosureHash(String disclosure) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(disclosure.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new JwtValidatorException("SHA-256 algorithm not available", e);
        }
    }
}

