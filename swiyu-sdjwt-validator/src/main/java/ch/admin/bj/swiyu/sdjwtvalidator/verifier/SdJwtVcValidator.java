package ch.admin.bj.swiyu.sdjwtvalidator.verifier;

import ch.admin.bj.swiyu.jwtutil.JwtUtil;
import ch.admin.bj.swiyu.jwtutil.JwtUtilException;
import ch.admin.bj.swiyu.jwtvalidator.DidJwtValidator;
import ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException;
import ch.admin.bj.swiyu.sdjwtvalidator.SdJwtConstants;
import ch.admin.bj.swiyu.sdjwtvalidator.exception.SdJwtVerificationException;

import com.authlete.sd.Disclosure;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;

import lombok.extern.slf4j.Slf4j;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

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

    private static final String SD_ALG_CLAIM = "_sd_alg";
    private static final String REQUIRED_HASH_ALGORITHM = "sha-256";

    private final DidJwtValidator didJwtValidator;

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    /**
     * Creates an {@code SdJwtVcValidator} that accepts only {@code dc+sd-jwt} as {@code typ}.
     *
     * @param didJwtValidator the underlying DID-based JWT validator; must not be {@code null}
     */
    public SdJwtVcValidator(DidJwtValidator didJwtValidator) {
        this.didJwtValidator = didJwtValidator;
    }

    /**
     * Validates the header to conform to swiss-profile 1.0 requirements. 
     * Makes the header available in the provided {@link SdJwt} object
     * @param sdJwt The sdJwt which will be verified and altered
     * @throws SdJwtVerificationException if the verification failed
     */
    public void validateHeader(SdJwt sdJwt) throws SdJwtVerificationException {
        JWSHeader header = sdJwt.getJwt().getHeader();

        if (header.getKeyID() == null || header.getKeyID().isBlank()) {
            throw new SdJwtVerificationException("Missing header attribute 'kid' for the issuer's Key Id in the JWT token");
        }
        sdJwt.setHeader(header);
    }


    /**
     * Validates the signature of the JWT, ensuring the key is hosted on an acceptable registry
     * @param sdJwt
     * @param issuerJWK
     * @throws SdJwtVerificationException
     */
    public void validateJwt(SdJwt sdJwt, JWK issuerJWK) throws SdJwtVerificationException {
        try {
            didJwtValidator.validateJwt(sdJwt.getSerializedJWT(), issuerJWK);
            sdJwt.setClaims(sdJwt.getJwt().getJWTClaimsSet());
        } catch (ParseException | JwtValidatorException e) {
            throw new SdJwtVerificationException("SD-JWT claims are not valid", e);
        }
    }

    /**
     * Validates the Key Binding JWT of the SD-JWT, ensuring that it is fresh 
     * and intended the correct audience accoding to RFC 9901 7.3 Key Binding Verification
     * This function should only be called if a key binding proof is required.
     * @param sdJwt the full validated SD-JWT
     * @param audience the audience (SD-JWT Verifier) for which the Key Binding should be issued
     * @param nonce the nonce which should be included in the Key Binding
     * @param acceptableKeyBindingWindow the acceptable window in seconds for the key binding, ensuring its freshness
     * @throws SdJwtVerificationException if no Key Binding is found or the key binding is not valid
     */
    public void validateKeyBinding(SdJwt sdJwt, String audience, String nonce, int acceptableKeyBindingWindow) throws SdJwtVerificationException {
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
     * 
     * @param proofIssueTime Instant when the Key Binding JWT was issued
     * @param acceptableKeyBindingWindow time window which is acceptable for the issue time, allowing for some clock skew and delays
     * @throws SdJwtVerificationException if the issue time verification was not successful
     */
    private void validateKeyBindingJWTCreationTime(Instant proofIssueTime, int acceptableKeyBindingWindow)
            throws ParseException, SdJwtVerificationException {

        Instant now = Instant.now();
        // iat not within acceptable proof time window
        if (proofIssueTime.isBefore(now.minusSeconds(acceptableKeyBindingWindow))
                || proofIssueTime.isAfter(now.plusSeconds(acceptableKeyBindingWindow))) {
            throw new SdJwtVerificationException(String.format("Key Binding proof is not recent enough. iat must be within +/- %d seconds of %d", acceptableKeyBindingWindow, now.getEpochSecond()));
        }
    }

    /**
     * Extract the key binding from the sd jwt
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
    public void validateTimeClaims(String jwtString) {
        try {
            SignedJWT jwt = SignedJWT.parse(jwtString);
            DefaultJWTClaimsVerifier<SecurityContext> verifier = new DefaultJWTClaimsVerifier<>(
                    null,                  // no required audience
                    new JWTClaimsSet.Builder().build(), // no exact match required
                    Set.of(),              // no required claims (exp/nbf checked if present)
                    Set.of()               // no prohibited claims – iss is ignored, not forbidden
            );
            verifier.setMaxClockSkew(60);
            verifier.verify(jwt.getJWTClaimsSet(), null);
            log.debug("JWT time claims (exp/nbf) verified successfully");
        } catch (ParseException e) {
            throw new JwtValidatorException("Failed to parse JWT for claims verification", e);
        } catch (BadJOSEException e) {
            throw new JwtValidatorException("JWT time claim validation failed: " + e.getMessage(), e);
        }
    }


    /**
     * Processes disclosures for the verification case according to RFC 9901 7.1
     * @param sdJwt the sd-jwt to be processed
     * @return the claims resolved and processed accordingto RFC 9901 as JSON
     * @throws SdJwtVerificationException if the sd-jwt did not pass verification and MUST be rejected
     */
    public Map<String, Object> processDisclosures(SdJwt sdJwt) throws SdJwtVerificationException {
        try {
            JsonNode claims = OBJECT_MAPPER.convertValue(sdJwt.getClaims().toJSONObject(), JsonNode.class);
            // 3.1 - For each Disclosure provided Calculate the digest over the base64url-encoded string
            // Reject immediately if the same disclosure appears more than once (identical digest)
            Map<String, Disclosure> digestToDisclosure = sdJwt.getDisclosures().stream().collect(
                Collectors.toMap(
                        Disclosure::digest,
                        Function.identity(),
                        (existing, duplicate) -> {
                            throw new IllegalArgumentException("Request contains non-distinct disclosures");
                        }
                ));
            
            List<String> usedDigests = new LinkedList<>();

            JsonNode processed = processNode(claims, digestToDisclosure, usedDigests);

            // 3.e Remove _sd keys
            removeSdKeys(processed);

            // 3.f Check if correct _sd_alg-value Remove _sd_alg
            processSdAlg(processed);


            // 5. If any Disclosure was not referenced by digest value in the Issuer-signed JWT (directly or recursively via other Disclosures), the SD-JWT MUST be rejected.
            if (usedDigests.size() != digestToDisclosure.size()) {
                throw new SdJwtVerificationException("Unused disclosures detected");
            }
            // 6. Checking nbf / exp here is not necessary anymore, as it was done before and these claims cannot be overridden.

            sdJwt.setResolvedClaims(OBJECT_MAPPER.convertValue(processed, new TypeReference<Map<String, Object>>(){}));
            return sdJwt.getResolvedClaims();
        } catch (IllegalArgumentException e) {
            throw new SdJwtVerificationException(e);
        }
    }

    private void processSdAlg(JsonNode processed) throws SdJwtVerificationException {
        if (processed.hasNonNull(SD_ALG_CLAIM) && !REQUIRED_HASH_ALGORITHM.contains(processed.get(SD_ALG_CLAIM).asString())) {
            throw new SdJwtVerificationException("Unsupported _sd_alg value: %s".formatted(processed.get(SD_ALG_CLAIM).asString()));
        }
        ((ObjectNode) processed).remove(SD_ALG_CLAIM);
    }

    
    /**
     * Processes a JSON node recursively, handling both object and array nodes according to RFC 9901 SD-JWT specifications.
     *
     * @param node The JSON node to process.
     * @param digestMap A map of digests to their corresponding disclosures.
     * @param usedDigests A list to track digests that have already been processed.
     * @return The processed JSON node.
     * @throws SdJwtVerificationException If an error occurs during processing.
     */
    private JsonNode processNode(JsonNode node,
                                 Map<String, Disclosure> digestMap,
                                 List<String> usedDigests) throws SdJwtVerificationException {
        if (node.isObject()) {
            return processObjectNode((ObjectNode) node, digestMap, usedDigests);
        }

        if (node.isArray()) {
            return processArrayNode((ArrayNode) node, digestMap, usedDigests);
        }

        return node;
    }

    /**
     * Processes an object node, handling selective disclosures if the SdJwtConstants.SD_CLAIM key is present.
     *
     * @param object The object node to process.
     * @param digestMap A map of digests to their corresponding disclosures.
     * @param usedDigests A list to track digests that have already been processed.
     * @return The processed object node.
     * @throws SdJwtVerificationException If an error occurs during processing.
     */
    private JsonNode processObjectNode(ObjectNode object,
                                       Map<String, Disclosure> digestMap,
                                       List<String> usedDigests) throws SdJwtVerificationException {
        // if no _sd key present, just recurse into fields
        if (!object.has(SdJwtConstants.SD_CLAIM)) {
            Iterator<String> fields = object.propertyNames().iterator();
            List<String> names = new ArrayList<>();
            fields.forEachRemaining(names::add);
            for (String name : names) {
                object.set(name, processNode(object.get(name), digestMap, usedDigests));
            }
            return object;
        }

        // object has _sd -> process disclosures first
        JsonNode sdNode = object.get(SdJwtConstants.SD_CLAIM);
        if (!(sdNode instanceof ArrayNode sdArray)) {
            throw new SdJwtVerificationException("'_sd' claim must be a JSON array");
        }

        // snapshot original fields to avoid processing newly added fields
        List<String> originalFields = new ArrayList<>();
        object.propertyNames().iterator().forEachRemaining(originalFields::add);

        handleSdArray(object, sdArray, digestMap, usedDigests);

        // iterate only the original fields (skip _sd) and recurse
        for (String field : originalFields) {
            if (SdJwtConstants.SD_CLAIM.equals(field)) continue;
            object.set(field, processNode(object.get(field), digestMap, usedDigests));
        }

        return object;
    }

    /**
     * Handles the array of digests in the SdJwtConstants.SD_CLAIM key, applying disclosures to the object node.
     *
     * @param object The object node to update with disclosures.
     * @param sdArray The array node containing digests.
     * @param digestMap A map of digests to their corresponding disclosures.
     * @param usedDigests A list to track digests that have already been processed.
     * @throws SdJwtVerificationException If an error occurs during processing.
     */
    private void handleSdArray(ObjectNode object,
                               ArrayNode sdArray,
                               Map<String, Disclosure> digestMap,
                               List<String> usedDigests) throws SdJwtVerificationException {
        for (JsonNode digestNode : sdArray) {
            String digest = digestNode.asString();

            if (!digestMap.containsKey(digest)) continue;

            usedDigests.add(digest);
            var disclosure = digestMap.get(digest);
            var claimName = disclosure.getClaimName();

            // 3.2.1 If the contents of the respective Disclosure is not a JSON array of three elements (salt, claim name, claim value), the SD-JWT MUST be rejected.
            if (claimName == null || disclosure.getClaimValue() == null || disclosure.getSalt() == null) {
                throw new SdJwtVerificationException("Illegal disclosure found");
            }

            // 3.2. If the claim name is _sd or ..., the SD-JWT MUST be rejected.
            if (claimName.equals(SdJwtConstants.SD_CLAIM) || claimName.equals(SdJwtConstants.SD_ARRAY_CLAIM)) {
                throw new SdJwtVerificationException("Illegal disclosure found with name _sd or ...");
            }

            // 3.3.  If the claim name already exists at the level of the _sd key, the SD-JWT MUST be rejected
            if (object.has(claimName)) {
                throw new SdJwtVerificationException("Claim name already exists at the level of the _sd key");
            }

            var claimValue = OBJECT_MAPPER.convertValue(disclosure.getClaimValue(), JsonNode.class);
            object.set(claimName, processNode(claimValue, digestMap, usedDigests));
        }
    }

    /**
     * Processes an array node, handling selective disclosures for elements marked with SdJwtConstants.SD_ARRAY_CLAIM.
     *
     * @param array The array node to process.
     * @param digestMap A map of digests to their corresponding disclosures.
     * @param usedDigests A list to track digests that have already been processed.
     * @return The processed array node.
     * @throws SdJwtVerificationException If an error occurs during processing.
     */
    private JsonNode processArrayNode(ArrayNode array,
                                      Map<String, Disclosure> digestMap,
                                      List<String> usedDigests) throws SdJwtVerificationException {
        ArrayNode newArray = OBJECT_MAPPER.createArrayNode();

        for (JsonNode element : array) {
            if (element.isObject() && element.has(SdJwtConstants.SD_ARRAY_CLAIM)) {
                String digest = element.get(SdJwtConstants.SD_ARRAY_CLAIM).asString();

                JsonNode value;

                if (digestMap.containsKey(digest)) {
                    usedDigests.add(digest);
                    var disclosure = digestMap.get(digest);

                    if (disclosure.getClaimName() != null || disclosure.getClaimValue() == null || disclosure.getSalt() == null) {
                        throw new SdJwtVerificationException("Illegal non-array disclosure found");
                    }

                    value = OBJECT_MAPPER.convertValue(disclosure.getClaimValue(), JsonNode.class);
                } else {
                    // if value is not requested, add digest to array otherwise index access won't work
                    value = OBJECT_MAPPER.convertValue(digest, JsonNode.class);
                }


                newArray.add(processNode(value, digestMap, usedDigests));
            } else {
                newArray.add(processNode(element, digestMap, usedDigests));
            }
        }

        return newArray;
    }

    /**
     * Recursively removes all SdJwtConstants.SD_CLAIM keys from the JSON node.
     *
     * @param node The JSON node to process.
     */
    private void removeSdKeys(JsonNode node) {
        if (node.isObject()) {
            ObjectNode obj = (ObjectNode) node;
            obj.remove(SdJwtConstants.SD_CLAIM);

            for (String string : obj.propertyNames()) {
                removeSdKeys(obj.get(string));
            }
        } else if (node.isArray()) {
            for (JsonNode n : node) {
                removeSdKeys(n);
            }
        }
    }
}

