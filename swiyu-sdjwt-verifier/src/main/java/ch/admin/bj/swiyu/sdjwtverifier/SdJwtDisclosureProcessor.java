package ch.admin.bj.swiyu.sdjwtverifier;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import com.authlete.sd.Disclosure;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import ch.admin.bj.swiyu.sdjwtutil.SdJwtConstants;
import ch.admin.bj.swiyu.sdjwtverifier.exception.SdJwtVerificationException;

/**
 * Resolves the claims of an SD-JWT by applying its disclosures according to RFC 9901 §7.1.
 *
 * <p>This class is framework-agnostic and has no Spring dependencies.</p>
 */
class SdJwtDisclosureProcessor {

    private static final String REQUIRED_HASH_ALGORITHM = "sha-256";

    private final SdJwtNodeProcessor nodeProcessor;

    SdJwtDisclosureProcessor() {
        this.nodeProcessor = new SdJwtNodeProcessor();
    }

    /**
     * Processes disclosures for the verification case according to RFC 9901 7.1
     *
     * @param sdJwt the sd-jwt to be processed
     * @return the claims resolved and processed according to RFC 9901 as JSON
     * @throws SdJwtVerificationException if the sd-jwt did not pass verification and MUST be rejected
     */
    Map<String, Object> process(SdJwt sdJwt) throws SdJwtVerificationException {
        try {
            JsonNode claims = SdJwtObjectMapper.INSTANCE.convertValue(sdJwt.getClaims().toJSONObject(), JsonNode.class);
            // 3.a - For each Disclosure provided Calculate the digest over the base64url-encoded string
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

            JsonNode processed = nodeProcessor.processNode(claims, digestToDisclosure, usedDigests);

            // 3.e Remove _sd keys
            nodeProcessor.removeSdKeys(processed);

            // 3.f Check if correct _sd_alg-value Remove _sd_alg
            validateAndRemoveSdAlg(processed);

            // 5. If any Disclosure was not referenced by digest value in the Issuer-signed JWT (directly or recursively via other Disclosures), the SD-JWT MUST be rejected.
            if (usedDigests.size() != digestToDisclosure.size()) {
                throw new SdJwtVerificationException("Unused disclosures detected");
            }
            // 6. Checking nbf / exp here is not necessary anymore, as it was done before and these claims cannot be overridden.

            sdJwt.setResolvedClaims(SdJwtObjectMapper.INSTANCE.convertValue(processed, new TypeReference<Map<String, Object>>(){}));
            return sdJwt.getResolvedClaims();
        } catch (IllegalArgumentException e) {
            throw new SdJwtVerificationException(e);
        }
    }

    private void validateAndRemoveSdAlg(JsonNode processed) throws SdJwtVerificationException {
        if (processed.hasNonNull(SdJwtConstants.SD_ALG_CLAIM) && !REQUIRED_HASH_ALGORITHM.equals(processed.get(SdJwtConstants.SD_ALG_CLAIM).asString())) {
            throw new SdJwtVerificationException("Unsupported _sd_alg value: %s".formatted(processed.get(SdJwtConstants.SD_ALG_CLAIM).asString()));
        }
        ((ObjectNode) processed).remove(SdJwtConstants.SD_ALG_CLAIM);
    }
}
