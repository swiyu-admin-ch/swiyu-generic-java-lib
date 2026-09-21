package ch.admin.bj.swiyu.sdjwtverifier;

import ch.admin.bj.swiyu.sdjwtutil.SdJwtConstants;
import ch.admin.bj.swiyu.sdjwtverifier.exception.SdJwtVerificationException;
import com.authlete.sd.Disclosure;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.*;

/**
 * Recursively resolves selectively disclosed claims within a JSON claim tree according to
 * RFC 9901 §7.1 (object {@code _sd} arrays and array {@code ...} elements).
 *
 * <p>This class is framework-agnostic and has no Spring dependencies.</p>
 */
class SdJwtNodeProcessor {

    /**
     * Processes a JSON node recursively, handling both object and array nodes according to RFC 9901 SD-JWT specifications.
     *
     * @param node The JSON node to process.
     * @param digestMap A map of digests to their corresponding disclosures.
     * @param usedDigests A list to track digests that have already been processed and do have a disclosure. Used if every disclosure was referenced by a digest
     * @param foundDigests A set to track digests that have already been processed. Used to check if digests are reused.
     * @return The processed JSON node.
     * @throws SdJwtVerificationException If an error occurs during processing.
     */
    JsonNode processNode(JsonNode node,
                          Map<String, Disclosure> digestMap,
                          List<String> usedDigests,
                         Set<String> foundDigests) throws SdJwtVerificationException {
        if (node.isObject()) {
            return processObjectNode((ObjectNode) node, digestMap, usedDigests, foundDigests);
        }

        if (node.isArray()) {
            return processArrayNode((ArrayNode) node, digestMap, usedDigests, foundDigests);
        }

        return node;
    }

    /**
     * Recursively removes all SdJwtConstants.SD_CLAIM keys from the JSON node.
     *
     * @param node The JSON node to process.
     */
    void removeSdKeys(JsonNode node) {
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

    /**
     * Processes an object node, handling selective disclosures if the SdJwtConstants.SD_CLAIM key is present.
     *
     * @param object The object node to process.
     * @param digestMap A map of digests to their corresponding disclosures.
     * @param usedDigests A list to track digests that have already been processed and do have a disclosure. Used if every disclosure was referenced by a digest
     * @param foundDigests A set to track digests that have already been processed. Used to check if digests are reused.
     * @return The processed object node.
     * @throws SdJwtVerificationException If an error occurs during processing.
     */
    private JsonNode processObjectNode(ObjectNode object,
                                        Map<String, Disclosure> digestMap,
                                        List<String> usedDigests,
                                        Set<String> foundDigests) throws SdJwtVerificationException {
        // if no _sd key present, just recurse into fields
        if (!object.has(SdJwtConstants.SD_CLAIM)) {
            Iterator<String> fields = object.propertyNames().iterator();
            List<String> names = new ArrayList<>();
            fields.forEachRemaining(names::add);
            for (String name : names) {
                object.set(name, processNode(object.get(name), digestMap, usedDigests, foundDigests));
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

        handleSdArray(object, sdArray, digestMap, usedDigests, foundDigests);

        // iterate only the original fields (skip _sd) and recurse
        for (String field : originalFields) {
            if (SdJwtConstants.SD_CLAIM.equals(field)) continue;
            object.set(field, processNode(object.get(field), digestMap, usedDigests, foundDigests));
        }

        return object;
    }

    /**
     * Handles the array of digests in the SdJwtConstants.SD_CLAIM key, applying disclosures to the object node.
     *
     * @param object The object node to update with disclosures.
     * @param sdArray The array node containing digests.
     * @param digestMap A map of digests to their corresponding disclosures.
     * @param usedDigests A list to track digests that have already been processed and do have a disclosure. Used if every disclosure was referenced by a digest
     * @param foundDigests A set to track digests that have already been processed. Used to check if digests are reused.
     * @throws SdJwtVerificationException If an error occurs during processing.
     */
    private void handleSdArray(ObjectNode object,
                                ArrayNode sdArray,
                                Map<String, Disclosure> digestMap,
                                List<String> usedDigests,
                                Set<String> foundDigests) throws SdJwtVerificationException {
        for (JsonNode digestNode : sdArray) {
            String digest = digestNode.asString();

            // check if digest has already been checked (maybe not used), if so throw exception otherwise add to usedDigests (this covers step 4 of RFC 9901 7.1)
            checkAndUpdateFoundDigest(digest, foundDigests);

            if (!digestMap.containsKey(digest)) continue;

            usedDigests.add(digest);
            var disclosure = digestMap.get(digest);
            var claimName = disclosure.getClaimName();

            // 3.2.1 If the contents of the respective Disclosure is not a JSON array of three elements (salt, claim name, claim value), the SD-JWT MUST be rejected.
            if (claimName == null || disclosure.getClaimValue() == null || disclosure.getSalt() == null) {
                throw new SdJwtVerificationException("Illegal disclosure found");
            }

            // 3.2.2. If the claim name is _sd or ..., the SD-JWT MUST be rejected.
            if (claimName.equals(SdJwtConstants.SD_CLAIM) || claimName.equals(SdJwtConstants.SD_ARRAY_CLAIM)) {
                throw new SdJwtVerificationException("Illegal disclosure found with name _sd or ...");
            }

            // 3.2.3.  If the claim name already exists at the level of the _sd key, the SD-JWT MUST be rejected
            if (object.has(claimName)) {
                throw new SdJwtVerificationException("Claim name already exists at the level of the _sd key");
            }

            var claimValue = SdJwtObjectMapper.INSTANCE.convertValue(disclosure.getClaimValue(), JsonNode.class);
            object.set(claimName, processNode(claimValue, digestMap, usedDigests, foundDigests));
        }
    }

    /**
     * Processes an array node, handling selective disclosures for elements marked with SdJwtConstants.SD_ARRAY_CLAIM.
     *
     * @param array The array node to process.
     * @param digestMap A map of digests to their corresponding disclosures.
     * @param usedDigests A list to track digests that have already been processed and do have a disclosure. Used if every disclosure was referenced by a digest
     * @param foundDigests A set to track digests that have already been processed. Used to check if digests are reused.
     * @return The processed array node.
     * @throws SdJwtVerificationException If an error occurs during processing.
     */
    private JsonNode processArrayNode(ArrayNode array,
                                       Map<String, Disclosure> digestMap,
                                       List<String> usedDigests,
                                       Set<String> foundDigests) throws SdJwtVerificationException {
        ArrayNode newArray = SdJwtObjectMapper.INSTANCE.createArrayNode();

        for (JsonNode element : array) {
            if (element.isObject() && element.has(SdJwtConstants.SD_ARRAY_CLAIM)) {
                String digest = element.get(SdJwtConstants.SD_ARRAY_CLAIM).asString();

                JsonNode value;

                // check if digest has already been checked (maybe not used), if so throw exception otherwise add to usedDigests (this covers step 4 of RFC 9901 7.1)
                checkAndUpdateFoundDigest(digest, foundDigests);

                if (digestMap.containsKey(digest)) {
                    usedDigests.add(digest);

                    var disclosure = digestMap.get(digest);

                    if (disclosure.getClaimName() != null || disclosure.getClaimValue() == null || disclosure.getSalt() == null) {
                        throw new SdJwtVerificationException("Illegal non-array disclosure found");
                    }

                    value = SdJwtObjectMapper.INSTANCE.convertValue(disclosure.getClaimValue(), JsonNode.class);
                } else {
                    // if value is not requested, return the digest so callers can check type -> must be checked in verifier
                    value = SdJwtObjectMapper.INSTANCE.convertValue(digest, JsonNode.class);
                }

                newArray.add(processNode(value, digestMap, usedDigests, foundDigests));
            } else {
                newArray.add(processNode(element, digestMap, usedDigests, foundDigests));
            }
        }

        return newArray;
    }

    private void checkAndUpdateFoundDigest(String digest, Set<String> foundDigests) throws SdJwtVerificationException {
        if (!foundDigests.add(digest)) {
            throw new SdJwtVerificationException("Digest used more than once");
        }
    }
}
