package ch.admin.bj.swiyu.sdjwtvalidator.builder;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDObjectBuilder;

import ch.admin.bj.swiyu.sdjwtvalidator.SdJwtConstants;
import ch.admin.bj.swiyu.sdjwtvalidator.exception.SdJwtBuilderException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class RecursiveDisclosureUtil {
    /**
     * Add the selectively discloseable data to the SD-JWT and prepare the discosures
     *
     * @return list of the disclosures
     * @throws SdJwtBuilderException if the building of the disclosures fail due to faulty input data - for example a guarded claim is voilated
     */
    static List<Disclosure> putSelectivelyDiscloseableData(SDObjectBuilder builder, Map<String, Object> selectivelyDiscloseableData) throws SdJwtBuilderException {
        // Optional claims as disclosures
        // Code below follows example from
        // https://github.com/authlete/sd-jwt?tab=readme-ov-file#credential-jwt
        List<Disclosure> disclosures = new ArrayList<>();

        // https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#section-3.2.2.2
        try {
            selectivelyDiscloseableData.forEach((entryKey, entryValue) -> handleClaimRecursive(entryKey, entryValue, disclosures, builder));
        } catch (IllegalArgumentException e) {
            throw new SdJwtBuilderException(e);
        }

        return disclosures;
    }
    
    private static Disclosure handleClaimRecursive(String entryKey, Object entryValue, List<Disclosure> disclosures, SDObjectBuilder builder) {
        return switch (entryValue) {
            case Map<?, ?> mapValue when mapValue.keySet().stream().allMatch(String.class::isInstance) ->
                    handleNestedClaimMap(entryKey, (Map<String, Object>) mapValue, disclosures, builder);
            case Collection<?> collectionValue ->
                    handleListDisclosures(builder, entryKey, collectionValue, disclosures);
            case null, default -> handleLeafClaim(entryKey, entryValue, disclosures, builder);
        };
    }

    private static Disclosure handleNestedClaimMap(String entryKey,
                                            Map<String, Object> mapValue,
                                            List<Disclosure> disclosures,
                                            SDObjectBuilder builder) {

        guardProtectedClaims(entryKey);

        // Create a new builder for the nested map to build its disclosures
        var nestedBuilder = new SDObjectBuilder();

        // Recursive call for nested maps
        mapValue.forEach((key, entryValue) -> handleClaimRecursive(key, entryValue, disclosures, nestedBuilder));

        // Create new Disclosure for the nested map and add it to the disclosures list
        // and the parent builder
        var nestedDigest = new Disclosure(entryKey, nestedBuilder.build());

        disclosures.add(nestedDigest);

        // Only add to parent builder if we have a key, otherwise this is a nested map within a list and should not be added as separate claim to the builder
        if (entryKey != null) {
            builder.putSDClaim(nestedDigest);
        }

        return nestedDigest;
    }

    private static Disclosure handleListDisclosures(SDObjectBuilder builder,
                                             String key,
                                             Collection<?> collectionValue,
                                             List<Disclosure> disclosures) {

        guardProtectedClaims(key);

        SDObjectBuilder nestedBuilder = new SDObjectBuilder();

        var listDisclosures = collectionValue.stream()
                .map(item -> handleClaimRecursive(null, item, disclosures, nestedBuilder))
                .toList();

        var disc = listDisclosures.stream()
                .filter(Objects::nonNull)
                .map(Disclosure::toArrayElement)
                .toList();

        var recDisclosure = new Disclosure(key, disc);
        disclosures.add(recDisclosure);

        if (key != null) {
            builder.putSDClaim(recDisclosure);
        }

        return recDisclosure;
    }

    private static Disclosure handleLeafClaim(String key,
                                       Object value,
                                       List<Disclosure> disclosures,
                                       SDObjectBuilder builder) {

        guardProtectedClaims(key);

        Disclosure disclosure;

        if (key != null) {
            disclosure = new Disclosure(key, value);
            builder.putSDClaim(disclosure);
        } else {
            // handle array list element -> does not contain key and is not added to builder
            disclosure = new Disclosure(value);
        }

        disclosures.add(disclosure);

        return disclosure;
    }

    /**
     * Guard which throws an 
     * @param entryKey the key to be evaluated
     * @throws IllegalArgumentException if the entryKey is a protected claim and should not be used
     */
    private static void guardProtectedClaims(String entryKey) {
        if (entryKey != null && SdJwtConstants.PROTECTED_CLAIMS.contains(entryKey)) {
            throw new IllegalArgumentException(String.format("Protected claim %s MUST NOT be overridden", entryKey));
        }
    }
}
