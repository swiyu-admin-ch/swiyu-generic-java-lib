package ch.admin.bj.swiyu.sdjwtverifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.authlete.sd.Disclosure;

import tools.jackson.databind.JsonNode;

import ch.admin.bj.swiyu.sdjwtverifier.exception.SdJwtVerificationException;

/**
 * Unit tests for {@link SdJwtNodeProcessor}, the recursive tree-walking core of the
 * disclosure resolution logic (RFC 9901 §7.1).
 */
class SdJwtNodeProcessorTest {

    private final SdJwtNodeProcessor processor = new SdJwtNodeProcessor();

    @Test
    void processNode_whenObjectHasDisclosedClaim_thenResolvesClaimAndTracksDigest() throws SdJwtVerificationException {
        Disclosure disclosure = new Disclosure("name", "Bob");
        String digest = disclosure.digest();
        JsonNode input = toJson(Map.of("_sd", List.of(digest), "other", "value"));
        List<String> usedDigests = new ArrayList<>();

        JsonNode result = processor.processNode(input, Map.of(digest, disclosure), usedDigests);

        assertThat(result.get("name").asString()).isEqualTo("Bob");
        assertThat(result.get("other").asString()).isEqualTo("value");
        assertThat(usedDigests).containsExactly(digest);
    }

    @Test
    void processNode_whenArrayElementDigestIsResolved_thenReplacesElementWithValue() throws SdJwtVerificationException {
        Disclosure disclosure = new Disclosure("secret-value");
        String digest = disclosure.digest();
        JsonNode input = toJson(List.of(Map.of("...", digest)));
        List<String> usedDigests = new ArrayList<>();

        JsonNode result = processor.processNode(input, Map.of(digest, disclosure), usedDigests);

        assertThat(result.isArray()).isTrue();
        assertThat(result.get(0).asString()).isEqualTo("secret-value");
        assertThat(usedDigests).containsExactly(digest);
    }

    @Test
    void processNode_whenArrayElementDigestIsNotProvided_thenKeepsDigestAsPlaceholder() throws SdJwtVerificationException {
        Disclosure disclosure = new Disclosure("undisclosed-value");
        String digest = disclosure.digest();
        JsonNode input = toJson(List.of(Map.of("...", digest)));

        JsonNode result = processor.processNode(input, Map.of(), new ArrayList<>());

        // Element must not simply be dropped, otherwise index-based access on the array would shift.
        assertThat(result.get(0).asString()).isEqualTo(digest);
    }

    @Test
    void processNode_whenSdClaimIsNotAnArray_thenThrows() {
        JsonNode input = toJson(Map.of("_sd", "not-an-array"));

        assertThatThrownBy(() -> processor.processNode(input, Map.of(), new ArrayList<>()))
                .isInstanceOf(SdJwtVerificationException.class)
                .hasMessageContaining("'_sd' claim must be a JSON array");
    }

    @Test
    void processNode_whenDisclosedClaimNameAlreadyExistsAtSdLevel_thenThrows() {
        Disclosure disclosure = new Disclosure("name", "Bob");
        String digest = disclosure.digest();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("name", "AlreadyPresent");
        claims.put("_sd", List.of(digest));
        JsonNode input = toJson(claims);

        assertThatThrownBy(() -> processor.processNode(input, Map.of(digest, disclosure), new ArrayList<>()))
                .isInstanceOf(SdJwtVerificationException.class)
                .hasMessageContaining("already exists");
    }

    @ParameterizedTest
    @ValueSource(strings = {"_sd", "..."})
    void processNode_whenDisclosureClaimNameIsReserved_thenThrows(String reservedName) {
        Disclosure disclosure = new Disclosure(reservedName, "value");
        String digest = disclosure.digest();
        JsonNode input = toJson(Map.of("_sd", List.of(digest)));

        assertThatThrownBy(() -> processor.processNode(input, Map.of(digest, disclosure), new ArrayList<>()))
                .isInstanceOf(SdJwtVerificationException.class)
                .hasMessageContaining("_sd or ...");
    }

    @Test
    void removeSdKeys_removesSdKeyAtEveryNestingLevel() {
        JsonNode input = toJson(Map.of(
                "_sd", List.of("top-level-digest"),
                "nested", Map.of("_sd", List.of("nested-digest"), "value", "kept")));

        assertDoesNotThrow(() -> processor.removeSdKeys(input));

        assertThat(input.has("_sd")).isFalse();
        assertThat(input.get("nested").has("_sd")).isFalse();
        assertThat(input.get("nested").get("value").asString()).isEqualTo("kept");
    }

    private static JsonNode toJson(Object value) {
        return SdJwtObjectMapper.INSTANCE.convertValue(value, JsonNode.class);
    }
}
