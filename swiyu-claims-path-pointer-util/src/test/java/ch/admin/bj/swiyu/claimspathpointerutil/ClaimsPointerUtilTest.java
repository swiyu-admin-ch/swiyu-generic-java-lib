package ch.admin.bj.swiyu.claimspathpointerutil;

import java.util.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClaimsPathPointerUtilTest {

    private Map<String, Object> sdJwt;

    @BeforeEach
    void setUp() throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        // OID4VP 1.0 7.3 Claims Path Pointer Example https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-7.3
        // all numbers are float, as sdjwt lib marshalls all numbers to float
        sdJwt = objectMapper.readValue("""
                {
                  "vct": "https://www.oid4vp.example.com/university",
                  "name": "Arthur Dent",
                  "address": {
                    "street_address": "42 Market Street",
                    "locality": "Milliways",
                    "postal_code": "12345"
                  },
                  "degrees": [
                    {
                      "type": "Bachelor of Science",
                      "university": "University of Betelgeuse"
                    },
                    {
                      "type": "Master of Science",
                      "university": "University of Betelgeuse"
                    }
                  ],
                  "nationalities": ["British", "Betelgeusian"],
                  "boolean_value": true,
                  "integer_number": 98.0,
                  "float_number": 55.5,
                  "lucky_numbers": [7.0, 3.14, 42.0]
                }
                """, Map.class);
    }

    /**
     * Verifies that flatten returns the input path when the current object is a leaf (non-Map and non-List).
     */
    @Test
    void flatten_leafValue_returnsCurrentPath() {
        Set<List<Object>> result = ClaimsPathPointerUtil.flatten("leaf", new ArrayList<>(List.of("a")));

        assertEquals(1, result.size());
        assertTrue(result.contains(List.of("a")));
    }

    /**
     * Verifies that flatten returns an empty result set when invoked on a leaf with an empty path.
     */
    @Test
    void flatten_leafValueWithEmptyPath_returnsEmptySet() {
        Set<List<Object>> result = ClaimsPathPointerUtil.flatten("leaf", new ArrayList<>());

        assertTrue(result.isEmpty());
    }

    /**
     * Verifies that flatten handles nested objects and produces full paths to leaves.
     */
    @Test
    void flatten_nestedMaps_producesFullPath() {
        Map<String, Object> inner = new HashMap<>();
        inner.put("leaf", "v");
        Map<String, Object> root = new HashMap<>();
        root.put("obj", inner);

        Set<List<Object>> result = ClaimsPathPointerUtil.flatten(root, new ArrayList<>());

        assertEquals(1, result.size());
        assertTrue(result.contains(List.of("obj", "leaf")));
    }

    /**
     * Verifies that flatten does not mutate the input path list.
     */
    @Test
    void flatten_doesNotMutateInputPath() {
        List<Object> originalPath = new ArrayList<>(List.of("base"));
        Map<String, Object> root = new HashMap<>();
        root.put("a", "x");

        ClaimsPathPointerUtil.flatten(root, originalPath);

        assertEquals(List.of("base"), originalPath);
    }

    /**
     * Verifies complex structure.
     */
    @Test
    void flatten_complex() {
        Map<String, Object> obj = Map.of(
                "given_name", "Alice",
                "family_name", "Smith",
                "age", 30.0,
                "address", Map.of(
                        "street_address", "Main St",
                        "locality", "Zurich",
                        "country", "CH",
                        "coordinates", Map.of(
                                "lat", 47.3769,
                                "lng", 8.5417
                        )
                ),
                "emails", List.of(
                        Map.of("type", "work", "value", "alice@company.com"),
                        Map.of("type", "personal", "value", "alice@gmail.com")
                ),
                "phone_numbers", List.of("+41790000000"),
                "roles", List.of("admin", "user")
        );

        var claimsPathPointer = ClaimsPathPointerUtil.flatten(obj, List.of());

        assertTrue(claimsPathPointer.contains(List.of("given_name")));
        assertTrue(claimsPathPointer.contains(List.of("family_name")));
        assertTrue(claimsPathPointer.contains(List.of("age")));
        assertTrue(claimsPathPointer.contains(List.of("address", "street_address")));
        assertTrue(claimsPathPointer.contains(List.of("address", "locality")));
        assertTrue(claimsPathPointer.contains(List.of("address", "country")));
        assertTrue(claimsPathPointer.contains(List.of("address", "coordinates", "lat")));
        assertTrue(claimsPathPointer.contains(List.of("address", "coordinates", "lng")));
        assertTrue(claimsPathPointer.contains(getListOf("emails", null, "type")));
        assertTrue(claimsPathPointer.contains(getListOf("emails", null, "value")));
        assertTrue(claimsPathPointer.contains(getListOf("phone_numbers", null)));
        assertTrue(claimsPathPointer.contains(getListOf("roles", null)));

        assertEquals(12, claimsPathPointer.size());
    }

    private List<Object> getListOf(Object... elements) {
        return Arrays.asList(elements);
    }

    @Test
    void validateRequestedClaims_emptyPointerPath_throws() {
        Map<String, Object> obj = Map.of("a", "b");
        assertThrows(IllegalArgumentException.class,
                () -> ClaimsPathPointerUtil.validateRequestedClaims(obj, List.of(), null));
    }

    @Test
    void validateRequestedClaims_pathNotFound_throws() {
        Map<String, Object> obj = Map.of("a", Map.of("b", "c"));
        assertThrows(IllegalArgumentException.class,
                () -> ClaimsPathPointerUtil.validateRequestedClaims(obj, List.of("a", "missing"), null));
    }

    @Test
    void validateRequestedClaims_simplePath_successWhenValuesNull() {
        Map<String, Object> obj = Map.of("name", "Arthur Dent");
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(obj, List.of("name"), null));
    }

    @Test
    void validateRequestedClaims_simplePath_valueSatisfied_success() {
        Map<String, Object> obj = Map.of("name", "Arthur Dent");
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(
                obj,
                List.of("name"),
                List.of("Arthur Dent", "Zaphod")
        ));
    }

    @Test
    void validateRequestedClaims_simplePath_valueNotSatisfied_throws() {
        Map<String, Object> obj = Map.of("name", "Arthur Dent");
        assertThrows(IllegalArgumentException.class, () -> ClaimsPathPointerUtil.validateRequestedClaims(
                obj,
                List.of("name"),
                List.of("Ford Prefect")
        ));
    }

    @Test
    void validateRequestedClaims_wildcardSelectAllArrayElements_success() {
        Map<String, Object> obj = Map.of(
                "roles", List.of("admin", "user")
        );
        List<Object> claimPointer = new ArrayList<>();
        claimPointer.add("roles");
        claimPointer.add(null); // wildcard on array

        // roles[*] contains "user"
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(
                obj,
                claimPointer,
                List.of("user")
        ));
    }

    @Test
    void validateRequestedClaims_numericIndexSelection_success() {
        Map<String, Object> obj = Map.of(
                "degrees", List.of(
                        Map.of("type", "BSc"),
                        Map.of("type", "MSc")
                )
        );

        // degrees[1].type == "MSc"
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(
                obj,
                List.of("degrees", 1, "type"),
                List.of("MSc")
        ));
    }

    @Test
    void validateRequestedClaims_illegalPathComponentType_throws() {
        Map<String, Object> obj = Map.of("a", "b");
        assertThrows(IllegalArgumentException.class, () -> ClaimsPathPointerUtil.validateRequestedClaims(
                obj,
                List.of(new Object()),
                null
        ));
    }

    @Test
    void validateRequestedClaims_wildcardOnNonArray_throws() {
        Map<String, Object> obj = Map.of("roles", "admin");
        List<Object> claimPointer = new ArrayList<>();
        claimPointer.add("roles");
        claimPointer.add(null); // wildcard on array
        assertThrows(IllegalArgumentException.class, () -> ClaimsPathPointerUtil.validateRequestedClaims(
                obj,
                claimPointer,
                null
        ));
    }

    @Test
    void validateRequestedClaims_indexOnNonArray_throws() {
        Map<String, Object> obj = Map.of("roles", "admin");
        assertThrows(IllegalArgumentException.class, () -> ClaimsPathPointerUtil.validateRequestedClaims(
                obj,
                List.of("roles", 0),
                null
        ));
    }

    @Test
    void validateRequestedClaims_keySelectionOnNonObject_throws() {
        Map<String, Object> obj = Map.of("roles", List.of("admin"));
        assertThrows(IllegalArgumentException.class, () -> ClaimsPathPointerUtil.validateRequestedClaims(
                obj,
                List.of("roles", 0, "name"),
                null
        ));
    }

    @Test
    void validateRequestedClaims_keySelectionOnNonObject_thenSuccess() {
        List<Object> claimPointer = new ArrayList<>();
        claimPointer.add("roles");
        claimPointer.add(null); // wildcard on array
        Map<String, Object> obj = Map.of("roles", List.of("admin"));
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(
                obj,
                claimPointer,
                null
        ));
    }

    /**
     * checks value of numbers in array, if one matches, the selection is valid
     */
    @Test
    void validateRequestedClaims_withNumberValidation_doesNotThrow() {
        var numberList = new ArrayList<>();
        numberList.add("lucky_numbers");
        numberList.add(null);
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(sdJwt, numberList, List.of(7)));
    }

    /**
     * checks value of numbers in array, if one matches, the selection is valid
     */
    @Test
    void validateRequestedClaims_withFloatNumberValidation_doesNotThrow() {
        var numberList = new ArrayList<>();
        numberList.add("lucky_numbers");
        numberList.add(null);
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(sdJwt, numberList, List.of(3.14)));
    }
}
