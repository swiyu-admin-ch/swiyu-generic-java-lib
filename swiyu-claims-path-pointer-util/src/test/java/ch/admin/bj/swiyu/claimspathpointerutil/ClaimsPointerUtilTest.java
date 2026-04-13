package ch.admin.bj.swiyu.claimspathpointerutil;

import java.util.*;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClaimsPathPointerUtilTest {

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
                "age", 30,
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
    void validateRequestedClaim_emptyPointerPath_throws() {
        Map<String, Object> obj = Map.of("a", "b");
        assertThrows(IllegalArgumentException.class,
                () -> ClaimsPathPointerUtil.validateRequestedClaim(obj, List.of(), null));
    }

    @Test
    void validateRequestedClaim_pathNotFound_throws() {
        Map<String, Object> obj = Map.of("a", Map.of("b", "c"));
        assertThrows(IllegalArgumentException.class,
                () -> ClaimsPathPointerUtil.validateRequestedClaim(obj, List.of("a", "missing"), null));
    }

    @Test
    void validateRequestedClaim_simplePath_successWhenValuesNull() {
        Map<String, Object> obj = Map.of("name", "Arthur Dent");
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaim(obj, List.of("name"), null));
    }

    @Test
    void validateRequestedClaim_simplePath_valueSatisfied_success() {
        Map<String, Object> obj = Map.of("name", "Arthur Dent");
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaim(
                obj,
                List.of("name"),
                List.of("Arthur Dent", "Zaphod")
        ));
    }

    @Test
    void validateRequestedClaim_simplePath_valueNotSatisfied_throws() {
        Map<String, Object> obj = Map.of("name", "Arthur Dent");
        assertThrows(IllegalArgumentException.class, () -> ClaimsPathPointerUtil.validateRequestedClaim(
                obj,
                List.of("name"),
                List.of("Ford Prefect")
        ));
    }

    @Test
    void validateRequestedClaim_wildcardSelectAllArrayElements_success() {
        Map<String, Object> obj = Map.of(
                "roles", List.of("admin", "user")
        );
        List<Object> claimPointer = new ArrayList<>();
        claimPointer.add("roles");
        claimPointer.add(null); // wildcard on array

        // roles[*] contains "user"
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaim(
                obj,
                claimPointer,
                List.of("user")
        ));
    }

    @Test
    void validateRequestedClaim_numericIndexSelection_success() {
        Map<String, Object> obj = Map.of(
                "degrees", List.of(
                        Map.of("type", "BSc"),
                        Map.of("type", "MSc")
                )
        );

        // degrees[1].type == "MSc"
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaim(
                obj,
                List.of("degrees", 1, "type"),
                List.of("MSc")
        ));
    }

    @Test
    void validateRequestedClaim_illegalPathComponentType_throws() {
        Map<String, Object> obj = Map.of("a", "b");
        assertThrows(IllegalArgumentException.class, () -> ClaimsPathPointerUtil.validateRequestedClaim(
                obj,
                List.of(new Object()),
                null
        ));
    }

    @Test
    void validateRequestedClaim_wildcardOnNonArray_throws() {
        Map<String, Object> obj = Map.of("roles", "admin");
        List<Object> claimPointer = new ArrayList<>();
        claimPointer.add("roles");
        claimPointer.add(null); // wildcard on array
        assertThrows(IllegalArgumentException.class, () -> ClaimsPathPointerUtil.validateRequestedClaim(
                obj,
                claimPointer,
                null
        ));
    }

    @Test
    void validateRequestedClaim_indexOnNonArray_throws() {
        Map<String, Object> obj = Map.of("roles", "admin");
        assertThrows(IllegalArgumentException.class, () -> ClaimsPathPointerUtil.validateRequestedClaim(
                obj,
                List.of("roles", 0),
                null
        ));
    }

    @Test
    void validateRequestedClaim_keySelectionOnNonObject_throws() {
        Map<String, Object> obj = Map.of("roles", List.of("admin"));
        assertThrows(IllegalArgumentException.class, () -> ClaimsPathPointerUtil.validateRequestedClaim(
                obj,
                List.of("roles", 0, "name"),
                null
        ));
    }

    @Test
    void validateRequestedClaim_keySelectionOnNonObject_thenSuccess() {
        List<Object> claimPointer = new ArrayList<>();
        claimPointer.add("roles");
        claimPointer.add(null); // wildcard on array
        Map<String, Object> obj = Map.of("roles", List.of("admin"));
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaim(
                obj,
                claimPointer,
                null
        ));
    }
}
