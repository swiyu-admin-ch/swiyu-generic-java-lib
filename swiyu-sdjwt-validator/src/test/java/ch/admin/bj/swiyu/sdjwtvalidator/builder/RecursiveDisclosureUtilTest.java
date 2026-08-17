package ch.admin.bj.swiyu.sdjwtvalidator.builder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.authlete.sd.Disclosure;
import com.authlete.sd.SDObjectBuilder;
import ch.admin.bj.swiyu.sdjwtvalidator.exception.SdJwtBuilderException;
import org.junit.jupiter.api.Test;

class RecursiveDisclosureUtilTest {

    @Test
    void putSelectivelyDiscloseableData_WithFlatMap_ReturnsDisclosures() throws SdJwtBuilderException {
        var builder = new SDObjectBuilder();
        Map<String, Object> data = Map.of("name", "John", "age", 30);

        var disclosures = RecursiveDisclosureUtil.putSelectivelyDiscloseableData(builder, data);

        assertThat(disclosures).hasSize(2);
        assertThat(disclosures).extracting(Disclosure::getClaimName)
            .containsExactlyInAnyOrder("name", "age");
    }

    @Test
    void putSelectivelyDiscloseableData_WithNestedMap_ReturnsDisclosures() throws SdJwtBuilderException {
        var builder = new SDObjectBuilder();
        Map<String, Object> data = Map.of("address", Map.of("street", "Main St", "city", "Zurich"));

        var disclosures = RecursiveDisclosureUtil.putSelectivelyDiscloseableData(builder, data);

        assertThat(disclosures).hasSize(3); // address, street, city
    }

    @Test
    void putSelectivelyDiscloseableData_WithList_ReturnsDisclosures() throws SdJwtBuilderException {
        var builder = new SDObjectBuilder();
        Map<String, Object> data = Map.of("roles", List.of("admin", "user"));

        var disclosures = RecursiveDisclosureUtil.putSelectivelyDiscloseableData(builder, data);

        assertThat(disclosures).hasSize(3); // roles, admin, user
    }

    @Test
    void putSelectivelyDiscloseableData_WithProtectedClaim_ThrowsException() {
        var builder = new SDObjectBuilder();
        Map<String, Object> data = Map.of("iss", "invalid");

        assertThatThrownBy(() -> RecursiveDisclosureUtil.putSelectivelyDiscloseableData(builder, data))
            .isInstanceOf(SdJwtBuilderException.class)
            .hasMessageContaining("Protected claim iss MUST NOT be overridden");
    }

    @Test
    void putSelectivelyDiscloseableData_WithNullValue_ReturnsDisclosure() throws SdJwtBuilderException {
        var builder = new SDObjectBuilder();
        Map<String, Object> data = new HashMap<>();
        data.put("optional", null);

        var disclosures = RecursiveDisclosureUtil.putSelectivelyDiscloseableData(builder, data);

        assertThat(disclosures).hasSize(1);
        assertThat(disclosures.get(0).getClaimName()).isEqualTo("optional");
        assertThat(disclosures.get(0).getClaimValue()).isNull();
    }

    @Test
    void putSelectivelyDiscloseableData_WithComplexNestedStructure_ReturnsDisclosures() throws SdJwtBuilderException {
        var builder = new SDObjectBuilder();
        Map<String, Object> data = Map.of(
            "user", Map.of(
                "name", "Alice",
                "roles", List.of("admin", "user"),
                "address", Map.of("city", "Bern")
            )
        );

        var disclosures = RecursiveDisclosureUtil.putSelectivelyDiscloseableData(builder, data);

        assertThat(disclosures).as("There are 5 values with keys and 2 list entries").hasSize(7); // user, name, roles, admin, user, city, null, null
    }
}