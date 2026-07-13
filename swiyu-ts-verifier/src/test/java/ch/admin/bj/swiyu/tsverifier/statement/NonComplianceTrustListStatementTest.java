package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class NonComplianceTrustListStatementTest {
    ObjectMapper mapper = new ObjectMapper();

    @Test
    void testParseExample()  throws JsonProcessingException {
        var ncTLS = mapper.readValue(ExampleTrustStatement.ncTLS.getBodyJson(), NonComplianceTrustListStatement.class);
        var header = mapper.readValue(ExampleTrustStatement.ncTLS.getHeaderJson(), StatementHeader.class);
        ncTLS.setStatementHeaders(header);
        assertThat(ncTLS.getStatementHeaders().getTyp()).isEqualTo(StatementType.NON_COMPLIANCE_TRUST_LIST_STATEMENT);
        assertThat(ncTLS.getNonCompliantActors())
                .as("Should parse both entries")
                .hasSize(2)
                .filteredOn(nonCompliantActor -> "did:example:badActor".equals(nonCompliantActor.getActor()))
                .as("Should find the example bad actor in the parsed list")
                .hasSize(1);
    }
}