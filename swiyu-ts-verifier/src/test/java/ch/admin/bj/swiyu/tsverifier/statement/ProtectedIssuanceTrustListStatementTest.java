package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ProtectedIssuanceTrustListStatementTest {

    ObjectMapper mapper = new ObjectMapper();

    @Test
    void testParseExample() throws JsonProcessingException {
        var piTLS = mapper.readValue(ExampleTrustStatement.piTLS.getBodyJson(), ProtectedIssuanceTrustListStatement.class);
        var header = mapper.readValue(ExampleTrustStatement.piTLS.getHeaderJson(), StatementHeader.class);
        piTLS.setStatementHeaders(header);
        assertThat(piTLS.getStatementHeaders().getTyp()).isEqualTo(StatementType.PROTECTED_ISSUANCE_TRUST_LIST_STATEMENT);
        assertThat(piTLS.getVctValues()).hasSize(3).contains("urn:ch.admin.fedpol.betaid", "urn:ch.admin.fedpol.eid", "urn:com.example.otherCredential");
    }
}