package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class ProtectedIssuanceTrustListStatementTest {

    ObjectMapper mapper = new ObjectMapper();

    @Test
    void testParseExample() throws JsonProcessingException {
        var piTLS = mapper.readValue(ExampleTrustStatement.piTLS.getCombinedJson(), ProtectedIssuanceTrustListStatement.class);
        assertThat(piTLS.getTyp()).isEqualTo(StatementType.PROTECTED_ISSUANCE_TRUST_LIST_STATEMENT);
        assertThat(piTLS.getVctValues()).hasSize(2).contains("urn:ch.admin.fedpol.betaid", "urn:ch.admin.fedpol.eid");
    }
}