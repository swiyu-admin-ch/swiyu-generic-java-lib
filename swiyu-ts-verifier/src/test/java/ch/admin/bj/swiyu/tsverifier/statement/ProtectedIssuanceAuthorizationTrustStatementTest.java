package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ProtectedIssuanceAuthorizationTrustStatementTest {

    ObjectMapper mapper = new ObjectMapper();

    @Test
    void testParseExample() throws JsonProcessingException {
        var piaTS = mapper.readValue(ExampleTrustStatement.piaTS.getBodyJson(), ProtectedIssuanceAuthorizationTrustStatement.class);
        var header = mapper.readValue(ExampleTrustStatement.piaTS.getHeaderJson(), StatementHeader.class);
        piaTS.setStatementHeaders(header);
        assertThat(piaTS.getStatementHeaders().getTyp()).isEqualTo(StatementType.PROTECTED_ISSUANCE_AUTHORIZATION_TRUST_STATEMENT);
        assertThat(piaTS.getCanIssue())
                .as("Should have a can_issue authorization")
                .isNotNull();
        assertThat(piaTS.getCanIssue().getVct())
                .as("Should have a can issue VCT")
                .isEqualTo("urn:ch.admin.fedpol.betaid");
    }
}