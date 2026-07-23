package ch.admin.bj.swiyu.tsverifier.statement;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ProtectedIssuanceAuthorizationTrustStatementTest {

    ObjectMapper mapper = new ObjectMapper();

    @Test
    void testParseExample() throws JacksonException {
        var piaTS = mapper.readValue(ExampleTrustStatement.piaTS.getBodyJson(), ProtectedIssuanceAuthorizationTrustStatement.class);
        var header = mapper.readValue(ExampleTrustStatement.piaTS.getHeaderJson(), StatementHeader.class);
        piaTS.setStatementHeaders(header);
        assertThat(piaTS.getExp()).isEqualTo(32503676400L);
        assertThat(piaTS.getIat()).isEqualTo(1690360968L);
        assertThat(piaTS.getStatementHeaders().getTyp()).isEqualTo(StatementType.PROTECTED_ISSUANCE_AUTHORIZATION_TRUST_STATEMENT);
        assertThat(piaTS.getCanIssue())
                .as("Should have a can_issue authorization")
                .isNotNull();
        assertThat(piaTS.getCanIssue().getVct())
                .as("Should have a can issue VCT")
                .isEqualTo("urn:ch.admin.fedpol.betaid");
    }
}