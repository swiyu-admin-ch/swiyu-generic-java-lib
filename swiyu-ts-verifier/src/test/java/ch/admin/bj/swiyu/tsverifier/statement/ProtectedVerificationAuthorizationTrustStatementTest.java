package ch.admin.bj.swiyu.tsverifier.statement;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ProtectedVerificationAuthorizationTrustStatementTest {

    ObjectMapper mapper = new ObjectMapper();

    @Test
    void testParseExample() throws JacksonException {
        var pvaTS = mapper.readValue(ExampleTrustStatement.pvaTS.getBodyJson(), ProtectedVerificationAuthorizationTrustStatement.class);
        var header = mapper.readValue(ExampleTrustStatement.pvaTS.getHeaderJson(), StatementHeader.class);
        assertThat(pvaTS.getExp()).isEqualTo(32503676400L);
        assertThat(pvaTS.getIat()).isEqualTo(1690360968L);
        pvaTS.setStatementHeaders(header);
        assertThat(pvaTS.getStatementHeaders().getTyp()).isEqualTo(StatementType.PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT);
        assertThat(pvaTS.getAuthorizedFields()).hasSize(1).contains("personal_administrative_number");
    }
}