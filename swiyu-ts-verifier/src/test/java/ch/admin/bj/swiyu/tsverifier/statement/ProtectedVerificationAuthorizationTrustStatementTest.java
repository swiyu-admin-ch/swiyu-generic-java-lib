package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ProtectedVerificationAuthorizationTrustStatementTest {

    ObjectMapper mapper = new ObjectMapper();

    @Test
    void testParseExample() throws JsonProcessingException {
        var pvaTS = mapper.readValue(ExampleTrustStatement.pvaTS.getBodyJson(), ProtectedVerificationAuthorizationTrustStatement.class);
        var header = mapper.readValue(ExampleTrustStatement.pvaTS.getHeaderJson(), StatementHeader.class);
        pvaTS.setStatementHeaders(header);
        assertThat(pvaTS.getStatementHeaders().getTyp()).isEqualTo(StatementType.PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT);
        assertThat(pvaTS.getAuthorizedFields()).hasSize(1).contains("personal_administrative_number");
    }
}