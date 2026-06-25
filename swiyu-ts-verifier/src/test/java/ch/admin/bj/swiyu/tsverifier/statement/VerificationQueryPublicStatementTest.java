package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class VerificationQueryPublicStatementTest {

    ObjectMapper mapper = new ObjectMapper();

    @Test
    void testParseExample() throws JsonProcessingException {
        var vqPS = mapper.readValue(ExampleTrustStatement.vqPS_protected_claim.getBodyJson(), VerificationQueryPublicStatement.class);
        var header = mapper.readValue(ExampleTrustStatement.vqPS.getHeaderJson(), StatementHeader.class);
        vqPS.setStatementHeaders(header);

        assertThat(vqPS.getStatementHeaders().getTyp()).isEqualTo(StatementType.VERIFICATION_QUERY_PUBLIC_STATEMENT);
        assertThat(vqPS.getRequest()).isNotNull();
        assertThat(vqPS.getRequest().getQuery()).isNotNull();
    }
}