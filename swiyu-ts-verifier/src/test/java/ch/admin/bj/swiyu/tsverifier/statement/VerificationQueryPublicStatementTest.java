package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class VerificationQueryPublicStatementTest {

    ObjectMapper mapper = new ObjectMapper();

    @Test
    void testParseExample() throws JsonProcessingException {
        var pvaTS = mapper.readValue(ExampleTrustStatement.vqPS_protected_claim.getCombinedJson(), VerificationQueryPublicStatement.class);
        assertThat(pvaTS.getTyp()).isEqualTo(StatementType.VERIFICATION_QUERY_PUBLIC_STATEMENT);
        assertThat(pvaTS.getRequest()).isNotNull();
        assertThat(pvaTS.getRequest().getQuery()).isNotNull();
    }
}