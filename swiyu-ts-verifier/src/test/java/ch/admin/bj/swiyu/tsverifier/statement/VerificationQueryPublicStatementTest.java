package ch.admin.bj.swiyu.tsverifier.statement;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class VerificationQueryPublicStatementTest {

    ObjectMapper mapper = new ObjectMapper();

    @Test
    void testParseExample() throws JacksonException {
        var vqPS = mapper.readValue(ExampleTrustStatement.vqPS_protected_claim.getBodyJson(), VerificationQueryPublicStatement.class);
        var header = mapper.readValue(ExampleTrustStatement.vqPS.getHeaderJson(), StatementHeader.class);
        vqPS.setStatementHeaders(header);

        assertThat(vqPS.getExp()).isEqualTo(32503676400L);
        assertThat(vqPS.getIat()).isEqualTo(1690360968L);
        assertThat(vqPS.getStatementHeaders().getTyp()).isEqualTo(StatementType.VERIFICATION_QUERY_PUBLIC_STATEMENT);
        assertThat(vqPS.getRequest()).isNotNull();
        assertThat(vqPS.getRequest().getQuery()).isNotNull();
    }
}