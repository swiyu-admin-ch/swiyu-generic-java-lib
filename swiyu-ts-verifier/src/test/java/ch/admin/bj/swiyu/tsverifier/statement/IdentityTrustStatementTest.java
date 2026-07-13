package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class IdentityTrustStatementTest {

    ObjectMapper mapper = new ObjectMapper();

    @Test
    void testParseExample() throws JsonProcessingException {
        var idTS = mapper.readValue(ExampleTrustStatement.idTS.getBodyJson(), IdentityTrustStatement.class);
        var header = mapper.readValue(ExampleTrustStatement.idTS.getHeaderJson(), StatementHeader.class);
        idTS.setStatementHeaders(header);
        assertThat(idTS.getStatementHeaders().getTyp()).isEqualTo(StatementType.IDENTITY_TRUST_STATEMENT);
        assertThat(idTS.getExp()).isEqualTo(32503676400L);
        assertThat(idTS.getStatementHeaders().getKid()).isEqualTo("did:example:trust-issuer#key-1");
        assertThat(idTS.getEntityName()).isEqualTo("John Smith's Smithery");
    }
}