package ch.admin.bj.swiyu.tsverifier.statement;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class IdentityTrustStatementTest {

    ObjectMapper mapper = new ObjectMapper();

    @Test
    void testParseExample() throws JsonProcessingException {
        var idTS = mapper.readValue(ExampleTrustStatement.idTS.getCombinedJson(), IdentityTrustStatement.class);
        assertThat(idTS.getTyp()).isEqualTo(StatementType.IDENTITY_TRUST_STATEMENT);
        assertThat(idTS.getExp()).isEqualTo(1753432968);
        assertThat(idTS.getKid()).isEqualTo("did:example:trust-issuer#key-1");
        assertThat(idTS.getEntityName()).isEqualTo("John Smith's Smithery");
    }
}