package ch.admin.bj.swiyu.tsverifier.statement;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

import java.util.Optional;
import java.util.stream.Stream;

class StatementParserTest {
    
    static ECKey key;
    static ObjectMapper mapper = new ObjectMapper();
    
    @BeforeAll
    static void init() throws JOSEException {
        key = new ECKeyGenerator(Curve.P_256).keyID("test-key").generate();
    }

    private static Stream<Arguments> statementsProvider() {
        return Stream.of(
                Arguments.of(ExampleTrustStatement.idTS, IdentityTrustStatement.class),
                Arguments.of(ExampleTrustStatement.vqPS, VerificationQueryPublicStatement.class),
                Arguments.of(ExampleTrustStatement.pvaTS, ProtectedVerificationAuthorizationTrustStatement.class),
                Arguments.of(ExampleTrustStatement.piaTS, ProtectedIssuanceAuthorizationTrustStatement.class),
                Arguments.of(ExampleTrustStatement.piTLS, ProtectedIssuanceTrustListStatement.class),
                Arguments.of(ExampleTrustStatement.ncTLS, NonComplianceTrustListStatement.class)
        );
    }

    @ParameterizedTest
    @MethodSource("statementsProvider")
    void parseStatement_returnsCorrectStatement(ExampleTrustStatement example, Class<? extends Statement> expectedClass) {
        String serializedJwt = example.getSerializedJwt(key);
        StatementParser parser = new StatementParser();
        Statement parsed = assertDoesNotThrow(() -> parser.parse(serializedJwt).get());
        assertThat(parsed)
                .isNotNull()
                .as("Parsed statement should be of type %s", expectedClass.getSimpleName())
                .isInstanceOf(expectedClass);
        assertThat(parsed.getSerializedJwt())
                .as("Serialized JWT should be stored in the statement")
                .isEqualTo(serializedJwt);
    }

    @ParameterizedTest
    @MethodSource("statementsProvider")
    void parseStatement_mismatchStatement(ExampleTrustStatement example) {
        // Create Wrong statements where the body does not match the type
        var nextStatement = ExampleTrustStatement.values()[(example.ordinal()+1)%ExampleTrustStatement.values().length];
        var jwt = assertDoesNotThrow(() -> new SignedJWT(JWSHeader.parse(example.getHeader()), JWTClaimsSet.parse(nextStatement.getBody())));
        assertDoesNotThrow(() -> jwt.sign(new ECDSASigner(key)));
        var serializedJwt = jwt.serialize();
        StatementParser parser = new StatementParser();
        var parsedStatement = assertDoesNotThrow(() -> parser.parse(serializedJwt));
        assertThat(parsedStatement).isEmpty();
    }
}