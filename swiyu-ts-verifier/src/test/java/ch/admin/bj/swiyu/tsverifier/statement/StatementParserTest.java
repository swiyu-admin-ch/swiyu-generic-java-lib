package ch.admin.bj.swiyu.tsverifier.statement;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

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

import java.util.stream.Stream;

class StatementParserTest {
    
    static ECKey key;
    
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

    private static Stream<Arguments> iatExpNullProvider() {
        return Stream.of(
                Arguments.of(null, 1690360968L),
                Arguments.of(1690360968L, null),
                Arguments.of(null, null)
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
        assertThat(parsed.getStatementHeaders())
                .isNotNull();
        assertThat(parsed.getStatementHeaders().getTyp()).isEqualTo(example.getHeaderMap().getTyp());
        assertThat(parsed.getSerializedJwt())
                .as("Serialized JWT should be stored in the statement")
                .isEqualTo(serializedJwt);
    }

    @ParameterizedTest
    @MethodSource("statementsProvider")
    void parseStatement_mismatchStatement(ExampleTrustStatement example) {
        // Create Wrong statements where the body does not match the type
        var nextStatement = ExampleTrustStatement.values()[(example.ordinal()+3)%ExampleTrustStatement.values().length];
        var jwt = assertDoesNotThrow(() -> new SignedJWT(JWSHeader.parse(example.getHeader()), JWTClaimsSet.parse(nextStatement.getBody())));
        assertDoesNotThrow(() -> jwt.sign(new ECDSASigner(key)));
        var serializedJwt = jwt.serialize();
        StatementParser parser = new StatementParser();
        var parsedStatement = assertDoesNotThrow(() -> parser.parse(serializedJwt));
        assertThat(parsedStatement).as("Statement Header %s does not match the statement body".formatted(example.getHeader())).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("iatExpNullProvider")
    void parseStatement_withNullIatOrExp_returnsEmptyOptional(Long iat, Long exp) {
        String body = """
                {
                    "sub": "did:example:actor",
                    "iat": %s,
                    "exp": %s,
                    "status":  {
                        "status_list": {
                          "idx": 1,
                          "uri": "https://example.com/statuslists/1"
                        }
                    },
                    "entity_name": "John Smith's Smithery",
                    "entity_name#de": "John Smith's Schmiderei",
                    "entity_name#de-CH": "John Smith's Schmiderei",
                    "is_state_actor": false,
                    "registry_ids": [
                      {
                        "type": "UID",
                        "value": "CHE-000.000.000"
                      },
                      {
                        "type": "LEI",
                        "value": "0A1B2C3D4E5F6G7H8J9I"
                      }
                    ]
                }""".formatted(iat, exp);
        String header = """
                {
                   "typ": "swiyu-identity-trust-statement+jwt",
                   "alg": "ES256",
                   "kid": "did:example:trust-issuer#key-1",
               	   "profile_version": "swiss-profile-trust:1.0.0"
               }""";
        String serializedJwt = createSignedJwt(header, body);
        StatementParser parser = new StatementParser();
        var parsed = assertDoesNotThrow(() -> parser.parse(serializedJwt));
        assertThat(parsed).as("Combination of iat: %s and exp: %s contains null values. And results in empty".formatted(iat, exp)).isEmpty();
    }

    private String createSignedJwt(String header, String body) {
        var jwt = assertDoesNotThrow(() -> new SignedJWT(JWSHeader.parse(header), JWTClaimsSet.parse(body)));
        assertDoesNotThrow(() -> jwt.sign(new ECDSASigner(key)));
        return jwt.serialize();
    }
}