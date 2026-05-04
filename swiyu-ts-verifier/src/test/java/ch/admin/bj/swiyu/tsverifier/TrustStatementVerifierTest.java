package ch.admin.bj.swiyu.tsverifier;

import ch.admin.bj.swiyu.jwtvalidator.DidKidParser;
import ch.admin.bj.swiyu.jwtvalidator.UrlRestriction;
import ch.admin.bj.swiyu.statuslist.dto.TokenStatusListTokenDto;
import ch.admin.bj.swiyu.tsverifier.statement.ExampleTrustStatement;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class TrustStatementVerifierTest {

    static final String TRUST_ROOT_DID = "did:example:trust-issuer";
    static final String PUBLIC_STATEMENT_ISSUER_DID = "did:example:verification-statment-issuer";
    static final String ACTOR_DID = "did:example:actor";
    static final String PROTECTED_VCT = "urn:ch.admin.fedpol.betaid";
    static final ObjectMapper mapper = new ObjectMapper();
    static ECKey trustIssuerKey;
    static ECKey publicIssuerKey;

    UrlRestriction mockRestriction;
    DidKidParser mockKidParser;

    @BeforeAll
    static void init() throws JOSEException {
        trustIssuerKey = new ECKeyGenerator(Curve.P_256).keyID("%s#key-1".formatted(TRUST_ROOT_DID)).generate();
        publicIssuerKey = new ECKeyGenerator(Curve.P_256).keyID("%s#key-1".formatted(PUBLIC_STATEMENT_ISSUER_DID)).generate();
    }

    @BeforeEach
    void setup() {
        mockRestriction = Mockito.mock(UrlRestriction.class);
        when(mockRestriction.validateUrl(any())).thenReturn(true);
        mockKidParser = Mockito.mock(DidKidParser.class);
        when(mockKidParser.getDidFromAbsoluteKid(any())).thenAnswer(invocation ->  invocation.getArguments()[0].toString().split("#")[0]);
    }

    @Test
    void testGetKeyIds() {
        var statements = getExampleTrustStatements();

        var verifier = new TrustStatementVerifier(statements, Mockito.mock(UrlRestriction.class));
        var ids = verifier.getRequiredKeyIds();
        assertThat(ids).hasSize(2).contains("did:example:trust-issuer#key-1", "did:example:verification-statment-issuer#key-1");
    }

    @Test
    void testGetStatusListUris() {
        var statements = getExampleTrustStatements();
        var verifier = new TrustStatementVerifier(statements, Mockito.mock(UrlRestriction.class));
        var statusListUris = verifier.getRequiredStatusLists();
        assertThat(statusListUris).hasSize(1).contains("https://example.com/statuslists/1");
    }

    @Test
    void testVerifyIssuanceStatements_whenGovernedUseCase() {
        var statements = getExampleTrustStatements();
        var verifier = new TrustStatementVerifier(statements, mockRestriction, mockKidParser);
        var result = verifier.verifyIssuanceStatements(TRUST_ROOT_DID, ACTOR_DID, PROTECTED_VCT, new JWKSet(trustIssuerKey), List.of(generateStatusListToken()));
        assertThat(result.evaluatedActorDid()).isEqualTo(ACTOR_DID);
        var markers = result.markers();
        assertThat(markers.isTrustedIssuer()).as("All Trust Statements were valid and provided").isTrue();
        assertThat(markers.governedUseCaseTrustMarker()).as("urn:ch.admin.fedpol.betaid is protected").isTrue();
        assertThat(markers.governedUseCaseAuthorizationTrustMarker()).as("a valid authorization trust statement for urn:ch.admin.fedpol.betaid was provided").isTrue();
    }

    @Test
    void testVerifyVerifierStatements_whenGovernedUseCase() {
        var statements = getExampleTrustStatements();
        var verifier = new TrustStatementVerifier(statements, mockRestriction, mockKidParser);
        var result = verifier.verifyVerifierStatements(TRUST_ROOT_DID, PUBLIC_STATEMENT_ISSUER_DID, ACTOR_DID, new JWKSet(List.of(trustIssuerKey, publicIssuerKey)), List.of(generateStatusListToken()));
        assertThat(result.evaluatedActorDid()).isEqualTo(ACTOR_DID);
        var markers = result.markers();
        assertThat(markers.isTrustedVerifier()).as("All Trust Statements were valid and provided").isTrue();
        assertThat(markers.governedUseCaseTrustMarker()).as("personal_administrative_number is requested").isTrue();
        assertThat(markers.governedUseCaseAuthorizationTrustMarker()).as("a valid authorization trust statement for personal_administrative_number was provided").isTrue();
    }

    private static List<String> getExampleTrustStatements() {
        return Arrays.stream(ExampleTrustStatement.values())
                .map(exampleTrustStatement ->
                        {
                            if (exampleTrustStatement == ExampleTrustStatement.vqPS) {
                                return exampleTrustStatement.getSerializedJwt(publicIssuerKey);
                            }
                            return exampleTrustStatement.getSerializedJwt(trustIssuerKey);
                        })
                .toList();
    }

    /**
     * Generates a status list with 1 bits where index 0 is revoked
     */
    private static TokenStatusListTokenDto generateStatusListToken() {
        return assertDoesNotThrow(() -> mapper.readValue(
                """
                        {
                          "exp": 2291720170,
                          "iat": 1686920170,
                          "status_list": {
                            "bits": 1,
                            "lst": "eNrt3AENwCAMAEGogklACtKQPg9LugC9k_ACvreiogEAAKkeCQAAAAAAAAAAAAAAAAAAAIBylgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXG9IAAAAAAAAAPwsJAAAAAAAAAAAAAAAvhsSAAAAAAAAAAAA7KpLAAAAAAAAAAAAAAAAAAAAAJsLCQAAAAAAAAAAADjelAAAAAAAAAAAKjDMAQAAAACAZC8L2AEb"
                          },
                          "sub": "https://example.com/statuslists/1",
                          "ttl": 43200
                        }
                        """,
                TokenStatusListTokenDto.class
        ));
    }
}