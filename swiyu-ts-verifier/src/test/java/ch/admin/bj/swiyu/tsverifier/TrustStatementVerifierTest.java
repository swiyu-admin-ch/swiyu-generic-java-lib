package ch.admin.bj.swiyu.tsverifier;

import ch.admin.bj.swiyu.jwtvalidator.DidKidParser;
import ch.admin.bj.swiyu.jwtvalidator.UrlRestriction;
import ch.admin.bj.swiyu.statuslist.TokenStatusList;
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
    static final String PROTECTED_VCT_WITH_AUTHORIZATION = "urn:ch.admin.fedpol.betaid";
    static final String PROTECTED_VCT_WITHOUT_AUTHORIZATION = "urn:ch.admin.fedpol.eid";
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
        var statements = getValidExampleTrustStatements();

        var verifier = new TrustStatementVerifier(statements, Mockito.mock(UrlRestriction.class), new DidKidParser());
        var ids = verifier.getRequiredKeyIds();
        assertThat(ids).hasSize(2).contains("did:example:trust-issuer#key-1", "did:example:verification-statment-issuer#key-1");
    }

    @Test
    void testGetStatusListUris() {
        var statements = getValidExampleTrustStatements();
        var verifier = new TrustStatementVerifier(statements, Mockito.mock(UrlRestriction.class), new DidKidParser());
        var statusListUris = verifier.getRequiredStatusLists();
        assertThat(statusListUris).hasSize(1).contains("https://example.com/statuslists/1");
    }

    @Test
    void testVerifyIssuanceStatements_whenGovernedUseCase_thenAllMarks() {
        var statements = getValidExampleTrustStatements();
        var verifier = new TrustStatementVerifier(statements, mockRestriction, mockKidParser);
        var result = verifier.verifyIssuanceStatements(TRUST_ROOT_DID, ACTOR_DID, PROTECTED_VCT_WITH_AUTHORIZATION, new JWKSet(trustIssuerKey), List.of(generateStatusListToken()));
        assertThat(result.evaluatedActorDid()).isEqualTo(ACTOR_DID);
        var markers = result.markers();
        assertThat(markers.isTrustedIssuer()).as("All Trust Statements were valid and provided").isTrue();
        assertThat(markers.governedUseCaseTrustMarker()).as("urn:ch.admin.fedpol.betaid is protected").isTrue();
        assertThat(markers.governedUseCaseAuthorizationTrustMarker()).as("a valid authorization trust statement for urn:ch.admin.fedpol.betaid was provided").isTrue();
    }

    @Test
    void testVerifyIssuanceStatements_whenGovernedUseCase_lackingAuthorization_thenNotTrusted() {
        var statements = getExampleStatementsNoAuthorization();
        var verifier = new TrustStatementVerifier(statements, mockRestriction, mockKidParser);
        var result = verifier.verifyIssuanceStatements(TRUST_ROOT_DID, ACTOR_DID, PROTECTED_VCT_WITHOUT_AUTHORIZATION, new JWKSet(trustIssuerKey), List.of(generateStatusListToken()));
        assertThat(result.evaluatedActorDid()).isEqualTo(ACTOR_DID);
        var markers = result.markers();
        assertThat(markers.isTrustedIssuer()).as("Issuer should not be trusted").isFalse();
        assertThat(markers.governedUseCaseTrustMarker()).as("urn:ch.admin.fedpol.eid is protected").isTrue();
        assertThat(markers.governedUseCaseAuthorizationTrustMarker()).as("a valid authorization trust statement for urn:ch.admin.fedpol.eid was not provided").isFalse();
    }

    @Test
    void testVerifyIssuanceStatement_whenRevoked_thenNotTrusted() {
        var statements = getValidExampleTrustStatements();
        var verifier = new TrustStatementVerifier(statements, mockRestriction, mockKidParser);
        // Create Status Lists with revocation
        var statusLists = List.of(generateStatusListToken(1));
        var result = verifier.verifyIssuanceStatements(TRUST_ROOT_DID, ACTOR_DID, PROTECTED_VCT_WITH_AUTHORIZATION, new JWKSet(trustIssuerKey), statusLists);
        assertThat(result.evaluatedActorDid()).isEqualTo(ACTOR_DID);
        var markers = result.markers();
        assertThat(markers.isTrustedIssuer()).as("One or more statements were revoked").isFalse();
        assertThat(markers.identityTrustMarker()).as("Is revoked").isFalse();
        assertThat(markers.compliantActorTrustMarker()).as("Is revoked").isFalse();
        assertThat(markers.governedUseCaseTrustMarker()).as("All Claims are assumed to be protected when no valid protected issuance trust list statement (piTLS) is provided").isTrue();
        assertThat(markers.governedUseCaseAuthorizationTrustMarker()).as("Is revoked").isFalse();
    }

    @Test
    void testVerifyVerifierStatements_whenGovernedUseCase_thenAllMarks() {
        var statements = getValidExampleTrustStatements();
        var verifier = new TrustStatementVerifier(statements, mockRestriction, mockKidParser);
        var result = verifier.verifyVerifierStatements(TRUST_ROOT_DID, PUBLIC_STATEMENT_ISSUER_DID, ACTOR_DID, new JWKSet(List.of(trustIssuerKey, publicIssuerKey)), List.of(generateStatusListToken()));
        assertThat(result.evaluatedActorDid()).isEqualTo(ACTOR_DID);
        var markers = result.markers();
        assertThat(markers.isTrustedVerifier()).as("All Trust Statements were valid and provided").isTrue();
        assertThat(markers.governedUseCaseTrustMarker()).as("personal_administrative_number is requested").isTrue();
        assertThat(markers.governedUseCaseAuthorizationTrustMarker()).as("a valid authorization trust statement for personal_administrative_number was provided").isTrue();
        assertThat(markers.transparentVerificationTrustMarker()).as("vqPS was provided").isTrue();
    }

    @Test
    void testVerifyVerifierStatements_whenGovernedUseCase_lackingAuthorization_thenNotTrusted() {
        var statements = getTrustStatements(ExampleTrustStatement.idTS, ExampleTrustStatement.ncTLS, ExampleTrustStatement.vqPS_protected_claim);
        var verifier = new TrustStatementVerifier(statements, mockRestriction, mockKidParser);
        var result = verifier.verifyVerifierStatements(TRUST_ROOT_DID, PUBLIC_STATEMENT_ISSUER_DID, ACTOR_DID, new JWKSet(List.of(trustIssuerKey, publicIssuerKey)), List.of(generateStatusListToken()));
        assertThat(result.evaluatedActorDid()).isEqualTo(ACTOR_DID);
        var markers = result.markers();
        assertThat(markers.isTrustedVerifier()).as("No Statement for authorization was provided").isFalse();
        assertThat(markers.governedUseCaseTrustMarker()).as("personal_administrative_number is requested").isTrue();
        assertThat(markers.governedUseCaseAuthorizationTrustMarker()).as("no valid authorization trust statement for personal_administrative_number was provided").isFalse();
    }

    @Test
    void testVerifyVerifierStatements_whenUngovernedUseCase_lackingAuthorization_thenTrusted() {
        var statements = getTrustStatements(ExampleTrustStatement.idTS, ExampleTrustStatement.ncTLS, ExampleTrustStatement.vqPS);
        var verifier = new TrustStatementVerifier(statements, mockRestriction, mockKidParser);
        var result = verifier.verifyVerifierStatements(TRUST_ROOT_DID, PUBLIC_STATEMENT_ISSUER_DID, ACTOR_DID, new JWKSet(List.of(trustIssuerKey, publicIssuerKey)), List.of(generateStatusListToken()));
        assertThat(result.evaluatedActorDid()).isEqualTo(ACTOR_DID);
        var markers = result.markers();
        assertThat(markers.identityTrustMarker()).isTrue();
        assertThat(markers.compliantActorTrustMarker()).as("Not part of non-compliant actors").isTrue();
        assertThat(markers.transparentVerificationTrustMarker()).as("vqPS was provided").isTrue();
        assertThat(markers.governedUseCaseTrustMarker()).as("personal_administrative_number is not requested").isFalse();
        assertThat(markers.governedUseCaseAuthorizationTrustMarker()).as("No Authorization was provided").isFalse();
        assertThat(markers.isTrustedVerifier()).as("All Trust Statements were valid and provided").isTrue();
    }

    @Test
    void testVerifyVerifierStatements_whenRevoked_thenNotTrusted() {
        var statements = getValidExampleTrustStatements();
        var verifier = new TrustStatementVerifier(statements, mockRestriction, mockKidParser);
        // Create Status Lists with revocation
        var statusLists = List.of(generateStatusListToken(1));
        var result = verifier.verifyVerifierStatements(TRUST_ROOT_DID, PUBLIC_STATEMENT_ISSUER_DID, ACTOR_DID, new JWKSet(List.of(trustIssuerKey, publicIssuerKey)), statusLists);
        assertThat(result.evaluatedActorDid()).isEqualTo(ACTOR_DID);
        var markers = result.markers();
        assertThat(markers.isTrustedIssuer()).as("One or more statements were revoked").isFalse();
        assertThat(markers.identityTrustMarker()).as("Is revoked").isFalse();
        assertThat(markers.compliantActorTrustMarker()).as("Is revoked").isFalse();
        assertThat(markers.governedUseCaseTrustMarker()).as("administrative number is regarded still as protected").isTrue();
        assertThat(markers.governedUseCaseAuthorizationTrustMarker()).as("Is revoked").isFalse();
        assertThat(markers.transparentVerificationTrustMarker()).as("vqPS cannot be revoked").isTrue();
    }

    private static List<String> getValidExampleTrustStatements() {
        return getTrustStatements(
                ExampleTrustStatement.idTS,
                ExampleTrustStatement.ncTLS,
                ExampleTrustStatement.pvaTS,
                ExampleTrustStatement.vqPS_protected_claim,
                ExampleTrustStatement.piTLS,
                ExampleTrustStatement.piaTS,
                ExampleTrustStatement.piaTS_other
            );
    }

    private static List<String> getExampleStatementsNoAuthorization() {
        return getTrustStatements(
                ExampleTrustStatement.idTS,
                ExampleTrustStatement.ncTLS,
                ExampleTrustStatement.vqPS_protected_claim,
                ExampleTrustStatement.piTLS
            );
    }


    private static List<String> getTrustStatements(ExampleTrustStatement... statements) {
        return Arrays.stream(statements)
                .map(exampleTrustStatement ->
                {
                    // public statements must be signed with public Issuer Key, not trust issuer key
                    if (List.of(ExampleTrustStatement.vqPS, ExampleTrustStatement.vqPS_protected_claim).contains(exampleTrustStatement)) {
                        return exampleTrustStatement.getSerializedJwt(publicIssuerKey);
                    }
                    return exampleTrustStatement.getSerializedJwt(trustIssuerKey);
                })
                .toList();
    }

    /**
     * Generates a status list with 1 bits where no entries are revoked
     */
    private static TokenStatusListTokenDto generateStatusListToken(int... revokedIndexes) {
        var statusList = new TokenStatusList(1, 100);
        for (int index : revokedIndexes) {
            statusList.setStatus(index, 1);
        }
        var lst = assertDoesNotThrow( () -> statusList.getStatusListData());
        return assertDoesNotThrow(() -> mapper.readValue(
                """
                        {
                          "exp": 2291720170,
                          "iat": 1686920170,
                          "status_list": {
                            "bits": 1,
                            "lst": "%s"
                          },
                          "sub": "https://example.com/statuslists/1",
                          "ttl": 43200
                        }
                        """.formatted(lst),
                TokenStatusListTokenDto.class
        ));
    }
}