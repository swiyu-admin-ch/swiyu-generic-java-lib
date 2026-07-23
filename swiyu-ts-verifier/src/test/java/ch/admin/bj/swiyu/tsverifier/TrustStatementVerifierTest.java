package ch.admin.bj.swiyu.tsverifier;

import ch.admin.bj.swiyu.jwtvalidator.DidKidParser;
import ch.admin.bj.swiyu.tsverifier.statement.ExampleTrustStatement;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
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
    static final String ATTACKER_DID = "did:example:attacker";
    static final String ACTOR_DID = "did:example:actor";
    static final String PROTECTED_VCT_WITH_AUTHORIZATION = "urn:ch.admin.fedpol.betaid";
    static final String PROTECTED_VCT_WITHOUT_AUTHORIZATION = "urn:ch.admin.fedpol.eid";
    static ECKey trustIssuerKey;
    static ECKey publicIssuerKey;
    static ECKey attackerKey;

    DidKidParser mockKidParser;

    @BeforeAll
    static void init() throws JOSEException {
        trustIssuerKey = new ECKeyGenerator(Curve.P_256).keyID("%s#key-1".formatted(TRUST_ROOT_DID)).generate();
        publicIssuerKey = new ECKeyGenerator(Curve.P_256).keyID("%s#key-1".formatted(PUBLIC_STATEMENT_ISSUER_DID)).generate();
        attackerKey = new ECKeyGenerator(Curve.P_256).keyID("%s#key-1".formatted(ATTACKER_DID)).generate();
    }

    @BeforeEach
    void setup() {
        mockKidParser = Mockito.mock(DidKidParser.class);
        when(mockKidParser.getDidFromAbsoluteKid(any())).thenAnswer(invocation ->  invocation.getArguments()[0].toString().split("#")[0]);
    }

    @Test
    void testGetKeyIds() {
        var statements = getValidExampleTrustStatements();

        var verifier = new TrustStatementVerifier(statements, new DidKidParser());
        var ids = verifier.getRequiredKeyIds();
        assertThat(ids).hasSize(2).contains("did:example:trust-issuer#key-1", "did:example:verification-statment-issuer#key-1");
    }

    @Test
    void testGetKeyIds_withKidInHeaderAndBody_shouldTakeHeader_thenSuccess() {
        var headerWithKid = """
                {
                    "typ": "swiyu-identity-trust-statement+jwt",
                    "alg": "ES256",
                    "kid": "did:example:trust-issuer#key-1",
                    "profile_version": "swiss-profile-trust:1.0.0"
                }
            """;
        var bodyWithKid = """
        {
            "sub": "did:example:actor",
                "iat": 1690360968,
                "exp": 32503676400,
                "kid": "did:example:trust-different-issuer#key-1",
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
        }""";

        var jwt = assertDoesNotThrow(() -> new SignedJWT(JWSHeader.parse(headerWithKid), JWTClaimsSet.parse(bodyWithKid)));
        assertDoesNotThrow(() -> jwt.sign(new ECDSASigner(trustIssuerKey)));
        var serialized = jwt.serialize();

        getTrustStatements(ExampleTrustStatement.idTS, ExampleTrustStatement.ncTLS, ExampleTrustStatement.vqPS_protected_claim);


        var verifier = new TrustStatementVerifier(List.of(serialized), new DidKidParser());
        var ids = verifier.getRequiredKeyIds();
        assertThat(ids).hasSize(1).contains("did:example:trust-issuer#key-1");
    }

    @Test
    void testVerifyIssuanceStatements_whenPayloadKidClaimsTrustedDidButHeaderKidIsAttacker_thenIdentityTrustRejected() {
        var serialized = getSignedIdentityTrustStatement(
                "%s#key-1".formatted(ATTACKER_DID),
                "%s#key-1".formatted(TRUST_ROOT_DID),
                attackerKey);

        var verifier = new TrustStatementVerifier(List.of(serialized), mockKidParser);
        var result = verifier.verifyIssuanceStatements(
                TRUST_ROOT_DID,
                ACTOR_DID,
                PROTECTED_VCT_WITH_AUTHORIZATION);

        var markers = result.markers();
        assertThat(markers.identityTrustMarker())
                .as("A trusted payload kid must not override an untrusted JOSE header kid")
                .isFalse();
        assertThat(markers.isTrustedIssuer()).as("Issuer must not be trusted").isFalse();
    }

    @Test
    void testVerifyIssuanceStatements_whenPayloadKidClaimsAttackerDidButHeaderKidIsTrusted_thenIdentityTrustAccepted() {
        var serialized = getSignedIdentityTrustStatement(
                "%s#key-1".formatted(TRUST_ROOT_DID),
                "%s#key-1".formatted(ATTACKER_DID),
                trustIssuerKey);

        var verifier = new TrustStatementVerifier(List.of(serialized), mockKidParser);
        var result = verifier.verifyIssuanceStatements(
                TRUST_ROOT_DID,
                ACTOR_DID,
                PROTECTED_VCT_WITH_AUTHORIZATION);

        assertThat(result.markers().identityTrustMarker())
                .as("An untrusted payload kid must not override the trusted JOSE header kid")
                .isTrue();
    }

    @Test
    void testVerifyIssuanceStatements_whenGovernedUseCase_thenAllMarks() {
        var statements = getValidExampleTrustStatements();
        var verifier = new TrustStatementVerifier(statements, mockKidParser);
        var result = verifier.verifyIssuanceStatements(TRUST_ROOT_DID, ACTOR_DID, PROTECTED_VCT_WITH_AUTHORIZATION);
        assertThat(result.evaluatedActorDid()).isEqualTo(ACTOR_DID);
        var markers = result.markers();
        assertThat(markers.isTrustedIssuer()).as("All Trust Statements were valid and provided").isTrue();
        assertThat(markers.governedUseCaseTrustMarker()).as("urn:ch.admin.fedpol.betaid is protected").isTrue();
        assertThat(markers.governedUseCaseAuthorizationTrustMarker()).as("a valid authorization trust statement for urn:ch.admin.fedpol.betaid was provided").isTrue();
    }

    @Test
    void testVerifyIssuanceStatements_whenGovernedUseCase_lackingAuthorization_thenNotTrusted() {
        var statements = getExampleStatementsNoAuthorization();
        var verifier = new TrustStatementVerifier(statements, mockKidParser);
        var result = verifier.verifyIssuanceStatements(TRUST_ROOT_DID, ACTOR_DID, PROTECTED_VCT_WITHOUT_AUTHORIZATION);
        assertThat(result.evaluatedActorDid()).isEqualTo(ACTOR_DID);
        var markers = result.markers();
        assertThat(markers.isTrustedIssuer()).as("Issuer should not be trusted").isFalse();
        assertThat(markers.governedUseCaseTrustMarker()).as("urn:ch.admin.fedpol.eid is protected").isTrue();
        assertThat(markers.governedUseCaseAuthorizationTrustMarker()).as("a valid authorization trust statement for urn:ch.admin.fedpol.eid was not provided").isFalse();
    }

    @Test
    void testVerifyVerifierStatements_whenGovernedUseCase_thenAllMarks() {
        var statements = getValidExampleTrustStatements();
        var verifier = new TrustStatementVerifier(statements, mockKidParser);
        var result = verifier.verifyVerifierStatements(TRUST_ROOT_DID, PUBLIC_STATEMENT_ISSUER_DID, ACTOR_DID);
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
        var verifier = new TrustStatementVerifier(statements, mockKidParser);
        var result = verifier.verifyVerifierStatements(TRUST_ROOT_DID, PUBLIC_STATEMENT_ISSUER_DID, ACTOR_DID);
        assertThat(result.evaluatedActorDid()).isEqualTo(ACTOR_DID);
        var markers = result.markers();
        assertThat(markers.isTrustedVerifier()).as("No Statement for authorization was provided").isFalse();
        assertThat(markers.governedUseCaseTrustMarker()).as("personal_administrative_number is requested").isTrue();
        assertThat(markers.governedUseCaseAuthorizationTrustMarker()).as("no valid authorization trust statement for personal_administrative_number was provided").isFalse();
    }

    @Test
    void testVerifyVerifierStatements_whenUngovernedUseCase_lackingAuthorization_thenTrusted() {
        var statements = getTrustStatements(ExampleTrustStatement.idTS, ExampleTrustStatement.ncTLS, ExampleTrustStatement.vqPS);
        var verifier = new TrustStatementVerifier(statements, mockKidParser);
        var result = verifier.verifyVerifierStatements(TRUST_ROOT_DID, PUBLIC_STATEMENT_ISSUER_DID, ACTOR_DID);
        assertThat(result.evaluatedActorDid()).isEqualTo(ACTOR_DID);
        var markers = result.markers();
        assertThat(markers.identityTrustMarker()).isTrue();
        assertThat(markers.compliantActorTrustMarker()).as("Not part of non-compliant actors").isTrue();
        assertThat(markers.transparentVerificationTrustMarker()).as("vqPS was provided").isTrue();
        assertThat(markers.governedUseCaseTrustMarker()).as("personal_administrative_number is not requested").isFalse();
        assertThat(markers.governedUseCaseAuthorizationTrustMarker()).as("No Authorization was provided").isFalse();
        assertThat(markers.isTrustedVerifier()).as("All Trust Statements were valid and provided").isTrue();
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

    private static String getSignedIdentityTrustStatement(String headerKid, String payloadKid, ECKey signingKey) {
        var header = """
                {
                    "typ": "swiyu-identity-trust-statement+jwt",
                    "alg": "ES256",
                    "kid": "%s",
                    "profile_version": "swiss-profile-trust:1.0.0"
                }
                """.formatted(headerKid);
        var body = """
                {
                    "sub": "%s",
                    "iat": 1690360968,
                    "exp": 32503676400,
                    "kid": "%s",
                    "status":  {
                        "status_list": {
                            "idx": 1,
                            "uri": "https://example.com/statuslists/1"
                        }
                    },
                    "entity_name": "My entity",
                    "entity_name#de": "My entity (de)",
                    "entity_name#de-CH": "My entity (de-CH)",
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
                }
                """.formatted(ACTOR_DID, payloadKid);

        var jwt = assertDoesNotThrow(() -> new SignedJWT(JWSHeader.parse(header), JWTClaimsSet.parse(body)));
        assertDoesNotThrow(() -> jwt.sign(new ECDSASigner(signingKey)));
        return jwt.serialize();
    }
}
