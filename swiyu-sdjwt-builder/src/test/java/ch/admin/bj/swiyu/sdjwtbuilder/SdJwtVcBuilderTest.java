package ch.admin.bj.swiyu.sdjwtbuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.mock;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;

import ch.admin.bj.swiyu.sdjwtutil.SdJwtConstants;
import ch.admin.bj.swiyu.sdjwtbuilder.exception.SdJwtBuilderException;

/**
 * Test functionality for builder. For full happypath see swiyu-sdjwt-verifier's SdJwtUsageTest.
 */
class SdJwtVcBuilderTest {

    private static ECKey ecKey;
    private static OctetKeyPair edKey;
    private static JWSSigner ecSigner;
    private static JWSSigner edSigner;
    private static final String VERIFICATION_METHOD = "did:example:123#keys-1";
    private static final Map<SdJwtVcClaim, Object> minimalVcClaims = Map.of(
            SdJwtVcClaim.VCT, "VerifiableCredential"
        );
    
    @BeforeAll
    static void setUp() throws Exception {
        // EC256 Key
        ecKey = new ECKeyGenerator(Curve.P_256)
                .keyID(VERIFICATION_METHOD)
                .generate();
        ecSigner = new ECDSASigner(ecKey);

        // Ed25519 Key
        edKey = new OctetKeyPairGenerator(Curve.Ed25519)
                .keyID(VERIFICATION_METHOD)
                .generate();
        edSigner = new Ed25519Signer(edKey);
    }

    static Stream<Arguments> signerProvider() {
        return Stream.of(
            arguments(ecSigner, ecKey),
            arguments(edSigner, edKey)
        );
    }

    @ParameterizedTest
    @MethodSource("signerProvider")
    void createSignedSdJwtVc_ShouldSucceed(JWSSigner signer) throws Exception {
        Map<SdJwtVcClaim, Object> vcClaims = Map.of(
            SdJwtVcClaim.ISSUER, "https://issuer.example.com",
            SdJwtVcClaim.VCT_SUBTYPE, "VerifiableCredential.subtype",
            SdJwtVcClaim.VCT, "VerifiableCredential"
        );
        Map<String, Object> credentialSubjectClaims = Map.of(
            "given_name", "Max",
            "family_name", "Mustermann"
        );

        SdJwtVcBuilder builder = SdJwtVcBuilder.createBuilder(
            VERIFICATION_METHOD, vcClaims, credentialSubjectClaims, TimeConfiguration.builder().build(), signer);

        SdJwtVcBuilder.CreatedSdJwtVc result = builder.createSignedSdJwtVc(Optional.empty(), Optional.empty());

        assertThat(result).isNotNull();
        assertThat(result.jwt()).isNotNull();
        assertThat(result.serializedSdJwt()).isNotBlank();
        assertThat(result.vcHash()).isNotBlank();
        assertThat(result.serializedSdJwt()).contains("~");
        assertThat(result.jwt().getHeader().getKeyID()).isEqualTo(VERIFICATION_METHOD);
        assertThat(result.jwt().getHeader().getType()).isEqualTo(new JOSEObjectType(SdJwtConstants.TYP_DC_SD_JWT));
        assertThat(result.jwt().getJWTClaimsSet().getIssuer()).isEqualTo("https://issuer.example.com");
        assertThat(result.jwt().getJWTClaimsSet().getClaims()).as("Neither status nor holder binding is set").doesNotContainKeys("status", "cnf");
        assertThat(result.jwt().getJWTClaimsSet().getClaim("vct")).as("vct must be handled as normal claim").isEqualTo("VerifiableCredential");
        assertThat(result.jwt().getJWTClaimsSet().getClaims()).as("subject data must be selective disclosable").doesNotContainKeys("given_name", "family_name");
    }


    @Test
    void createSignedSdJwtVc_missingVct_ShouldThrow() {
        Map<SdJwtVcClaim, Object> vcClaims = Map.of();
        Map<String, Object> credentialSubjectClaims = Map.of();
        assertThatThrownBy( () -> SdJwtVcBuilder.createBuilder(
                VERIFICATION_METHOD, vcClaims, credentialSubjectClaims, TimeConfiguration.builder().build(), mock(JWSSigner.class)))
                .isInstanceOf(SdJwtBuilderException.class);
    }

    @ParameterizedTest
    @EnumSource(value = SdJwtVcClaim.class, names = {"EXPIRY", "NOT_BEFORE", "ISSUED_AT"})
    void createBuilder_overrideTime_shouldThrow(SdJwtVcClaim claim) {
        Map<SdJwtVcClaim, Object> vcClaims = Map.of(SdJwtVcClaim.VCT, "VerifiableCredential", claim, Instant.now().toEpochMilli());
        assertThatThrownBy(() -> SdJwtVcBuilder.createBuilder(
            VERIFICATION_METHOD, vcClaims, Map.of(), TimeConfiguration.builder().build(), mock(JWSSigner.class)))
            .isInstanceOf(SdJwtBuilderException.class)
            .hasMessageContaining(claim.getClaimName());
    }

    @ParameterizedTest
    @EnumSource(SdJwtVcClaim.class)
    void createSignedSdJwtVc_protectedClaims_ShouldThrow(SdJwtVcClaim claim) {

        Map<String, Object> credentialSubjectClaims = Map.of(
            claim.getClaimName(), "shouldNotBeOverridden"
        );
        var overrideBuilder = assertDoesNotThrow( () -> SdJwtVcBuilder.createBuilder(
                VERIFICATION_METHOD, minimalVcClaims, credentialSubjectClaims, TimeConfiguration.builder().build(), mock(JWSSigner.class)));
        assertThatThrownBy(() ->
            overrideBuilder.createSignedSdJwtVc(Optional.empty(), Optional.empty())
        ).isInstanceOf(SdJwtBuilderException.class);
    }

}
