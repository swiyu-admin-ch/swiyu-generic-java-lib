package ch.admin.bj.swiyu.sdjwtvalidator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ch.admin.bj.swiyu.jwtvalidator.DidJwtValidator;
import ch.admin.bj.swiyu.jwtvalidator.UrlRestriction;
import ch.admin.bj.swiyu.sdjwtvalidator.builder.SdJwtVcBuilder;
import ch.admin.bj.swiyu.sdjwtvalidator.builder.SdJwtVcBuilder.CreatedSdJwtVc;
import ch.admin.bj.swiyu.sdjwtvalidator.builder.SdJwtVcClaim;
import ch.admin.bj.swiyu.sdjwtvalidator.builder.TimeConfiguration;
import ch.admin.bj.swiyu.sdjwtvalidator.builder.TokenStatusListReferenceData;
import ch.admin.bj.swiyu.sdjwtvalidator.verifier.SdJwt;
import ch.admin.bj.swiyu.sdjwtvalidator.verifier.SdJwtParser;
import ch.admin.bj.swiyu.sdjwtvalidator.verifier.SdJwtVcValidator;

/**
 * Test containing a similarity of outside usage, from both creating and verifying of SD-JWT VCs
 */
public class SdJwtUsageTest {

    static String AUDIENCE = "did:webvh:scid:example.com";
    static String NONCE = UUID.randomUUID().toString();

    private static Stream<SignatureData> signatureKey() throws JOSEException {
        ECKey ecKeyIssuer = createECKey("key-1");
        ECKey ecKeyHolder = createECKey("holder-key-1");
        OctetKeyPair edKeyIssuer = createEdKey("key-2");
        OctetKeyPair edKeyHolder = createEdKey("holder-key-2");
        return Stream.of(
            new SignatureData(ecKeyIssuer.toPublicJWK(), new ECDSASigner(ecKeyIssuer), ecKeyHolder, new ECDSASigner(ecKeyHolder)),
            new SignatureData(edKeyIssuer.toPublicJWK(), new Ed25519Signer(edKeyIssuer), edKeyHolder, new Ed25519Signer(edKeyHolder)));
    }

    private static ECKey createECKey(String kid) throws JOSEException {
        return new ECKeyGenerator(Curve.P_256)
            .algorithm(JWSAlgorithm.ES256)
            .keyUse(KeyUse.SIGNATURE)
            .keyID(kid)
            .generate();
    }

    private static OctetKeyPair createEdKey(String kid) throws JOSEException {
        return new OctetKeyPairGenerator(Curve.Ed25519)
            .algorithm(JWSAlgorithm.Ed25519)
            .keyUse(KeyUse.SIGNATURE)
            .keyID(kid)
            .generate();
    }

    private record SignatureData(JWK jwk, JWSSigner signer, JWK holderKey, JWSSigner holderKeySigner) {
    }

    /**
     * A Test for the compatability of SD-JWT Builder and SD-JWT Verifier
     * @param signatureData Signing data for the SD-JWT & Key Binidng JWT
     * @throws ParseException 
     */
    @MethodSource("signatureKey")
    @ParameterizedTest
    void createAndValidateSdJwt(SignatureData signatureData) throws ParseException {
        String issuerDid = "did:webvh:scid:example.com";
        String verificationMethod = issuerDid + "#" + signatureData.jwk.getKeyID();
        // Create fixed vc calims with normal claims, optional data and discloseable claims
        Map<SdJwtVcClaim, Object> vcClaims = Map.of(SdJwtVcClaim.ISSUER, issuerDid, SdJwtVcClaim.VCT, "ch.swiyu.test", SdJwtVcClaim.VCT_SUBTYPE, "ch.swiyu.test.v2");
        Map<String, Object> credentialSubjectClaims = Map.of("name", "Bob", "surname", "Builder", 
            "canWeArray", 
                // Test Lists with mixed values and same values in list
                List.of("Yes", "Duplicate", "Duplicate", "Duplicate", 1l, 1l, 1.0, //  Note: Numbers are after processing all longs
                    List.of("List in List", Map.of("Subobject in list", "In List"))),  // Nested List and Nested Object in List
            "canWeNested", Map.of("nested", "Yes",  // Complex nested Object
                "canWeRecursiveNested", Map.of("canWe", "Yes"), 
                    "canWeRecursiveArray", List.of("Yes", Map.of("listObject", List.of("Yes", "Yes"))))); // Deep Recusive data

        TimeConfiguration timeConfig = TimeConfiguration.builder()
            .expiry(Optional.of(Instant.now().plus(1, ChronoUnit.DAYS)))
            .notBefore(Optional.of(Instant.now()))
            .issuedAt(Optional.of(Instant.now()))
            .build();
        var builder = assertDoesNotThrow(() -> SdJwtVcBuilder.createBuilder(verificationMethod, vcClaims, credentialSubjectClaims, timeConfig, signatureData.signer));
        var signed = assertDoesNotThrow(() -> builder.createSignedSdJwtVc(Optional.of(new TokenStatusListReferenceData(1, "https://www.example.com/status/1")), Optional.of(signatureData.holderKey.toPublicJWK())));
        assertThat(signed.jwt().getJWTClaimsSet().toString())
            .as("Subject data should be discloseable").doesNotContain(credentialSubjectClaims.keySet())
            .as("Disclosable fixed data should be discloseable").doesNotContain(vcClaims.keySet().stream().filter(k -> !k.isAlwaysDisclosed()).map(SdJwtVcClaim::getClaimName).toList())
            .as("Always disclosed data should be present, even optional issuer").contains(vcClaims.keySet().stream().filter(k -> k.isAlwaysDisclosed()).map(SdJwtVcClaim::getClaimName).toList())
            .as("Time claims should be always disclosed").contains("exp", "nbf", "iat")
            .as("Status List and Holder Binding must be present as always disclosed values").contains(List.of("status", "cnf"));

        // Create Holder Binding
        var keyBinding = createKeyBinding(signed, signatureData);

        // Verify using the verifier
        var mockUrlRestriction = mock(UrlRestriction.class);
        when(mockUrlRestriction.validateUrl(anyString())).thenReturn(true);
        var validator = new SdJwtVcValidator(new DidJwtValidator(mockUrlRestriction));
        var presentation = signed.serializedSdJwt()+keyBinding; // JWT~disclosure 1~...~disclosure n~key binding
        SdJwt sdJwt = assertDoesNotThrow(() -> SdJwtParser.parseSdJwt(presentation));
        
        assertThrows(IllegalStateException.class, () -> sdJwt.getHeader()); // Should fail as verification was not done yet
        assertDoesNotThrow(() -> validator.validateHeader(sdJwt));

        assertThat(sdJwt.getHeader().getKeyID()).as("KID must be verification method").isEqualTo(verificationMethod);
        
        assertThrows(IllegalStateException.class, () -> sdJwt.getClaims()); // Should fail as verification was not done yet
        
        // Validate Issued JWT
        assertDoesNotThrow(() -> validator.validateJwt(sdJwt, signatureData.jwk));
        // Validate Key Binding (Is the JWT really presented to us or was it presented to someone else?)
        assertDoesNotThrow(() -> validator.validateKeyBinding(sdJwt, AUDIENCE, NONCE, 120));
        // Resolve the claims so we will now have all regular claims again
        var processedSdJwt = assertDoesNotThrow(() -> validator.processDisclosures(sdJwt));
        assertThat(processedSdJwt).as("Serialization and Deseralization of all claims must be lossless").containsAllEntriesOf(credentialSubjectClaims);
    }

    private String createKeyBinding(CreatedSdJwtVc signed, SignatureData signatureData) {
        SdJwt holderbindingless = assertDoesNotThrow(() -> SdJwtParser.parseSdJwt(signed.serializedSdJwt()));
        var hash = holderbindingless.getPresentationHash();
        var holderKey = signatureData.holderKey;
        SignedJWT keyBindingJwt = new SignedJWT(
            new JWSHeader.Builder((JWSAlgorithm) holderKey.getAlgorithm()).keyID(holderKey.getKeyID()).type(SdJwtConstants.KEY_BINDING_TYPE).build(), 
            new JWTClaimsSet.Builder()
                .issueTime(Date.from(Instant.now()))
                .audience(AUDIENCE)
                .claim("nonce", NONCE)
                .claim("sd_hash", hash).build());

        assertDoesNotThrow(() -> keyBindingJwt.sign(signatureData.holderKeySigner));
        
        return keyBindingJwt.serialize();
    }

}
