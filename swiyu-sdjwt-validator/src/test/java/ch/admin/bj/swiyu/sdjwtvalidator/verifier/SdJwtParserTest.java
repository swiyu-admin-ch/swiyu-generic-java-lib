package ch.admin.bj.swiyu.sdjwtvalidator.verifier;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ch.admin.bj.swiyu.sdjwtvalidator.SdJwtConstants;
import ch.admin.bj.swiyu.sdjwtvalidator.builder.SdJwtVcBuilder;
import ch.admin.bj.swiyu.sdjwtvalidator.builder.SdJwtVcClaim;
import ch.admin.bj.swiyu.sdjwtvalidator.builder.TimeConfiguration;
import ch.admin.bj.swiyu.sdjwtvalidator.exception.SdJwtParseException;

class SdJwtParserTest {

    static ECKey key;
    static SdJwtVcBuilder.CreatedSdJwtVc testVc;

    @BeforeAll
    static void setup() throws Exception {
        key = new ECKeyGenerator(Curve.P_256).keyID("key1").algorithm(JWSAlgorithm.ES256).generate();
        var builder = SdJwtVcBuilder.createBuilder("did:webvh:scid:example.com#-key1", Map.of(SdJwtVcClaim.VCT, "test"), Map.of("a", "1", "b", "2"), TimeConfiguration.builder().build(), new ECDSASigner(key));
        testVc = builder.createSignedSdJwtVc(Optional.empty(), Optional.empty());
    }

    /**
     * Test basic sd-jwt
     * JWT ~ Disclosure 1 ~ ... ~ Disclosure n ~
     */
    @Test
    void parseSdJwt_whenPlausible_thenSuccess() {
        assertDoesNotThrow(() -> SdJwtParser.parseSdJwt(testVc.serializedSdJwt()));
    }

    /**
     * Test with Holder Binding;
     * JWT ~ Disclosure 1 ~ ... ~ Disclosure n ~ HolderBinding
     */
    @Test
    void parseSdJwt_whenPlausibleHolderBinding_thenSuccess() {
        var presentation = testVc.serializedSdJwt()+testVc.jwt().serialize();
        assertDoesNotThrow(() -> SdJwtParser.parseSdJwt(presentation));
    }

    /**
     * Test no disclosures
     * JWT~
     */
    @Test
    void parseSdJwt_whenNoDisclosures_thenSuccess() {
        var presentation = testVc.jwt().serialize() + "~";
        assertDoesNotThrow(() -> SdJwtParser.parseSdJwt(presentation));
    }
    /**
     * Test missing disclosures
     * JWT
     */
    @Test
    void parseSdJwt_whenMissingDisclosures_thenThrows() {
        assertThatThrownBy(() -> SdJwtParser.parseSdJwt(testVc.jwt().serialize()))
        .isInstanceOf(SdJwtParseException.class);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"jwt", "sd-jwt", "kb+sd-jwt"})
    void parseSdJwt_wrongJWSHeaderType_thenThrows(String type) throws JOSEException {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(type == null ? null : new JOSEObjectType(type) ).build(), new JWTClaimsSet.Builder().build());
        jwt.sign(new ECDSASigner(key));
        var presentation = jwt.serialize()+SdJwtConstants.JWT_PART_DELINEATION_CHARACTER;
        assertThatThrownBy(() -> SdJwtParser.parseSdJwt(presentation))
            .isInstanceOf(SdJwtParseException.class)
            .hasMessageContaining(SdJwtConstants.TYP_DC_SD_JWT);
    }
    

}

