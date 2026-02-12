package ch.admin.bj.swiyu.jwtutil;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Unit tests for JwtUtil.
 * Covers EC/RSA verification, missing key, and unsupported key type.
 */
class JwtUtilTest {
    /**
     * Verifies a valid EC JWT is accepted and claims are correct.
     */
    @Test
    void verifyJwt_validECKey_success() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).keyID("ec1").generate();
        JWKSet jwkSet = new JWKSet(ecKey.toPublicJWK());
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("ec1").build(),
                new JWTClaimsSet.Builder().claim("foo", "bar").build()
        );
        jwt.sign(new ECDSASigner(ecKey));
        Map<String, Object> claims = JwtUtil.verifyJwt(jwt.serialize(), jwkSet);
        assertEquals("bar", claims.get("foo"));
    }

    /**
     * Verifies a valid RSA JWT is accepted and claims are correct.
     */
    @Test
    void verifyJwt_validRSAKey_success() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("rsa1").generate();
        JWKSet jwkSet = new JWKSet(rsaKey.toPublicJWK());
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("rsa1").build(),
                new JWTClaimsSet.Builder().claim("baz", 42).build()
        );
        jwt.sign(new RSASSASigner(rsaKey));
        Map<String, Object> claims = JwtUtil.verifyJwt(jwt.serialize(), jwkSet);
        assertEquals(42L, claims.get("baz"));
    }

    /**
     * Verifies that missing key in JWKSet throws exception.
     */
    @Test
    void verifyJwt_missingKey_throws() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).keyID("ec3").generate();
        JWKSet jwkSet = new JWKSet(); // No keys
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("ec3").build(),
                new JWTClaimsSet.Builder().claim("fail", true).build()
        );
        jwt.sign(new ECDSASigner(ecKey));
        String jwtString = jwt.serialize();
        assertThrows(JwtUtilException.class, () -> JwtUtil.verifyJwt(jwtString, jwkSet));
    }

    /**
     * Verifies that unsupported key type throws exception.
     */
    @Test
    void buildVerifier_unsupportedKeyType_throws() {
        JWK octKey = new OctetSequenceKey.Builder(new byte[]{1,2,3}).keyID("oct1").build();
        KeyType keyType = octKey.getKeyType();
        assertThrows(JwtUtilException.class, () -> JwtUtil.buildVerifier(keyType, octKey));
    }

    /**
     * Tests signJwt with EC key and verifies the signature.
     */
    @Test
    void signJwt_ecKey_success() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).keyID("ec-sign").generate();
        JWSHeader header = JwtUtil.buildHeader(JWSAlgorithm.ES256, "ec-sign", "JWT");
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("test", "ec").build();
        SignedJWT jwt = JwtUtil.signJwt(claims, header, new ECDSASigner(ecKey));
        JWKSet jwkSet = new JWKSet(ecKey.toPublicJWK());
        Map<String, Object> verifiedClaims = JwtUtil.verifyJwt(jwt.serialize(), jwkSet);
        assertEquals("ec", verifiedClaims.get("test"));
    }

    /**
     * Tests signJwt with RSA key and verifies the signature.
     */
    @Test
    void signJwt_rsaKey_success() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("rsa-sign").generate();
        JWSHeader header = JwtUtil.buildHeader(JWSAlgorithm.RS256, "rsa-sign", "JWT");
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("test", "rsa").build();
        SignedJWT jwt = JwtUtil.signJwt(claims, header, new RSASSASigner(rsaKey));
        JWKSet jwkSet = new JWKSet(rsaKey.toPublicJWK());
        Map<String, Object> verifiedClaims = JwtUtil.verifyJwt(jwt.serialize(), jwkSet);
        assertEquals("rsa", verifiedClaims.get("test"));
    }

    /**
     * Tests buildHeader for correct fields.
     */
    @Test
    void buildHeader_fields_correct() {
        JWSHeader header = JwtUtil.buildHeader(JWSAlgorithm.ES256, "kid123", "JWT");
        assertEquals(JWSAlgorithm.ES256, header.getAlgorithm());
        assertEquals("kid123", header.getKeyID());
        assertEquals("JWT", header.getType().toString());
    }

    /**
     * Tests verifySignedJwt directly.
     */
    @Test
    void verifySignedJwt_direct_success() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).keyID("ec4").generate();
        JWKSet jwkSet = new JWKSet(ecKey.toPublicJWK());
        SignedJWT jwt = JwtUtil.signJwt(
            new JWTClaimsSet.Builder().claim("foo", "baz").build(),
            JwtUtil.buildHeader(JWSAlgorithm.ES256, "ec4", "JWT"),
            new ECDSASigner(ecKey)
        );
        Map<String, Object> claims = JwtUtil.verifySignedJwt(jwt, jwkSet);
        assertEquals("baz", claims.get("foo"));
    }

    /**
     * Tests buildVerifier for EC and RSA keys.
     */
    @Test
    void buildVerifier_validKeys_success() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).keyID("ec5").generate();
        JWSVerifier ecVerifier = JwtUtil.buildVerifier(ecKey.getKeyType(), ecKey);
        assertEquals(ECDSAVerifier.class, ecVerifier.getClass());
        RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("rsa5").generate();
        JWSVerifier rsaVerifier = JwtUtil.buildVerifier(rsaKey.getKeyType(), rsaKey);
        assertEquals(RSASSAVerifier.class, rsaVerifier.getClass());
    }

    /**
     * Tests buildVerifier with null factory.
     */
    @Test
    void buildVerifier_nullFactory_throws() {
        JWK octKey = new OctetSequenceKey.Builder(new byte[]{1,2,3}).keyID("oct2").build();
        assertThrows(JwtUtilException.class, () -> JwtUtil.buildVerifier(null, octKey));
    }

    /**
     * Tests verifyJwt with invalid JWT string.
     */
    @Test
    void verifyJwt_invalidJwtString_throws() {
        JWKSet jwkSet = new JWKSet();
        assertThrows(JwtUtilException.class, () -> JwtUtil.verifyJwt("not-a-jwt", jwkSet));
    }

}
