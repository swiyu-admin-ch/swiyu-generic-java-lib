package ch.admin.bj.swiyu.jweutil;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for JweUtil.
 * Covers EC encryption/decryption, invalid input, and exception handling.
 */
class JweUtilTest {
    @Test
    void encryptDecrypt_roundTrip_success() throws Exception {
        ECKey ecKey = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).keyID("ec1").generate();
        String payload = "test-payload";
        String encrypted = JweUtil.encrypt(payload, ecKey.toPublicJWK());
        String decrypted = JweUtil.decrypt(encrypted, ecKey);
        assertEquals(payload, decrypted);
    }

    @Test
    void encrypt_nullPayload_throws() throws JOSEException {
        ECKey ecKey = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).keyID("ec2").generate();
        assertThrows(JweUtilException.class, () -> {
            JweUtil.encrypt(null, ecKey.toPublicJWK());
        });
    }

    @Test
    void encrypt_nullKey_throws() {
        assertThrows(JweUtilException.class, () -> JweUtil.encrypt("payload", null));
    }

    @Test
    void decrypt_nullJwe_throws() throws JOSEException {
        ECKey ecKey = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).keyID("ec3").generate();
        assertThrows(JweUtilException.class, () -> JweUtil.decrypt(null, ecKey));
    }

    @Test
    void decrypt_nullKey_throws() {
        assertThrows(JweUtilException.class, () -> JweUtil.decrypt("jwe", null));
    }

    @Test
    void decrypt_invalidJwe_throws() throws JOSEException {
        ECKey ecKey = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).keyID("ec4").generate();
        assertThrows(JweUtilException.class, () -> JweUtil.decrypt("not-a-jwe", ecKey));
    }

    @Test
    void encrypt_emptyPayload_success() throws Exception {
        ECKey ecKey = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).keyID("ec5").generate();
        String encrypted = JweUtil.encrypt("", ecKey.toPublicJWK());
        String decrypted = JweUtil.decrypt(encrypted, ecKey);
        assertEquals("", decrypted);
    }

    @Test
    void encrypt_unsupportedKeyType_throws() {
        JWK octKey = new com.nimbusds.jose.jwk.OctetSequenceKey.Builder(new byte[]{1,2,3}).keyID("oct1").build();
        assertThrows(JweUtilException.class, () -> JweUtil.encrypt("payload", octKey));
    }

    @Test
    void decrypt_unsupportedKeyType_throws() {
        JWK octKey = new com.nimbusds.jose.jwk.OctetSequenceKey.Builder(new byte[]{1,2,3}).keyID("oct2").build();
        assertThrows(JweUtilException.class, () -> JweUtil.decrypt("jwe", octKey));
    }
}

