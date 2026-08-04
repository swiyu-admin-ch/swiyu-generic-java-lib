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
        // generates a string consisting of random letters (a-z, A-Z)
        String payload = new java.security.SecureRandom().ints(230000, 0, 52)
                .mapToObj(i -> String.valueOf((char)(i < 26 ? 'A' + i : 'a' + (i - 26))))
                .collect(java.util.stream.Collectors.joining());
        String encrypted = JweUtil.encrypt(payload, ecKey.toPublicJWK());
        String decrypted = JweUtil.decrypt(encrypted, ecKey, 230000);
        assertEquals(payload, decrypted);
    }

    @Test
    void encryptDecrypt_roundTrip_thenError() throws Exception {
        ECKey ecKey = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).keyID("ec1").generate();
        String payload = new java.security.SecureRandom().ints(200000, 0, 52)
                .mapToObj(i -> String.valueOf((char)(i < 26 ? 'A' + i : 'a' + (i - 26))))
                .collect(java.util.stream.Collectors.joining());
        String encrypted = JweUtil.encrypt(payload, ecKey.toPublicJWK());
        assertThrows(JweUtilException.class, () -> JweUtil.decrypt(encrypted, ecKey, 30000));
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

    // ---------------------------------------------------------------------
    // Tests for EIDOMNI-1117 / EIDSEC-843 "JWE Decompression Bomb" fix
    // ---------------------------------------------------------------------

    @Test
    void decrypt_whenDecompressedPayloadWithinDefaultLimits_thenSucceeds() throws Exception {
        ECKey ecKey = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).keyID("ec6").generate();
        String payload = "a small, well within default limits, payload";
        String encrypted = JweUtil.encrypt(payload, ecKey.toPublicJWK());
        String decrypted = JweUtil.decrypt(encrypted, ecKey, JweDecryptionLimits.defaults());
        assertEquals(payload, decrypted);
    }

    @Test
    void decrypt_whenCompressedCipherTextExceedsConfiguredLimit_thenThrowsJweUtilException() throws Exception {
        ECKey ecKey = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).keyID("ec7").generate();
        // random (high-entropy) data does not compress well, so the compressed ciphertext
        // will exceed a very small configured limit
        String payload = new java.security.SecureRandom().ints(50000, 0, 52)
                .mapToObj(i -> String.valueOf((char) (i < 26 ? 'A' + i : 'a' + (i - 26))))
                .collect(java.util.stream.Collectors.joining());
        String encrypted = JweUtil.encrypt(payload, ecKey.toPublicJWK());
        JweDecryptionLimits limits = new JweDecryptionLimits(100, JweDecryptionLimits.DEFAULT_MAX_DECOMPRESSED_PAYLOAD_LENGTH);
        assertThrows(JweUtilException.class, () -> JweUtil.decrypt(encrypted, ecKey, limits));
    }

    @Test
    void decrypt_whenDecompressedPayloadExceedsConfiguredLimit_thenThrowsJweUtilException() throws Exception {
        ECKey ecKey = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).keyID("ec8").generate();
        // Highly repetitive (and therefore highly compressible) plaintext: this simulates a
        // "zip bomb" - its compressed size stays small, but its decompressed size is huge.
        String payload = "A".repeat(2_000_000); // ~2,000,000 chars decompressed
        String encrypted = JweUtil.encrypt(payload, ecKey.toPublicJWK());
        // Compressed ciphertext limit is generous enough to let the highly compressible
        // payload through, but the decompressed payload limit is deliberately small.
        JweDecryptionLimits limits = new JweDecryptionLimits(
                JweDecryptionLimits.DEFAULT_MAX_COMPRESSED_CIPHER_TEXT_LENGTH, 1000);
        JweUtilException exception = assertThrows(JweUtilException.class,
                () -> JweUtil.decrypt(encrypted, ecKey, limits));
        assertTrue(exception.getMessage().contains("exceeds the maximum allowed decompressed size"));
    }

    @Test
    void jweDecryptionLimits_whenValueIsZeroOrNegative_thenThrowsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new JweDecryptionLimits(0, 1000));
        assertThrows(IllegalArgumentException.class, () -> new JweDecryptionLimits(1000, 0));
        assertThrows(IllegalArgumentException.class, () -> new JweDecryptionLimits(-1, 1000));
        assertThrows(IllegalArgumentException.class, () -> new JweDecryptionLimits(1000, -1));
    }

    @Test
    void decrypt_whenLimitsIsNull_thenDefaultsAreApplied() throws Exception {
        ECKey ecKey = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).keyID("ec9").generate();
        String payload = "payload within defaults";
        String encrypted = JweUtil.encrypt(payload, ecKey.toPublicJWK());
        String decrypted = JweUtil.decrypt(encrypted, ecKey, (JweDecryptionLimits) null);
        assertEquals(payload, decrypted);
    }

    @Test
    void decrypt_deprecatedNoArgOverload_stillWorks() throws Exception {
        ECKey ecKey = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).keyID("ec10").generate();
        String payload = "backward compatible payload";
        String encrypted = JweUtil.encrypt(payload, ecKey.toPublicJWK());
        String decrypted = JweUtil.decrypt(encrypted, ecKey);
        assertEquals(payload, decrypted);
    }

    @Test
    void decrypt_deprecatedIntegerOverload_stillWorks() throws Exception {
        ECKey ecKey = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).keyID("ec11").generate();
        String payload = new java.security.SecureRandom().ints(230000, 0, 52)
                .mapToObj(i -> String.valueOf((char) (i < 26 ? 'A' + i : 'a' + (i - 26))))
                .collect(java.util.stream.Collectors.joining());
        String encrypted = JweUtil.encrypt(payload, ecKey.toPublicJWK());
        String decrypted = JweUtil.decrypt(encrypted, ecKey, 230000);
        assertEquals(payload, decrypted);
    }

    @Test
    void decrypt_deprecatedIntegerOverload_exceedsLimit_throws() throws Exception {
        ECKey ecKey = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).keyID("ec12").generate();
        String payload = new java.security.SecureRandom().ints(200000, 0, 52)
                .mapToObj(i -> String.valueOf((char) (i < 26 ? 'A' + i : 'a' + (i - 26))))
                .collect(java.util.stream.Collectors.joining());
        String encrypted = JweUtil.encrypt(payload, ecKey.toPublicJWK());
        assertThrows(JweUtilException.class, () -> JweUtil.decrypt(encrypted, ecKey, 30000));
    }
}
